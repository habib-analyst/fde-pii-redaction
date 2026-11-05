"""Local token vault: the reversible half of the redactor.

When a document is redacted in ``mask`` mode, the mapping from typed
placeholder (``[EMAIL_1]``) to the original value is stored here, in a
local SQLite database, scoped to exactly one (tenant, document) pair.

Rules enforced by the vault:

* a restore must present the tenant key registered for that tenant;
* a restore under a different tenant is denied, even with that other
  tenant's own valid key (entries are looked up per tenant, and a
  document that exists only under another tenant is an access error,
  never a silent miss);
* entries expire: every entry carries an expiry taken from an
  injectable clock plus a TTL, and restoring an expired entry fails.

Only ``mask`` mode is reversible. ``hash`` mode is one-way by design
and ``partial`` mode is lossy, so the engine stores nothing for them.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Callable


class VaultError(Exception):
    """Base class for vault failures."""


class VaultAccessError(VaultError):
    """Wrong tenant key, or the document belongs to another tenant."""


class VaultNotFoundError(VaultError):
    """No vault entry for this tenant + document."""


class VaultExpiredError(VaultError):
    """The vault entry exists but its TTL has passed."""


class TokenVault:
    def __init__(
        self,
        db_path: str = ":memory:",
        tenant_keys: dict[str, str] | None = None,
        clock: Callable[[], float] = time.time,
        ttl_seconds: float = 3600.0,
    ) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                tenant_id TEXT NOT NULL,
                doc_id    TEXT NOT NULL,
                mapping   TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (tenant_id, doc_id)
            )
            """
        )
        self._conn.commit()
        self._tenant_keys = dict(tenant_keys or {})
        self._clock = clock
        self._ttl = float(ttl_seconds)

    # ------------------------------------------------------------------ api

    def store(self, tenant_id: str, doc_id: str, mapping: dict[str, str]) -> None:
        now = self._clock()
        self._conn.execute(
            "INSERT OR REPLACE INTO vault_entries "
            "(tenant_id, doc_id, mapping, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (tenant_id, doc_id, json.dumps(mapping), now, now + self._ttl),
        )
        self._conn.commit()

    def restore(self, tenant_id: str, doc_id: str, tenant_key: str, payload):
        """Return ``payload`` with placeholders replaced by originals.

        ``payload`` may be a string or a nested dict/list structure.
        Raises VaultAccessError, VaultNotFoundError or
        VaultExpiredError on any rule violation.
        """
        expected = self._tenant_keys.get(tenant_id)
        if expected is None or tenant_key != expected:
            raise VaultAccessError("tenant key does not match this tenant")

        row = self._conn.execute(
            "SELECT mapping, expires_at FROM vault_entries "
            "WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchone()
        if row is None:
            other = self._conn.execute(
                "SELECT 1 FROM vault_entries WHERE doc_id = ?", (doc_id,)
            ).fetchone()
            if other is not None:
                raise VaultAccessError(
                    "document belongs to a different tenant"
                )
            raise VaultNotFoundError("no vault entry for this document")

        mapping = json.loads(row[0])
        if self._clock() > row[1]:
            raise VaultExpiredError("vault entry has expired")

        return self._apply(payload, mapping)

    # -------------------------------------------------------------- helpers

    @staticmethod
    def _apply(payload, mapping: dict[str, str]):
        # Longest placeholder first so [PHONE_10] is never mangled by
        # an earlier [PHONE_1] replacement.
        ordered = sorted(mapping.items(), key=lambda kv: -len(kv[0]))

        def fix(value):
            if isinstance(value, str):
                for placeholder, original in ordered:
                    value = value.replace(placeholder, original)
                return value
            if isinstance(value, dict):
                return {k: fix(v) for k, v in value.items()}
            if isinstance(value, list):
                return [fix(v) for v in value]
            return value

        return fix(payload)

    def close(self) -> None:
        self._conn.close()
