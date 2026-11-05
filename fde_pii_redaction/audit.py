"""Compliance audit log.

One record is written per redact call. A record contains only:

* the acting tenant id and the document id,
* the document hash (SHA-256 of the document content plus the
  per-tenant fixture salt),
* detector counts by type,
* a timestamp from an injectable clock.

Raw PII values are NEVER written to the audit log. Only their counts
and a salted hash of the whole document are stored, so the log can
prove what was processed without becoming a second copy of the data
it exists to protect. :meth:`AuditLog.verify_no_pii` scans the raw
table rows and reports any value that somehow appears.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Callable

from .fixtures import fixture_salt


def document_hash(content: str, tenant_id: str) -> str:
    return hashlib.sha256(
        (fixture_salt(tenant_id) + "\x00" + content).encode("utf-8")
    ).hexdigest()


def value_hash(value: str, tenant_id: str) -> str:
    """Salted SHA-256 of a single value (never the value itself)."""
    return hashlib.sha256(
        (fixture_salt(tenant_id) + "\x00" + value).encode("utf-8")
    ).hexdigest()


class AuditLog:
    def __init__(
        self,
        db_path: str = ":memory:",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                doc_hash TEXT NOT NULL,
                counts TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        self._conn.commit()
        self._clock = clock

    def log_redaction(
        self,
        tenant_id: str,
        doc_id: str,
        content: str,
        counts: dict[str, int],
    ) -> str:
        """Write one audit record; returns the document hash stored."""
        doc_hash = document_hash(content, tenant_id)
        self._conn.execute(
            "INSERT INTO audit_records "
            "(tenant_id, doc_id, doc_hash, counts, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (tenant_id, doc_id, doc_hash, json.dumps(counts), self._clock()),
        )
        self._conn.commit()
        return doc_hash

    def records(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT tenant_id, doc_id, doc_hash, counts, created_at "
            "FROM audit_records ORDER BY id"
        ).fetchall()
        return [
            {
                "tenant_id": r[0],
                "doc_id": r[1],
                "doc_hash": r[2],
                "counts": json.loads(r[3]),
                "created_at": r[4],
            }
            for r in rows
        ]

    def raw_rows(self) -> list[tuple]:
        return self._conn.execute("SELECT * FROM audit_records").fetchall()

    def verify_no_pii(self, values: list[str]) -> list[str]:
        """Return any of ``values`` found anywhere in the raw table.

        An empty list means the audit log is clean.
        """
        blob = "\n".join(str(cell) for row in self.raw_rows() for cell in row)
        return [v for v in values if v and v in blob]

    def close(self) -> None:
        self._conn.close()
