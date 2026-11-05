"""Redaction engine: text mode, JSON mode, three redaction modes.

Modes:

* ``mask``    - typed placeholders (``[EMAIL_1]``). Numbering is per
  document and consistent: the same value always gets the same
  placeholder within one document, and a card written as
  ``4111-1111-1111-1111`` and later as ``4111 1111 1111 1111`` is the
  same value. This is the only reversible mode (via the token vault).
* ``hash``    - one-way tokens (``[EMAIL_9f86d081]``) derived from a
  salted SHA-256 of the value. Irreversible by design.
* ``partial`` - shape-preserving partial masks: an email becomes
  ``f***@example.com``, a card becomes ``**** **** **** 1111``, a
  phone keeps only its last 4 digits. Lossy, so also irreversible.

Every redact call (text or JSON) writes exactly one compliance audit
record when an audit log is attached, and stores the placeholder
mapping in the vault when a vault is attached and the mode is
``mask``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from . import detectors
from .audit import AuditLog, document_hash
from .fixtures import fixture_salt
from .vault import TokenVault

MODES = ("mask", "hash", "partial")
_DIGIT_TYPES = {"CARD", "PHONE", "SSN", "IBAN"}


def _normalise(span: detectors.Span) -> str:
    """Canonical form of a value for consistency checks."""
    if span.type in _DIGIT_TYPES:
        return re.sub(r"\D", "", span.value)
    if span.type == "EMAIL":
        return span.value.lower()
    return span.value


def _partial_mask(span: detectors.Span) -> str:
    value = span.value
    if span.type == "EMAIL":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if span.type == "CARD":
        return "**** **** **** " + re.sub(r"\D", "", value)[-4:]
    if span.type == "PHONE":
        return "***-***-" + re.sub(r"\D", "", value)[-4:]
    if span.type == "SSN":
        return "***-**-" + re.sub(r"\D", "", value)[-4:]
    if span.type == "IBAN":
        return "**** **** **** " + re.sub(r"[\s]", "", value)[-4:]
    if span.type == "NAME":
        return " ".join(part[:1] + "***" for part in value.split())
    if span.type == "ID":
        digits = re.sub(r"\D", "", value)
        return "*" * max(len(digits) - 2, 1) + digits[-2:]
    return "***"


class _DocContext:
    """Per-document placeholder state shared across a whole payload."""

    def __init__(self, tenant_id: str, mode: str) -> None:
        self.tenant_id = tenant_id
        self.mode = mode
        self.counters: dict[str, int] = {}
        self.by_value: dict[tuple[str, str], str] = {}
        self.mapping: dict[str, str] = {}  # placeholder -> original (mask)
        self.counts: dict[str, int] = {}

    def replacement(self, span: detectors.Span) -> str:
        self.counts[span.type] = self.counts.get(span.type, 0) + 1
        if self.mode == "partial":
            return _partial_mask(span)
        key = (span.type, _normalise(span))
        if key in self.by_value:
            return self.by_value[key]
        if self.mode == "hash":
            digest = hashlib.sha256(
                (fixture_salt(self.tenant_id) + "\x00" + key[1]).encode()
            ).hexdigest()[:8]
            token = f"[{span.type}_{digest}]"
        else:  # mask
            n = self.counters.get(span.type, 0) + 1
            self.counters[span.type] = n
            token = f"[{span.type}_{n}]"
            self.mapping[token] = span.value
        self.by_value[key] = token
        return token


@dataclass
class RedactResult:
    output: object  # str for text mode, same-shaped structure for JSON
    counts: dict[str, int] = field(default_factory=dict)
    mapping: dict[str, str] = field(default_factory=dict)
    doc_hash: str = ""


class RedactionEngine:
    def __init__(
        self,
        vault: TokenVault | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.vault = vault
        self.audit = audit

    # ------------------------------------------------------------- public

    def redact_text(
        self,
        text: str,
        tenant_id: str = "tenant-a",
        doc_id: str = "doc-1",
        mode: str = "mask",
    ) -> RedactResult:
        self._check_mode(mode)
        ctx = _DocContext(tenant_id, mode)
        output = self._redact_str(text, ctx)
        return self._finish(output, text, tenant_id, doc_id, ctx)

    def redact_json(
        self,
        payload,
        tenant_id: str = "tenant-a",
        doc_id: str = "doc-1",
        mode: str = "mask",
    ) -> RedactResult:
        """Redact every string value in a nested dict/list payload.

        Structure and non-string values (numbers, booleans, nulls)
        are preserved exactly; dict keys are left untouched.
        """
        self._check_mode(mode)
        ctx = _DocContext(tenant_id, mode)

        def walk(node):
            if isinstance(node, str):
                return self._redact_str(node, ctx)
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            return node

        output = walk(payload)
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return self._finish(output, canonical, tenant_id, doc_id, ctx)

    def restore(
        self, tenant_id: str, doc_id: str, tenant_key: str, payload
    ):
        if self.vault is None:
            raise RuntimeError("this engine has no token vault attached")
        return self.vault.restore(tenant_id, doc_id, tenant_key, payload)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _check_mode(mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown redaction mode: {mode!r}")

    @staticmethod
    def _redact_str(text: str, ctx: _DocContext) -> str:
        spans = detectors.detect_all(text)
        if not spans:
            return text
        parts = []
        pos = 0
        for span in spans:
            parts.append(text[pos:span.start])
            parts.append(ctx.replacement(span))
            pos = span.end
        parts.append(text[pos:])
        return "".join(parts)

    def _finish(self, output, source_text, tenant_id, doc_id, ctx):
        doc_hash = document_hash(source_text, tenant_id)
        if self.audit is not None:
            self.audit.log_redaction(tenant_id, doc_id, source_text, ctx.counts)
        if self.vault is not None and ctx.mode == "mask" and ctx.mapping:
            self.vault.store(tenant_id, doc_id, ctx.mapping)
        return RedactResult(
            output=output,
            counts=dict(ctx.counts),
            mapping=dict(ctx.mapping),
            doc_hash=doc_hash,
        )
