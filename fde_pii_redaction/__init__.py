"""fde-pii-redaction: PII redaction middleware for SaaS / AI pipelines.

Detects PII in text and structured JSON payloads before downstream
processing, masks it with consistent typed placeholders, optionally
reverses it through a local per-tenant token vault, and writes a
compliance audit record (hashes and counts only, never raw values)
for every redaction. All bundled sample data is synthetic fixture
data.
"""

from .audit import AuditLog
from .detectors import Span, detect_all, iban_ok, luhn_ok, ssn_ok
from .engine import MODES, RedactResult, RedactionEngine
from .vault import (
    TokenVault,
    VaultAccessError,
    VaultError,
    VaultExpiredError,
    VaultNotFoundError,
)

__all__ = [
    "AuditLog",
    "MODES",
    "RedactResult",
    "RedactionEngine",
    "Span",
    "TokenVault",
    "VaultAccessError",
    "VaultError",
    "VaultExpiredError",
    "VaultNotFoundError",
    "detect_all",
    "iban_ok",
    "luhn_ok",
    "ssn_ok",
]

__version__ = "1.0.0"
