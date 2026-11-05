"""Pattern-based PII detectors.

Each detector scans a text and returns candidate spans. Candidates are
then passed through overlap resolution (see :func:`resolve_overlaps`)
so every character of the input belongs to at most one detection.

Validation, not just shape, decides the high-risk types:

* credit cards must pass the Luhn checksum, so a random 16-digit
  string that fails Luhn is NOT flagged as a card;
* IBANs must pass the ISO 13616 mod-97 check;
* SSN-style numbers must satisfy the SSA area/group/serial rules
  (areas 000, 666 and 900-999, group 00 and serial 0000 rejected).

The generic long-number guard is deliberately conservative: it only
fires for digit strings of at least ``LONG_NUMBER_MIN_DIGITS`` digits
that appear next to an identifier label (``Passport ID: ...``,
``Account: ...``). Unlabelled long numbers are left alone, which is
what keeps order ids, invoice numbers and reference numbers in the
clean corpus untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .fixtures import FIXTURE_NAMES

LONG_NUMBER_MIN_DIGITS = 12

# Lower number = wins an overlap. Roughly: structured, checksummed
# identifiers first, then contact details, then contextual types,
# then the generic guard last.
SPECIFICITY = {
    "IBAN": 0,
    "CARD": 1,
    "SSN": 2,
    "EMAIL": 3,
    "PHONE": 4,
    "ADDRESS": 5,
    "NAME": 6,
    "ID": 7,
}


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    value: str

    @property
    def length(self) -> int:
        return self.end - self.start


# ---------------------------------------------------------------- checksums

def luhn_ok(digits: str) -> bool:
    """True if a digit string passes the Luhn checksum."""
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    """True if an IBAN passes the ISO 13616 mod-97 check."""
    compact = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged
    )
    return int(numeric) % 97 == 1


def ssn_ok(area: str, group: str, serial: str) -> bool:
    """SSA validity rules for SSN-style numbers."""
    a = int(area)
    if a == 0 or a == 666 or a >= 900:
        return False
    if int(group) == 0:
        return False
    if int(serial) == 0:
        return False
    return True


# ---------------------------------------------------------------- detectors

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_CARD_CANDIDATE_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

_IBAN_CANDIDATE_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b"
)

_SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")

_PHONE_RES = [
    # (212) 555-0147
    re.compile(r"\(\d{3}\)\s*\d{3}[-.\s]\d{4}\b"),
    # +1 212-555-0147 / +1-212-555-0147 / 212-555-0147 / 212.555.0147
    re.compile(r"(?:\+\d{1,3}[-.\s]?)?\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),
    # +44 20 7946 0958 (international, grouped)
    re.compile(r"\+\d{1,3}\s\d{2}\s\d{4}\s\d{4}\b"),
    # +1-555-0147 style short fixture numbers
    re.compile(r"\+\d{1,3}-\d{3}-\d{4}\b"),
]

_ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct)\b"
    r"(?:,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,\s*[A-Z]{2}\s*\d{5})?"
)

_NAME_DICT = sorted(FIXTURE_NAMES, key=len, reverse=True)
_NAME_TITLE_RE = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?"
)
_NAME_CONTEXT_RE = re.compile(
    r"(?i)\b(?:name|patient|contact|customer|applicant)\s*:\s*"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})"
)

_ID_LABEL_RE = re.compile(
    r"(?i)\b(?:passport(?:\s+id)?|account|acct|licen[cs]e|member|policy|"
    r"national\s+id|customer\s+id|employee\s+id|id)\s*[:#]\s*(\d[\d ]*\d|\d)"
)


def detect_emails(text: str) -> list[Span]:
    return [Span(m.start(), m.end(), "EMAIL", m.group()) for m in _EMAIL_RE.finditer(text)]


def detect_cards(text: str) -> list[Span]:
    spans = []
    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            spans.append(Span(m.start(), m.end(), "CARD", m.group()))
    return spans


def detect_ibans(text: str) -> list[Span]:
    spans = []
    for m in _IBAN_CANDIDATE_RE.finditer(text):
        if iban_ok(m.group()):
            spans.append(Span(m.start(), m.end(), "IBAN", m.group()))
    return spans


def detect_ssns(text: str) -> list[Span]:
    spans = []
    for m in _SSN_RE.finditer(text):
        if ssn_ok(m.group(1), m.group(2), m.group(3)):
            spans.append(Span(m.start(), m.end(), "SSN", m.group()))
    return spans


def detect_phones(text: str) -> list[Span]:
    spans = []
    for rx in _PHONE_RES:
        for m in rx.finditer(text):
            spans.append(Span(m.start(), m.end(), "PHONE", m.group()))
    return spans


def detect_addresses(text: str) -> list[Span]:
    return [Span(m.start(), m.end(), "ADDRESS", m.group()) for m in _ADDRESS_RE.finditer(text)]


def detect_names(text: str) -> list[Span]:
    spans = []
    for name in _NAME_DICT:
        for m in re.finditer(r"\b" + re.escape(name) + r"\b", text):
            spans.append(Span(m.start(), m.end(), "NAME", m.group()))
    for m in _NAME_TITLE_RE.finditer(text):
        spans.append(Span(m.start(), m.end(), "NAME", m.group()))
    for m in _NAME_CONTEXT_RE.finditer(text):
        spans.append(Span(m.start(1), m.end(1), "NAME", m.group(1)))
    # The dictionary and context passes can find the same name twice.
    seen: set[tuple[int, int]] = set()
    unique = []
    for span in spans:
        if (span.start, span.end) not in seen:
            seen.add((span.start, span.end))
            unique.append(span)
    return unique


def detect_long_numbers(text: str) -> list[Span]:
    spans = []
    for m in _ID_LABEL_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if len(digits) >= LONG_NUMBER_MIN_DIGITS:
            spans.append(Span(m.start(1), m.end(1), "ID", m.group(1)))
    return spans


ALL_DETECTORS = [
    detect_ibans,
    detect_cards,
    detect_ssns,
    detect_emails,
    detect_phones,
    detect_addresses,
    detect_names,
    detect_long_numbers,
]


def resolve_overlaps(candidates: list[Span]) -> list[Span]:
    """Overlap resolution: the most specific detector wins; ties are
    broken by the longer span, then by the earlier start.

    Candidates are considered in (specificity, -length, start) order
    and accepted greedily if they do not overlap an accepted span.
    The result is returned sorted by start position.
    """
    ordered = sorted(
        candidates,
        key=lambda s: (SPECIFICITY[s.type], -s.length, s.start),
    )
    accepted: list[Span] = []
    for cand in ordered:
        if any(cand.start < a.end and a.start < cand.end for a in accepted):
            continue
        accepted.append(cand)
    return sorted(accepted, key=lambda s: s.start)


def detect_all(text: str) -> list[Span]:
    """Run every detector over ``text`` and resolve overlaps."""
    candidates: list[Span] = []
    for detector in ALL_DETECTORS:
        candidates.extend(detector(text))
    return resolve_overlaps(candidates)
