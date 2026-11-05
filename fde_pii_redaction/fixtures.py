"""Synthetic fixture data only.

Every name, number, address and key in this module is an obviously fake
test fixture (test-card numbers, 555-01XX phone range, example.com
addresses, well-known published example IBANs). No real personal data
of any real person is used anywhere in this project.
"""

# Fixture tenant keys used by the vault / API to authorise restores.
FIXTURE_TENANT_KEYS = {
    "tenant-a": "fixture-key-a",
    "tenant-b": "fixture-key-b",
}


def fixture_salt(tenant_id: str) -> str:
    """Per-tenant salt placeholder (fixture value, not a real secret)."""
    return f"fixture-salt-{tenant_id}"


# Small fixture dictionary of names for the name detector.
FIXTURE_NAMES = [
    "Alice Johnson",
    "Bob Smith",
    "Carol Williams",
    "David Brown",
    "Emma Davis",
    "Frank Miller",
    "Grace Wilson",
    "Henry Moore",
    "Ivy Taylor",
    "Jack Anderson",
    "Jane Doe",
    "John Doe",
]

# (value, expected detector type) pairs planted in the PII corpus.
PII_PLANTED = [
    ("fixture@example.com", "EMAIL"),
    ("jane.doe@example.com", "EMAIL"),
    ("(212) 555-0147", "PHONE"),
    ("+44 20 7946 0958", "PHONE"),
    ("4111-1111-1111-1111", "CARD"),
    ("5555 5555 5555 4444", "CARD"),
    ("GB29 NWBK 6016 1331 9268 19", "IBAN"),
    ("DE89 3704 0044 0532 0130 00", "IBAN"),
    ("123-45-6789", "SSN"),
    ("Alice Johnson", "NAME"),
    ("Dr. Frank Miller", "NAME"),
    ("123 Main Street, Springfield, IL 62701", "ADDRESS"),
    ("123456789012", "ID"),
]

PII_CORPUS_TEXT = (
    "Customer Alice Johnson can be reached at fixture@example.com or "
    "(212) 555-0147, and jane.doe@example.com is her backup address. "
    "Her UK line is +44 20 7946 0958. "
    "Billing card 4111-1111-1111-1111 and a second card "
    "5555 5555 5555 4444 are on file. "
    "Payouts go to GB29 NWBK 6016 1331 9268 19 or "
    "DE89 3704 0044 0532 0130 00. "
    "The form lists SSN 123-45-6789 for the applicant. "
    "The referral came from Dr. Frank Miller. "
    "Ship to 123 Main Street, Springfield, IL 62701. "
    "Passport ID: 123456789012 was recorded at intake."
)

# Strings that contain NO PII and must pass through the engine unchanged.
CLEAN_CORPUS = [
    "Order ORD-2026-88412 confirmed, invoice INV-2026-0042 total $1,299.99 due 2026-11-30.",
    "Version v2.3.1 released 2026-11-05, build 12345, 98.6% of checks green.",
    "Reference 1234 5678 9012 3456 was logged by the importer.",
    "Invoice 12345678 was paid in full, receipt R-8841 issued.",
    "Meeting moved to 10:30 on 2026-11-05, room 4, agenda item 12 of 30.",
    "Price changed from $19.99 to $24.50, a 22.5% increase over 90 days.",
    "ISBN 978-3-16-148410-0 scanned at checkout lane 7.",
    "Ticket TKT-0042-771 escalated to tier 2 with priority 3.",
]
