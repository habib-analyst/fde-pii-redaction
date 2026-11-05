# fde-pii-redaction

PII redaction middleware for a SaaS / AI pipeline. It inspects text and
structured JSON payloads **before** downstream processing, detects
personal data, and replaces it with consistent typed placeholders —
so the analytics job, the LLM call, or the support tool downstream
never sees the raw values. A local token vault can reverse the
masking for the one tenant that owns the document, and every
redaction writes a compliance audit record that contains hashes and
counts only, never the values themselves.

```python
from fde_pii_redaction import RedactionEngine

engine = RedactionEngine()
result = engine.redact_text(
    "Customer Alice Johnson can be reached at fixture@example.com "
    "or (212) 555-0147. Billing card 4111-1111-1111-1111."
)
print(result.output)
# Customer [NAME_1] can be reached at [EMAIL_1] or [PHONE_1].
# Billing card [CARD_1].
print(result.counts)   # {'NAME': 1, 'EMAIL': 1, 'PHONE': 1, 'CARD': 1}
```

## Detectors

Detection is pattern-based, and for the high-risk types a candidate
is only accepted if it also passes a real validation check — shape
alone is never enough:

| Type | Detection | Validation |
|---|---|---|
| `EMAIL` | address pattern | — |
| `PHONE` | US formats (`(212) 555-0147`, `212-555-0147`, `+1 212-555-0147`) and international grouped formats (`+44 20 7946 0958`) | — |
| `CARD` | 13–19 digit candidates, spaced or dashed | **Luhn checksum** — a random 16-digit string that fails Luhn is not flagged |
| `IBAN` | ISO country/length pattern | **mod-97 check (ISO 13616)** |
| `SSN` | `NNN-NN-NNNN` pattern | SSA rules: areas `000`, `666`, `900–999`, group `00` and serial `0000` rejected |
| `NAME` | fixture dictionary + title patterns (`Dr. …`) + context patterns (`Name: …`) | — |
| `ADDRESS` | house number + street-name + street-type pattern, optional city/state/ZIP tail | — |
| `ID` (generic long-number guard) | digit strings of 12+ digits | only next to an identifier label (`Passport ID: …`, `Account: …`) — unlabelled long numbers are left alone |

Every detector reports spans, and overlaps are resolved by a
documented rule: **the most specific detector wins; ties break by
longer span, then earlier position.** Specificity runs IBAN → card →
SSN → email → phone → address → name → generic ID, so a valid card
number is one `CARD` span, never a card plus a phone number carved
out of its middle.

## Redaction modes

- **`mask`** — typed placeholders (`[EMAIL_1]`, `[PHONE_1]`).
  Numbering is per document and consistent: the same value always
  maps to the same placeholder within a document, and a card written
  `4111-1111-1111-1111` and later `4111 1111 1111 1111` is recognised
  as the same value. This is the only reversible mode.
- **`hash`** — one-way tokens (`[EMAIL_9f86d081]`) from a salted
  SHA-256 of the value. Still consistent within and across documents
  for a tenant, impossible to reverse.
- **`partial`** — shape-preserving partial masks: an email becomes
  `f***@example.com`, a card becomes `**** **** **** 1111`, a phone
  or SSN keeps only its last 4 digits.

JSON mode walks nested dicts and lists, redacts string values in
place, and preserves the structure and every non-string value
(numbers, booleans, nulls) exactly. Placeholder consistency is shared
across the whole payload, not reset per field.

## Token vault

In `mask` mode the placeholder → original mapping is stored in a
local SQLite vault, keyed per (tenant, document):

- `/restore` returns the original payload **only** with the tenant
  key registered for that tenant;
- a restore under a different tenant is denied, even with that
  tenant's own valid key;
- entries expire after a TTL measured on an injectable clock, and
  restoring an expired entry fails.

`hash` and `partial` modes store nothing — they are irreversible by
design.

## Compliance audit

One audit record per redact call, containing the tenant, the
document id, detector counts by type, a timestamp, and a salted
SHA-256 hash of the document. Raw PII values are never written to
the log. A `verify_no_pii` check scans the raw audit table and
reports any value that somehow appears there; the test suite runs it
against every planted fixture value.

## Service

```bash
pip install fastapi pydantic uvicorn
uvicorn fde_pii_redaction.api:app --port 8000
```

```bash
curl -X POST localhost:8000/redact -H 'Content-Type: application/json' -d '{
  "tenant_id": "tenant-a", "doc_id": "doc-1",
  "text": "mail fixture@example.com", "mode": "mask"}'
# {"text": "mail [EMAIL_1]", "counts": {"EMAIL": 1}, "doc_hash": "…"}

curl -X POST localhost:8000/restore -H 'Content-Type: application/json' -d '{
  "tenant_id": "tenant-a", "doc_id": "doc-1",
  "tenant_key": "fixture-key-a", "text": "mail [EMAIL_1]"}'
# {"text": "mail fixture@example.com"}
```

Endpoints: `POST /redact`, `POST /restore`, `GET /audit`,
`POST /audit/verify`, `GET /health`. `/redact` accepts either `text`
or a nested `payload`, never both.

## Measured results

Fixture corpora ship in `fde_pii_redaction/fixtures.py`; all data is
synthetic (test-card numbers, 555-01XX phone range, `example.com`
addresses, published example IBANs).

- **Recall: 13 / 13** planted PII items in the PII corpus are caught
  (2 emails, 2 phones, 2 cards, 2 IBANs, 1 SSN, 2 names, 1 address,
  1 labelled ID number).
- **Precision: 8 / 8** clean-corpus strings (order ids, invoice
  numbers, dates, version strings, prices, a non-Luhn 16-digit
  reference number) pass through completely unchanged.
- **Tests: 74 passing** (`python3 -m pytest tests/ -q`), covering
  Luhn and mod-97 accept/reject, SSN validity rules, overlap
  resolution, JSON nesting, placeholder consistency, partial-mask
  formats, vault round-trip / cross-tenant denial / TTL expiry, the
  audit no-PII raw-row scan, and both corpora end to end.

## Scope and honesty

- Detection is **pattern-based**: it catches well-formed PII in the
  shapes listed above. It is not an ML/NER system — names are found
  via a small fixture dictionary plus title/context patterns, and
  free-form addresses outside the street pattern will be missed.
- All sample and test data is **synthetic fixture data**. No real
  personal data is used anywhere in this project.
- Tenant keys and salts in the fixtures are **placeholders** for
  local development and tests, not production secrets management.
- This is a working reference implementation, **not a certified
  compliance product**. Using it does not by itself make a pipeline
  GDPR-, HIPAA- or PCI-compliant.

## Layout

```
fde_pii_redaction/
  detectors.py   span detectors + validation (Luhn, mod-97, SSN rules)
  engine.py      text/JSON redaction, mask / hash / partial modes
  vault.py       SQLite token vault: per-tenant keys, TTL expiry
  audit.py       hash-only compliance audit log + verify_no_pii
  api.py         FastAPI service (/redact, /restore, /audit)
  fixtures.py    synthetic corpora, fixture names, tenant keys
tests/           74 tests across detectors, engine, vault, audit,
                 corpora and the HTTP API
```

## License

MIT
