# Launch note — fde-pii-redaction

Pre-launch checklist, worked item by item before any public release.
Every item is PASS or N/A with a reason.

1. **Functionality complete** — PASS: library (text + JSON redaction), token vault, audit log and FastAPI service all implemented and exercised end to end.
2. **Test suite green** — PASS: 74 tests pass with `python3 -m pytest tests/ -q` on Python 3.12.
3. **Measured results verified** — PASS: recall 13/13 planted fixture PII items, precision 8/8 clean strings unchanged, both pinned by tests.
4. **No real personal data** — PASS: every sample value is an obvious synthetic fixture (test cards, 555-01XX numbers, example.com, published example IBANs).
5. **No secrets in the repo** — PASS: tenant keys and salts are labelled fixture placeholders (`fixture-key-a`, `fixture-salt-*`); no real credential exists in the project.
6. **Audit log carries no PII** — PASS: audit stores counts + salted hashes only; a test scans the raw SQLite rows for every planted value.
7. **Tenant isolation tested** — PASS: cross-tenant restore and wrong-key restore are denied and covered by unit + API tests (403).
8. **Expiry behaviour tested** — PASS: vault TTL uses an injected clock; restore before expiry succeeds, after expiry raises and is tested both ways.
9. **False-positive discipline** — PASS: Luhn/mod-97/SSN validation plus the label-gated long-number guard; clean corpus passes unchanged in text and JSON modes.
10. **Input validation** — PASS: unknown redaction modes rejected; `/redact` and `/restore` require exactly one of `text`/`payload` (422 otherwise).
11. **Deterministic behaviour** — PASS: same input + tenant produces the same placeholders/hashes; ordering rules documented and pinned by tests.
12. **README accuracy** — PASS: every number in the README (74 tests, 13/13, 8/8) was measured from the shipped code in this build session.
13. **Scope honesty** — PASS: README states pattern-based limits, fixture-only data, placeholder keys, and that this is not a certified compliance product.
14. **No internal process language in public files** — PASS: README and package docs describe the product only.
15. **Cost** — PASS: $0; pure Python stdlib plus FastAPI/pydantic, runs on free tiers, no paid service or API key needed.
16. **Payments / billing** — N/A: the project takes no payments and has no billing surface.
17. **External sends** — N/A: the service sends nothing anywhere; it is a local library + local HTTP service with no outbound calls.
18. **Database safety** — PASS: SQLite access is parameterised throughout; vault and audit tables hold no raw PII in the audit case and per-tenant mappings only in the vault case.
19. **Error handling** — PASS: vault failures map to typed exceptions in the library and 403 responses in the API; no stack traces leak fixture values.
20. **Licence and attribution** — PASS: MIT licence stated in README and pyproject; example IBANs/cards used are published test fixtures.
