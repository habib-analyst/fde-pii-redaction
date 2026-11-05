from fde_pii_redaction import AuditLog, RedactionEngine
from fde_pii_redaction.fixtures import PII_CORPUS_TEXT, PII_PLANTED


def test_one_record_per_redact_call():
    audit = AuditLog()
    engine = RedactionEngine(audit=audit)
    engine.redact_text("fixture@example.com", doc_id="a")
    engine.redact_json({"e": "fixture@example.com"}, doc_id="b")
    records = audit.records()
    assert len(records) == 2
    assert records[0]["counts"] == {"EMAIL": 1}
    assert records[0]["tenant_id"] == "tenant-a"


def test_audit_record_shape():
    audit = AuditLog()
    engine = RedactionEngine(audit=audit)
    engine.redact_text(
        "fixture@example.com and (212) 555-0147", doc_id="shape"
    )
    (record,) = audit.records()
    assert record["counts"] == {"EMAIL": 1, "PHONE": 1}
    assert record["doc_id"] == "shape"
    assert len(record["doc_hash"]) == 64  # SHA-256 hex


def test_audit_log_contains_no_fixture_pii():
    audit = AuditLog()
    engine = RedactionEngine(audit=audit)
    engine.redact_text(PII_CORPUS_TEXT, doc_id="full")
    planted_values = [value for value, _ in PII_PLANTED]
    assert audit.verify_no_pii(planted_values) == []


def test_audit_raw_rows_scan_is_real():
    # Scan the raw SQLite rows directly: no planted value anywhere.
    audit = AuditLog()
    engine = RedactionEngine(audit=audit)
    engine.redact_text(PII_CORPUS_TEXT, doc_id="raw")
    blob = repr(audit.raw_rows())
    for value, _ in PII_PLANTED:
        assert value not in blob


def test_doc_hash_is_deterministic_and_tenant_salted():
    audit = AuditLog()
    engine = RedactionEngine(audit=audit)
    r1 = engine.redact_text("same text", tenant_id="tenant-a")
    r2 = engine.redact_text("same text", tenant_id="tenant-a")
    r3 = engine.redact_text("same text", tenant_id="tenant-b")
    assert r1.doc_hash == r2.doc_hash
    assert r1.doc_hash != r3.doc_hash
