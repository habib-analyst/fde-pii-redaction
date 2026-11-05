import re

import pytest

from fde_pii_redaction import RedactionEngine


@pytest.fixture()
def engine():
    return RedactionEngine()


def test_text_redaction_uses_typed_placeholders(engine):
    out = engine.redact_text(
        "mail fixture@example.com or call (212) 555-0147"
    ).output
    assert out == "mail [EMAIL_1] or call [PHONE_1]"


def test_placeholder_numbering_is_per_type(engine):
    out = engine.redact_text(
        "a fixture@example.com b jane.doe@example.com c (212) 555-0147"
    ).output
    assert "[EMAIL_1]" in out and "[EMAIL_2]" in out and "[PHONE_1]" in out


def test_same_value_same_placeholder_within_document(engine):
    out = engine.redact_text(
        "fixture@example.com wrote twice: fixture@example.com"
    ).output
    assert out.count("[EMAIL_1]") == 2
    assert "[EMAIL_2]" not in out


def test_same_card_two_formats_same_placeholder(engine):
    out = engine.redact_text(
        "card 4111-1111-1111-1111 equals 4111 1111 1111 1111"
    ).output
    assert out.count("[CARD_1]") == 2


def test_counts_reported_by_type(engine):
    result = engine.redact_text(
        "fixture@example.com and (212) 555-0147 and 123-45-6789"
    )
    assert result.counts == {"EMAIL": 1, "PHONE": 1, "SSN": 1}


def test_json_mode_walks_nested_structures(engine):
    payload = {
        "user": {"email": "fixture@example.com", "age": 41, "vip": True},
        "notes": ["call (212) 555-0147", "no pii here", None],
        "total": 19.99,
    }
    result = engine.redact_json(payload)
    assert result.output == {
        "user": {"email": "[EMAIL_1]", "age": 41, "vip": True},
        "notes": ["call [PHONE_1]", "no pii here", None],
        "total": 19.99,
    }


def test_json_placeholder_consistency_across_fields(engine):
    payload = {"a": "fixture@example.com", "b": {"c": ["fixture@example.com"]}}
    result = engine.redact_json(payload)
    assert result.output["a"] == "[EMAIL_1]"
    assert result.output["b"]["c"] == ["[EMAIL_1]"]


def test_hash_mode_is_deterministic_and_irreversible_shape(engine):
    text = "fixture@example.com and jane.doe@example.com"
    r1 = engine.redact_text(text, mode="hash")
    r2 = engine.redact_text(text, mode="hash")
    assert r1.output == r2.output
    assert re.search(r"\[EMAIL_[0-9a-f]{8}\]", r1.output)
    assert r1.mapping == {}  # nothing reversible is recorded


def test_hash_mode_differs_per_tenant(engine):
    text = "fixture@example.com"
    a = engine.redact_text(text, tenant_id="tenant-a", mode="hash").output
    b = engine.redact_text(text, tenant_id="tenant-b", mode="hash").output
    assert a != b


def test_partial_email_format(engine):
    out = engine.redact_text("fixture@example.com", mode="partial").output
    assert out == "f***@example.com"


def test_partial_card_format(engine):
    out = engine.redact_text("4111-1111-1111-1111", mode="partial").output
    assert out == "**** **** **** 1111"


def test_partial_phone_and_ssn_formats(engine):
    assert engine.redact_text("(212) 555-0147", mode="partial").output == (
        "***-***-0147"
    )
    assert engine.redact_text("123-45-6789", mode="partial").output == (
        "***-**-6789"
    )


def test_unknown_mode_rejected(engine):
    with pytest.raises(ValueError):
        engine.redact_text("hello", mode="scramble")


def test_clean_text_passes_through(engine):
    text = "Order ORD-2026-88412 shipped, total $1,299.99."
    assert engine.redact_text(text).output == text
