import pytest

from fde_pii_redaction import (
    RedactionEngine,
    TokenVault,
    VaultAccessError,
    VaultExpiredError,
    VaultNotFoundError,
)
from fde_pii_redaction.fixtures import FIXTURE_TENANT_KEYS

TEXT = "mail fixture@example.com or call (212) 555-0147"
KEY_A = FIXTURE_TENANT_KEYS["tenant-a"]
KEY_B = FIXTURE_TENANT_KEYS["tenant-b"]


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture()
def engine():
    vault = TokenVault(tenant_keys=FIXTURE_TENANT_KEYS, ttl_seconds=600)
    return RedactionEngine(vault=vault)


def test_vault_round_trip(engine):
    result = engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d1")
    assert "fixture@example.com" not in result.output
    restored = engine.restore("tenant-a", "d1", KEY_A, result.output)
    assert restored == TEXT


def test_vault_round_trip_json(engine):
    payload = {"email": "fixture@example.com", "tags": ["(212) 555-0147"]}
    result = engine.redact_json(payload, tenant_id="tenant-a", doc_id="d2")
    restored = engine.restore("tenant-a", "d2", KEY_A, result.output)
    assert restored == payload


def test_restore_with_wrong_key_denied(engine):
    result = engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d3")
    with pytest.raises(VaultAccessError):
        engine.restore("tenant-a", "d3", "fixture-key-WRONG", result.output)


def test_cross_tenant_restore_denied(engine):
    result = engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d4")
    # Tenant B presents its OWN valid key but asks for tenant A's doc.
    with pytest.raises(VaultAccessError):
        engine.restore("tenant-b", "d4", KEY_B, result.output)


def test_restore_unknown_document(engine):
    with pytest.raises(VaultNotFoundError):
        engine.restore("tenant-a", "no-such-doc", KEY_A, "[EMAIL_1]")


def test_restore_after_ttl_expiry_fails():
    clock = FakeClock()
    vault = TokenVault(
        tenant_keys=FIXTURE_TENANT_KEYS, clock=clock, ttl_seconds=60
    )
    engine = RedactionEngine(vault=vault)
    result = engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d5")
    clock.now += 61  # past the TTL
    with pytest.raises(VaultExpiredError):
        engine.restore("tenant-a", "d5", KEY_A, result.output)


def test_restore_before_ttl_expiry_works():
    clock = FakeClock()
    vault = TokenVault(
        tenant_keys=FIXTURE_TENANT_KEYS, clock=clock, ttl_seconds=60
    )
    engine = RedactionEngine(vault=vault)
    result = engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d6")
    clock.now += 59
    assert engine.restore("tenant-a", "d6", KEY_A, result.output) == TEXT


def test_hash_mode_stores_nothing_in_vault(engine):
    engine.redact_text(TEXT, tenant_id="tenant-a", doc_id="d7", mode="hash")
    with pytest.raises(VaultNotFoundError):
        engine.restore("tenant-a", "d7", KEY_A, "[EMAIL_1]")
