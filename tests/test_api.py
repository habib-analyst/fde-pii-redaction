import pytest
from fastapi.testclient import TestClient

from fde_pii_redaction.api import create_app
from fde_pii_redaction.fixtures import FIXTURE_TENANT_KEYS, PII_PLANTED


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_redact_text_endpoint(client):
    resp = client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-1",
            "text": "mail fixture@example.com",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["text"] == "mail [EMAIL_1]"
    assert body["counts"] == {"EMAIL": 1}
    assert len(body["doc_hash"]) == 64


def test_redact_json_endpoint(client):
    resp = client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-2",
            "payload": {"contact": {"email": "fixture@example.com"}, "n": 3},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["payload"] == {
        "contact": {"email": "[EMAIL_1]"},
        "n": 3,
    }


def test_redact_restore_round_trip_via_api(client):
    red = client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-3",
            "text": "call (212) 555-0147",
        },
    ).json()
    resp = client.post(
        "/restore",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-3",
            "tenant_key": FIXTURE_TENANT_KEYS["tenant-a"],
            "text": red["text"],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["text"] == "call (212) 555-0147"


def test_restore_cross_tenant_via_api_is_403(client):
    client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-4",
            "text": "call (212) 555-0147",
        },
    )
    resp = client.post(
        "/restore",
        json={
            "tenant_id": "tenant-b",
            "doc_id": "api-4",
            "tenant_key": FIXTURE_TENANT_KEYS["tenant-b"],
            "text": "call [PHONE_1]",
        },
    )
    assert resp.status_code == 403


def test_redact_rejects_both_text_and_payload(client):
    resp = client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-5",
            "text": "x",
            "payload": {"a": 1},
        },
    )
    assert resp.status_code == 422


def test_audit_verify_endpoint_reports_no_pii(client):
    client.post(
        "/redact",
        json={
            "tenant_id": "tenant-a",
            "doc_id": "api-6",
            "text": "mail fixture@example.com, card 4111-1111-1111-1111",
        },
    )
    resp = client.post(
        "/audit/verify",
        json={"values": [v for v, _ in PII_PLANTED]},
    )
    assert resp.status_code == 200
    assert resp.json()["leaked"] == []
