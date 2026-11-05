"""FastAPI service exposing the redactor as /redact and /restore.

Run locally with::

    uvicorn fde_pii_redaction.api:app --port 8000

The app factory accepts injected vault/audit/engine instances so
tests (and embedders) can control the clock, the TTL and the storage.
The default module-level app uses in-memory storage and the fixture
tenant keys from :mod:`fde_pii_redaction.fixtures`.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, model_validator

from .audit import AuditLog
from .engine import RedactionEngine
from .fixtures import FIXTURE_TENANT_KEYS
from .vault import TokenVault, VaultError


class RedactRequest(BaseModel):
    tenant_id: str
    doc_id: str
    text: Optional[str] = None
    payload: Optional[Any] = None
    mode: str = "mask"

    @model_validator(mode="after")
    def _exactly_one_input(self):
        if (self.text is None) == (self.payload is None):
            raise ValueError("provide exactly one of 'text' or 'payload'")
        return self


class RestoreRequest(BaseModel):
    tenant_id: str
    doc_id: str
    tenant_key: str
    text: Optional[str] = None
    payload: Optional[Any] = None

    @model_validator(mode="after")
    def _exactly_one_input(self):
        if (self.text is None) == (self.payload is None):
            raise ValueError("provide exactly one of 'text' or 'payload'")
        return self


class AuditVerifyRequest(BaseModel):
    values: list[str]


def create_app(
    engine: RedactionEngine | None = None,
    tenant_keys: dict[str, str] | None = None,
) -> FastAPI:
    keys = tenant_keys or FIXTURE_TENANT_KEYS
    if engine is None:
        engine = RedactionEngine(
            vault=TokenVault(tenant_keys=keys), audit=AuditLog()
        )

    app = FastAPI(title="fde-pii-redaction", version="1.0.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/redact")
    def redact(req: RedactRequest) -> dict:
        try:
            if req.text is not None:
                result = engine.redact_text(
                    req.text, tenant_id=req.tenant_id,
                    doc_id=req.doc_id, mode=req.mode,
                )
                return {
                    "text": result.output,
                    "counts": result.counts,
                    "doc_hash": result.doc_hash,
                }
            result = engine.redact_json(
                req.payload, tenant_id=req.tenant_id,
                doc_id=req.doc_id, mode=req.mode,
            )
            return {
                "payload": result.output,
                "counts": result.counts,
                "doc_hash": result.doc_hash,
            }
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.post("/restore")
    def restore(req: RestoreRequest) -> dict:
        payload = req.text if req.text is not None else req.payload
        try:
            restored = engine.restore(
                req.tenant_id, req.doc_id, req.tenant_key, payload
            )
        except VaultError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        if req.text is not None:
            return {"text": restored}
        return {"payload": restored}

    @app.get("/audit")
    def audit_records() -> dict:
        if engine.audit is None:
            return {"records": []}
        return {"records": engine.audit.records()}

    @app.post("/audit/verify")
    def audit_verify(req: AuditVerifyRequest) -> dict:
        if engine.audit is None:
            return {"leaked": []}
        return {"leaked": engine.audit.verify_no_pii(req.values)}

    app.state.engine = engine
    return app


app = create_app()
