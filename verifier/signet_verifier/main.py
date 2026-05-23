from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel, Field

import oqs

from . import db, merkle, webhooks as webhooks_mod
from .anomaly import AnomalyDetector, build_training_set
from .stream import StreamHub


load_dotenv()

logger = logging.getLogger("signet")
logging.basicConfig(
    level=os.environ.get("SIGNET_LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s","logger":"%(name)s"}',
)

_ALGO_CANDIDATES = ("ML-DSA-44", "Dilithium2")
_REPLAY_CACHE_SIZE = 4096

REQUESTS = Counter(
    "signet_requests_total",
    "Verifier requests by route and status",
    ["route", "status"],
)
ENVELOPES = Counter(
    "signet_envelopes_total",
    "Submitted envelopes by verdict",
    ["verdict"],
)
LATENCY = Histogram(
    "signet_request_seconds",
    "Verifier request latency",
    ["route"],
)
ANOMALY_GAUGE = Histogram(
    "signet_anomaly_score",
    "Anomaly score distribution",
    buckets=(0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = db.connect()
    db.init(conn)
    app.state.db = conn
    app.state.hub = StreamHub()
    app.state.nonce_cache = OrderedDict()

    detector = AnomalyDetector()
    if os.environ.get("SIGNET_SKIP_TRAIN") != "1":
        n_legit = int(os.environ.get("SIGNET_TRAIN_LEGIT", "120"))
        n_rogue = int(os.environ.get("SIGNET_TRAIN_ROGUE", "40"))
        X, y = build_training_set(n_legit=n_legit, n_rogue=n_rogue)
        report = detector.fit(X, y)
        print(
            f"[signet] anomaly detector trained: "
            f"quantum_auc={report.quantum_auc:.3f} rbf_auc={report.rbf_auc:.3f} "
            f"serving={report.chosen}"
        )
    app.state.detector = detector

    try:
        yield
    finally:
        conn.close()


_cors_origins = [o.strip() for o in os.environ.get("SIGNET_CORS_ORIGINS", "*").split(",") if o.strip()]

app = FastAPI(title="Signet Verifier", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


_PUBLIC_PREFIXES = ("/health", "/metrics", "/openapi", "/docs", "/redoc", "/ws/stream")


def _hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@app.middleware("http")
async def telemetry_and_auth(request: Request, call_next):
    route = request.url.path
    started = time.perf_counter()
    api_keys_required = bool(os.environ.get("SIGNET_API_KEYS"))
    if api_keys_required and not any(route.startswith(p) for p in _PUBLIC_PREFIXES):
        key = request.headers.get("x-api-key") or ""
        if not key or not db.api_key_exists(app.state.db, _hash_api_key(key)):
            REQUESTS.labels(route=route, status="401").inc()
            return Response(
                content='{"detail":"unauthorized"}',
                status_code=401,
                media_type="application/json",
            )
    response = await call_next(request)
    elapsed = time.perf_counter() - started
    LATENCY.labels(route=route).observe(elapsed)
    REQUESTS.labels(route=route, status=str(response.status_code)).inc()
    return response


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


class IdentityRegistration(BaseModel):
    agent_id: str
    principal_id: str
    algorithm: str = "ML-DSA-44"
    public_key_b64: str
    hybrid_classical: str | None = None
    hybrid_public_key_b64: str | None = None


class Envelope(BaseModel):
    envelope_version: str = "signet/1"
    envelope_id: str
    agent_id: str
    principal_id: str
    issued_at: str
    expires_at: str
    nonce: str
    action: dict[str, Any]
    signature: dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    valid: bool
    reason: str | None = None
    anomaly_score: float | None = None
    envelope_id: str | None = None


def _resolve_algorithm(preferred: str) -> str:
    enabled = set(oqs.get_enabled_sig_mechanisms())
    if preferred in enabled:
        return preferred
    for name in _ALGO_CANDIDATES:
        if name in enabled:
            return name
    raise RuntimeError(f"liboqs is missing ML-DSA-44; available: {sorted(enabled)}")


def _canonical_payload(env: Envelope) -> bytes:
    payload = {
        "envelope_version": env.envelope_version,
        "envelope_id": env.envelope_id,
        "agent_id": env.agent_id,
        "principal_id": env.principal_id,
        "issued_at": env.issued_at,
        "expires_at": env.expires_at,
        "nonce": env.nonce,
        "action": env.action,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _remember_nonce(env: Envelope) -> bool:
    cache: OrderedDict[str, str] = app.state.nonce_cache
    key = f"{env.agent_id}:{env.nonce}"
    if key in cache:
        return False
    cache[key] = env.envelope_id
    while len(cache) > _REPLAY_CACHE_SIZE:
        cache.popitem(last=False)
    return True


def _verify(env: Envelope) -> Verdict:
    conn = app.state.db
    agent = db.get_agent(conn, env.agent_id)
    if agent is None:
        return Verdict(valid=False, reason="unknown_agent", envelope_id=env.envelope_id)
    if agent.get("revoked_at"):
        return Verdict(valid=False, reason="revoked", envelope_id=env.envelope_id)

    try:
        expires = _parse_iso(env.expires_at)
    except ValueError:
        return Verdict(valid=False, reason="bad_expires_at", envelope_id=env.envelope_id)
    if _now() > expires:
        return Verdict(valid=False, reason="expired", envelope_id=env.envelope_id)

    sig_b64 = env.signature.get("value")
    if not sig_b64:
        return Verdict(valid=False, reason="missing_signature", envelope_id=env.envelope_id)
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return Verdict(valid=False, reason="bad_signature_b64", envelope_id=env.envelope_id)

    oqs_name = _resolve_algorithm(agent["algorithm"])
    payload = _canonical_payload(env)
    with oqs.Signature(oqs_name) as verifier:
        ok = bool(verifier.verify(payload, sig, bytes(agent["public_key"])))
    if not ok:
        return Verdict(valid=False, reason="bad_signature", envelope_id=env.envelope_id)

    classical_sig_b64 = env.signature.get("hybrid_classical_value")
    if agent.get("hybrid_public_key") and classical_sig_b64:
        try:
            classical_sig = base64.b64decode(classical_sig_b64)
            Ed25519PublicKey.from_public_bytes(bytes(agent["hybrid_public_key"])).verify(
                classical_sig, payload
            )
        except Exception:
            return Verdict(
                valid=False, reason="bad_hybrid_signature", envelope_id=env.envelope_id
            )
    elif agent.get("hybrid_public_key") and not classical_sig_b64:
        return Verdict(
            valid=False, reason="missing_hybrid_signature", envelope_id=env.envelope_id
        )

    if not _remember_nonce(env):
        return Verdict(valid=False, reason="replay", envelope_id=env.envelope_id)

    return Verdict(valid=True, anomaly_score=0.0, envelope_id=env.envelope_id)


def _score_for_agent(agent_id: str, current: Envelope) -> float | None:
    detector: AnomalyDetector | None = getattr(app.state, "detector", None)
    if detector is None or detector.rbf_svc is None:
        return None
    recent = db.recent_envelopes(app.state.db, limit=20, agent_id=agent_id)
    window = [
        {"issued_at": r["received_at"], "action": r["action"]} for r in recent
    ]
    window.insert(0, {"issued_at": current.issued_at, "action": current.action})
    try:
        return float(detector.score_envelopes(window))
    except Exception:
        return None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/identities")
def register_identity(reg: IdentityRegistration) -> dict[str, str]:
    try:
        pk = base64.b64decode(reg.public_key_b64)
    except Exception as exc:
        raise HTTPException(400, f"bad public_key_b64: {exc}")
    hybrid_pk: bytes | None = None
    if reg.hybrid_public_key_b64:
        try:
            hybrid_pk = base64.b64decode(reg.hybrid_public_key_b64)
        except Exception as exc:
            raise HTTPException(400, f"bad hybrid_public_key_b64: {exc}")
    db.upsert_agent(
        app.state.db,
        agent_id=reg.agent_id,
        principal_id=reg.principal_id,
        algorithm=reg.algorithm,
        public_key=pk,
        hybrid_classical=reg.hybrid_classical,
        hybrid_public_key=hybrid_pk,
    )
    return {
        "agent_id": reg.agent_id,
        "status": "registered",
        "hybrid": "yes" if hybrid_pk else "no",
    }


@app.post("/v1/envelopes/verify", response_model=Verdict)
def verify_envelope(envelope: Envelope) -> Verdict:
    return _verify(envelope)


@app.post("/v1/envelopes/submit", response_model=Verdict)
async def submit_envelope(envelope: Envelope) -> Verdict:
    verdict = _verify(envelope)
    if verdict.valid:
        score = _score_for_agent(envelope.agent_id, envelope)
        if score is not None:
            verdict.anomaly_score = score
            ANOMALY_GAUGE.observe(score)
    leaf = merkle.leaf_hash(envelope.model_dump()) if verdict.valid else None
    received_at, leaf_index = db.insert_envelope(
        app.state.db,
        envelope_id=envelope.envelope_id,
        agent_id=envelope.agent_id,
        principal_id=envelope.principal_id,
        action=envelope.action,
        signature=envelope.signature,
        verdict="valid" if verdict.valid else "invalid",
        reason=verdict.reason,
        anomaly_score=verdict.anomaly_score,
        raw=envelope.model_dump(),
        leaf_hash=leaf,
    )
    ENVELOPES.labels(verdict="valid" if verdict.valid else "invalid").inc()
    await app.state.hub.broadcast(
        {
            "type": "envelope",
            "envelope_id": envelope.envelope_id,
            "agent_id": envelope.agent_id,
            "principal_id": envelope.principal_id,
            "action": envelope.action,
            "verdict": verdict.model_dump(),
            "received_at": received_at,
            "leaf_index": leaf_index,
        }
    )
    event = "envelope.verified" if verdict.valid else "envelope.rejected"
    await webhooks_mod.emit(
        app.state.db,
        event,
        {
            "envelope_id": envelope.envelope_id,
            "agent_id": envelope.agent_id,
            "verdict": verdict.model_dump(),
            "leaf_index": leaf_index,
        },
    )
    if verdict.anomaly_score is not None and verdict.anomaly_score >= 0.7:
        await webhooks_mod.emit(
            app.state.db,
            "anomaly.detected",
            {
                "envelope_id": envelope.envelope_id,
                "agent_id": envelope.agent_id,
                "anomaly_score": verdict.anomaly_score,
            },
        )
    return verdict


@app.post("/v1/anomaly/score")
def anomaly_score(envelope: Envelope) -> dict[str, Any]:
    score = _score_for_agent(envelope.agent_id, envelope)
    detector: AnomalyDetector | None = getattr(app.state, "detector", None)
    explanation: list[dict[str, Any]] = []
    if detector is not None and detector.rbf_svc is not None:
        from .anomaly import extract_features

        recent = db.recent_envelopes(app.state.db, limit=20, agent_id=envelope.agent_id)
        window = [
            {"issued_at": r["received_at"], "action": r["action"]} for r in recent
        ]
        window.insert(0, {"issued_at": envelope.issued_at, "action": envelope.action})
        try:
            explanation = detector.explain(extract_features(window))
        except Exception:
            explanation = []
    return {
        "envelope_id": envelope.envelope_id,
        "agent_id": envelope.agent_id,
        "anomaly_score": score,
        "model": detector.chosen if detector else None,
        "top_features": explanation,
    }


@app.get("/v1/anomaly/report")
def anomaly_report() -> dict[str, Any]:
    detector: AnomalyDetector | None = getattr(app.state, "detector", None)
    if detector is None or detector.report is None:
        return {"trained": False}
    r = detector.report
    return {
        "trained": True,
        "quantum_auc": r.quantum_auc,
        "rbf_auc": r.rbf_auc,
        "chosen": r.chosen,
        "threshold": r.threshold,
    }


@app.post("/v1/agents/{agent_id}/revoke")
async def revoke_agent_endpoint(agent_id: str, reason: str = "unspecified") -> dict[str, str]:
    ok = db.revoke_agent(app.state.db, agent_id, reason)
    if not ok:
        raise HTTPException(404, "unknown_agent")
    await app.state.hub.broadcast(
        {"type": "revocation", "agent_id": agent_id, "reason": reason}
    )
    await webhooks_mod.emit(
        app.state.db,
        "agent.revoked",
        {"agent_id": agent_id, "reason": reason},
    )
    return {"agent_id": agent_id, "status": "revoked", "reason": reason}


@app.get("/v1/agents")
def list_agents_endpoint() -> dict[str, Any]:
    rows = db.list_agents(app.state.db)
    return {"count": len(rows), "agents": rows}


@app.get("/v1/agents/{agent_id}")
def get_agent_endpoint(agent_id: str) -> dict[str, Any]:
    agent = db.get_agent(app.state.db, agent_id)
    if agent is None:
        raise HTTPException(404, "unknown_agent")
    agent.pop("public_key", None)
    agent.pop("hybrid_public_key", None)
    return agent


@app.get("/v1/envelopes/{envelope_id}")
def get_envelope_endpoint(envelope_id: str) -> dict[str, Any]:
    env = db.get_envelope(app.state.db, envelope_id)
    if env is None:
        raise HTTPException(404, "unknown_envelope")
    return env


@app.get("/v1/envelopes/{envelope_id}/proof")
def get_inclusion_proof(envelope_id: str) -> dict[str, Any]:
    leaf = db.envelope_leaf(app.state.db, envelope_id)
    if leaf is None:
        raise HTTPException(404, "envelope_not_in_log")
    leaf_hash_hex, leaf_index = leaf
    leaves = db.all_leaf_hashes(app.state.db)
    return {
        "envelope_id": envelope_id,
        "algorithm": "sha3-256",
        "leaf_hash": leaf_hash_hex,
        "leaf_index": leaf_index,
        "tree_size": len(leaves),
        "root": merkle.compute_root(leaves),
        "proof": merkle.inclusion_proof(leaves, leaf_index),
    }


@app.get("/v1/audit/root")
def audit_root() -> dict[str, Any]:
    leaves = db.all_leaf_hashes(app.state.db)
    return {
        "algorithm": "sha3-256",
        "tree_size": len(leaves),
        "root": merkle.compute_root(leaves),
    }


class WebhookCreate(BaseModel):
    url: str
    events: list[str] = Field(default_factory=lambda: ["*"])
    secret: str | None = None


@app.post("/v1/webhooks")
def create_webhook(payload: WebhookCreate) -> dict[str, Any]:
    webhook_id = f"wh_{secrets.token_hex(8)}"
    db.add_webhook(
        app.state.db,
        webhook_id=webhook_id,
        url=payload.url,
        events=payload.events,
        secret=payload.secret,
    )
    return {"webhook_id": webhook_id, "url": payload.url, "events": payload.events}


@app.get("/v1/webhooks")
def list_webhook_endpoints() -> dict[str, Any]:
    rows = db.list_webhooks(app.state.db)
    return {"count": len(rows), "webhooks": rows}


@app.delete("/v1/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str) -> dict[str, str]:
    if not db.delete_webhook(app.state.db, webhook_id):
        raise HTTPException(404, "unknown_webhook")
    return {"webhook_id": webhook_id, "status": "deleted"}


@app.get("/v1/audit")
def audit(limit: int = 100, agent_id: str | None = None) -> dict[str, Any]:
    rows = db.recent_envelopes(app.state.db, limit=limit, agent_id=agent_id)
    return {"count": len(rows), "envelopes": rows}


@app.websocket("/ws/stream")
async def ws_stream(ws: WebSocket) -> None:
    await app.state.hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await app.state.hub.disconnect(ws)
