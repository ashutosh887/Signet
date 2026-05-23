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

from . import db, kem as kem_mod, merkle, policy, smt, webhooks as webhooks_mod
from .anomaly import AnomalyDetector, build_training_set
from .stream import StreamHub


load_dotenv()

logger = logging.getLogger("signet")
logging.basicConfig(
    level=os.environ.get("SIGNET_LOG_LEVEL", "INFO").upper(),
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


def _bootstrap_api_keys(conn) -> None:
    raw = os.environ.get("SIGNET_API_KEYS", "").strip()
    if not raw:
        return
    if raw.startswith("{"):
        try:
            mapping = json.loads(raw)
        except json.JSONDecodeError:
            mapping = {}
        for key, tenant in mapping.items():
            db.add_api_key(
                conn, key_hash=_hash_api_key(key), label=tenant, tenant_id=tenant
            )
    else:
        for key in (k.strip() for k in raw.split(",") if k.strip()):
            db.add_api_key(
                conn,
                key_hash=_hash_api_key(key),
                label=db.DEFAULT_TENANT,
                tenant_id=db.DEFAULT_TENANT,
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = db.connect()
    db.init(conn)
    app.state.db = conn
    app.state.hub = StreamHub()
    app.state.nonce_cache = OrderedDict()
    _bootstrap_api_keys(conn)

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

app = FastAPI(title="Signet Verifier", version="0.3.0", lifespan=lifespan)
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
    request.state.tenant_id = db.DEFAULT_TENANT
    if api_keys_required and not any(route.startswith(p) for p in _PUBLIC_PREFIXES):
        key = request.headers.get("x-api-key") or ""
        tenant = db.api_key_tenant(app.state.db, _hash_api_key(key)) if key else None
        if not tenant:
            REQUESTS.labels(route=route, status="401").inc()
            return Response(
                content='{"detail":"unauthorized"}',
                status_code=401,
                media_type="application/json",
            )
        request.state.tenant_id = tenant
    response = await call_next(request)
    elapsed = time.perf_counter() - started
    LATENCY.labels(route=route).observe(elapsed)
    REQUESTS.labels(route=route, status=str(response.status_code)).inc()
    return response


def _tenant_of(request: Request) -> str:
    return getattr(request.state, "tenant_id", db.DEFAULT_TENANT)


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
    tenant_id: str | None = None


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
    policy_rule_id: str | None = None


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


def _policy_context(env: Envelope, agent: dict[str, Any]) -> dict[str, Any]:
    action = env.action or {}
    return {
        "tenant_id": agent.get("tenant_id", db.DEFAULT_TENANT),
        "agent_id": env.agent_id,
        "principal_id": env.principal_id,
        "action_type": action.get("type"),
        "action_name": action.get("name"),
        "params": action.get("params") or {},
        "capability": action.get("capability"),
    }


def _verify(env: Envelope, *, tenant_id: str | None = None) -> Verdict:
    conn = app.state.db
    agent = db.get_agent(conn, env.agent_id)
    if agent is None:
        return Verdict(valid=False, reason="unknown_agent", envelope_id=env.envelope_id)
    if tenant_id is not None and agent.get("tenant_id", db.DEFAULT_TENANT) != tenant_id:
        return Verdict(valid=False, reason="tenant_mismatch", envelope_id=env.envelope_id)
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

    decision = policy.evaluate_policies(
        db.list_policies(
            conn, tenant_id=agent.get("tenant_id", db.DEFAULT_TENANT), enabled_only=True
        ),
        _policy_context(env, agent),
    )
    if not decision.allowed:
        return Verdict(
            valid=False,
            reason=decision.reason or "policy_violation",
            envelope_id=env.envelope_id,
            policy_rule_id=decision.rule_id,
        )

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
def register_identity(reg: IdentityRegistration, request: Request) -> dict[str, str]:
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
    tenant_id = reg.tenant_id or _tenant_of(request)
    db.upsert_agent(
        app.state.db,
        agent_id=reg.agent_id,
        principal_id=reg.principal_id,
        algorithm=reg.algorithm,
        public_key=pk,
        tenant_id=tenant_id,
        hybrid_classical=reg.hybrid_classical,
        hybrid_public_key=hybrid_pk,
    )
    return {
        "agent_id": reg.agent_id,
        "tenant_id": tenant_id,
        "status": "registered",
        "hybrid": "yes" if hybrid_pk else "no",
    }


@app.post("/v1/envelopes/verify", response_model=Verdict)
def verify_envelope(envelope: Envelope, request: Request) -> Verdict:
    api_keys_required = bool(os.environ.get("SIGNET_API_KEYS"))
    return _verify(envelope, tenant_id=_tenant_of(request) if api_keys_required else None)


@app.post("/v1/envelopes/submit", response_model=Verdict)
async def submit_envelope(envelope: Envelope, request: Request) -> Verdict:
    api_keys_required = bool(os.environ.get("SIGNET_API_KEYS"))
    tenant_scope = _tenant_of(request) if api_keys_required else None
    verdict = _verify(envelope, tenant_id=tenant_scope)
    agent = db.get_agent(app.state.db, envelope.agent_id) or {}
    tenant_id = agent.get("tenant_id", db.DEFAULT_TENANT)
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
        tenant_id=tenant_id,
        leaf_hash=leaf,
    )
    ENVELOPES.labels(verdict="valid" if verdict.valid else "invalid").inc()
    await app.state.hub.broadcast(
        {
            "type": "envelope",
            "envelope_id": envelope.envelope_id,
            "agent_id": envelope.agent_id,
            "principal_id": envelope.principal_id,
            "tenant_id": tenant_id,
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
        tenant_id=tenant_id,
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
            tenant_id=tenant_id,
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
async def revoke_agent_endpoint(
    agent_id: str, request: Request, reason: str = "unspecified"
) -> dict[str, str]:
    agent = db.get_agent(app.state.db, agent_id)
    if agent is None:
        raise HTTPException(404, "unknown_agent")
    api_keys_required = bool(os.environ.get("SIGNET_API_KEYS"))
    if api_keys_required and agent.get("tenant_id", db.DEFAULT_TENANT) != _tenant_of(request):
        raise HTTPException(403, "tenant_mismatch")
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
        tenant_id=agent.get("tenant_id", db.DEFAULT_TENANT),
    )
    return {"agent_id": agent_id, "status": "revoked", "reason": reason}


def _tenant_filter(request: Request) -> str | None:
    return _tenant_of(request) if os.environ.get("SIGNET_API_KEYS") else None


@app.get("/v1/agents")
def list_agents_endpoint(request: Request) -> dict[str, Any]:
    rows = db.list_agents(app.state.db, tenant_id=_tenant_filter(request))
    return {"count": len(rows), "agents": rows}


@app.get("/v1/agents/{agent_id}")
def get_agent_endpoint(agent_id: str, request: Request) -> dict[str, Any]:
    agent = db.get_agent(app.state.db, agent_id)
    if agent is None:
        raise HTTPException(404, "unknown_agent")
    tenant_scope = _tenant_filter(request)
    if tenant_scope is not None and agent.get("tenant_id", db.DEFAULT_TENANT) != tenant_scope:
        raise HTTPException(404, "unknown_agent")
    agent.pop("public_key", None)
    agent.pop("hybrid_public_key", None)
    return agent


@app.get("/v1/envelopes/{envelope_id}")
def get_envelope_endpoint(envelope_id: str, request: Request) -> dict[str, Any]:
    env = db.get_envelope(app.state.db, envelope_id)
    if env is None:
        raise HTTPException(404, "unknown_envelope")
    tenant_scope = _tenant_filter(request)
    if tenant_scope is not None and env.get("tenant_id", db.DEFAULT_TENANT) != tenant_scope:
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


def _revoked_agent_ids(conn) -> list[str]:
    rows = conn.execute(
        "SELECT agent_id FROM agents WHERE revoked_at IS NOT NULL ORDER BY agent_id"
    ).fetchall()
    return [r["agent_id"] for r in rows]


@app.get("/v1/revocations/root")
def revocations_root() -> dict[str, Any]:
    ids = _revoked_agent_ids(app.state.db)
    return {
        "algorithm": "sha3-256",
        "depth": smt.DEPTH,
        "size": len(ids),
        "root": smt.compute_root(ids),
    }


@app.get("/v1/agents/{agent_id}/revocation-proof")
def agent_revocation_proof(agent_id: str) -> dict[str, Any]:
    ids = _revoked_agent_ids(app.state.db)
    p = smt.proof(ids, agent_id)
    p["root"] = smt.compute_root(ids)
    return p


class WebhookCreate(BaseModel):
    url: str
    events: list[str] = Field(default_factory=lambda: ["*"])
    secret: str | None = None


@app.post("/v1/webhooks")
def create_webhook(payload: WebhookCreate, request: Request) -> dict[str, Any]:
    webhook_id = f"wh_{secrets.token_hex(8)}"
    db.add_webhook(
        app.state.db,
        webhook_id=webhook_id,
        url=payload.url,
        events=payload.events,
        secret=payload.secret,
        tenant_id=_tenant_of(request),
    )
    return {"webhook_id": webhook_id, "url": payload.url, "events": payload.events}


@app.get("/v1/webhooks")
def list_webhook_endpoints(request: Request) -> dict[str, Any]:
    rows = db.list_webhooks(app.state.db, tenant_id=_tenant_filter(request))
    return {"count": len(rows), "webhooks": rows}


@app.delete("/v1/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str) -> dict[str, str]:
    if not db.delete_webhook(app.state.db, webhook_id):
        raise HTTPException(404, "unknown_webhook")
    return {"webhook_id": webhook_id, "status": "deleted"}


@app.get("/v1/audit")
def audit(
    request: Request, limit: int = 100, agent_id: str | None = None
) -> dict[str, Any]:
    rows = db.recent_envelopes(
        app.state.db,
        limit=limit,
        agent_id=agent_id,
        tenant_id=_tenant_filter(request),
    )
    return {"count": len(rows), "envelopes": rows}


class PolicyRule(BaseModel):
    id: str | None = None
    effect: str = "allow"
    match: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    enabled: bool = True


class PolicyCreate(BaseModel):
    name: str
    rules: list[PolicyRule]
    enabled: bool = True


@app.post("/v1/policies")
def create_policy(payload: PolicyCreate, request: Request) -> dict[str, Any]:
    policy_id = f"pol_{secrets.token_hex(8)}"
    db.upsert_policy(
        app.state.db,
        policy_id=policy_id,
        tenant_id=_tenant_of(request),
        name=payload.name,
        rules=[r.model_dump() for r in payload.rules],
        enabled=payload.enabled,
    )
    return {"policy_id": policy_id, "name": payload.name, "enabled": payload.enabled}


@app.get("/v1/policies")
def list_policy_endpoints(request: Request) -> dict[str, Any]:
    rows = db.list_policies(app.state.db, tenant_id=_tenant_filter(request))
    return {"count": len(rows), "policies": rows}


@app.delete("/v1/policies/{policy_id}")
def delete_policy_endpoint(policy_id: str) -> dict[str, str]:
    if not db.delete_policy(app.state.db, policy_id):
        raise HTTPException(404, "unknown_policy")
    return {"policy_id": policy_id, "status": "deleted"}


class PolicyEvalRequest(BaseModel):
    agent_id: str
    principal_id: str | None = None
    action: dict[str, Any]


@app.post("/v1/policies/evaluate")
def evaluate_policy(payload: PolicyEvalRequest, request: Request) -> dict[str, Any]:
    agent = db.get_agent(app.state.db, payload.agent_id) or {"tenant_id": _tenant_of(request)}
    context = {
        "tenant_id": agent.get("tenant_id", db.DEFAULT_TENANT),
        "agent_id": payload.agent_id,
        "principal_id": payload.principal_id or agent.get("principal_id"),
        "action_type": payload.action.get("type"),
        "action_name": payload.action.get("name"),
        "params": payload.action.get("params") or {},
        "capability": payload.action.get("capability"),
    }
    decision = policy.evaluate_policies(
        db.list_policies(
            app.state.db,
            tenant_id=agent.get("tenant_id", db.DEFAULT_TENANT),
            enabled_only=True,
        ),
        context,
    )
    return {
        "allowed": decision.allowed,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }


class RootAttestation(BaseModel):
    payload: dict[str, Any]
    root_algorithm: str
    root_public_key_b64: str
    signature_b64: str


@app.post("/v1/identities/attested")
def register_attested_identity(att: RootAttestation, request: Request) -> dict[str, str]:
    try:
        import json as _json
        canonical = _json.dumps(att.payload, sort_keys=True, separators=(",", ":")).encode()
        sig = base64.b64decode(att.signature_b64)
        root_pk = base64.b64decode(att.root_public_key_b64)
    except Exception as exc:
        raise HTTPException(400, f"bad attestation: {exc}")

    enabled = set(oqs.get_enabled_sig_mechanisms())
    root_name = None
    for cand in ("SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple"):
        if cand in enabled:
            root_name = cand
            break
    if root_name is None:
        raise HTTPException(501, "verifier liboqs build lacks SLH-DSA/SPHINCS+")
    with oqs.Signature(root_name) as v:
        if not v.verify(canonical, sig, root_pk):
            raise HTTPException(400, "bad_root_signature")

    payload = att.payload
    try:
        pk = base64.b64decode(payload["public_key_b64"])
        hybrid_pk = (
            base64.b64decode(payload["hybrid_public_key_b64"])
            if payload.get("hybrid_public_key_b64") else None
        )
    except Exception as exc:
        raise HTTPException(400, f"bad attested public_key: {exc}")
    tenant_id = payload.get("tenant_id") or _tenant_of(request)
    db.upsert_agent(
        app.state.db,
        agent_id=payload["agent_id"],
        principal_id=payload["principal_id"],
        algorithm=payload.get("algorithm", "ML-DSA-44"),
        public_key=pk,
        tenant_id=tenant_id,
        hybrid_classical=payload.get("hybrid_classical"),
        hybrid_public_key=hybrid_pk,
    )
    return {
        "agent_id": payload["agent_id"],
        "tenant_id": tenant_id,
        "status": "registered",
        "attested_by": payload.get("root_id", ""),
        "root_algorithm": att.root_algorithm,
    }


class KemKeygenRequest(BaseModel):
    tenant_id: str | None = None


@app.post("/v1/kem/keygen")
def kem_keygen(payload: KemKeygenRequest, request: Request) -> dict[str, Any]:
    pair = kem_mod.generate()
    kem_id = f"kem_{secrets.token_hex(8)}"
    db.store_kem_keypair(
        app.state.db,
        kem_id=kem_id,
        tenant_id=payload.tenant_id or _tenant_of(request),
        algorithm=pair.algorithm,
        public_key=pair.classical_public + pair.pq_public,
        secret_key=pair.classical_secret + pair.pq_secret,
    )
    return {
        "kem_id": kem_id,
        "algorithm": pair.algorithm,
        "pq_public_b64": base64.b64encode(pair.pq_public).decode(),
        "classical_public_b64": base64.b64encode(pair.classical_public).decode(),
    }


class KemEncapsulateRequest(BaseModel):
    pq_public_b64: str
    classical_public_b64: str


@app.post("/v1/kem/encapsulate")
def kem_encapsulate(payload: KemEncapsulateRequest) -> dict[str, Any]:
    try:
        pq_pk = base64.b64decode(payload.pq_public_b64)
        cl_pk = base64.b64decode(payload.classical_public_b64)
    except Exception as exc:
        raise HTTPException(400, f"bad base64: {exc}")
    ct, ephem, shared = kem_mod.encapsulate(pq_pk, cl_pk)
    return {
        "algorithm": kem_mod.HYBRID_LABEL,
        "pq_ciphertext_b64": base64.b64encode(ct).decode(),
        "classical_ephemeral_public_b64": base64.b64encode(ephem).decode(),
        "shared_secret_b64": base64.b64encode(shared).decode(),
    }


class KemDecapsulateRequest(BaseModel):
    kem_id: str
    pq_ciphertext_b64: str
    classical_ephemeral_public_b64: str


@app.post("/v1/kem/decapsulate")
def kem_decapsulate(payload: KemDecapsulateRequest) -> dict[str, Any]:
    row = db.get_kem_keypair(app.state.db, payload.kem_id)
    if row is None:
        raise HTTPException(404, "unknown_kem")
    secret = bytes(row["secret_key"])
    cl_sk = secret[:32]
    pq_sk = secret[32:]
    try:
        ct = base64.b64decode(payload.pq_ciphertext_b64)
        ephem = base64.b64decode(payload.classical_ephemeral_public_b64)
    except Exception as exc:
        raise HTTPException(400, f"bad base64: {exc}")
    shared = kem_mod.decapsulate(pq_sk, ct, cl_sk, ephem)
    return {
        "algorithm": row["algorithm"],
        "shared_secret_b64": base64.b64encode(shared).decode(),
    }


class DemoFireRequest(BaseModel):
    prompt: str
    provider: str | None = None


_LLM_TOOLS = [
    {"name": "book_meeting", "params": {"with": "string", "date": "ISO date", "duration_min": "integer"}},
    {"name": "send_email", "params": {"to": "email", "subject": "string", "body": "string"}},
    {"name": "summarize", "params": {"source": "string", "length": "short|medium|long"}},
    {"name": "search_kb", "params": {"query": "string"}},
    {"name": "set_reminder", "params": {"when": "ISO datetime", "what": "string"}},
    {"name": "draft_reply", "params": {"to": "string", "body": "string"}},
    {"name": "fetch_document", "params": {"doc_id": "string"}},
]
_LLM_SYSTEM = (
    "You are an AI assistant that picks ONE tool call to fulfill a user request. "
    'Respond with ONLY a JSON object {"name": <tool>, "params": {...}}. '
    "Available tools: " + json.dumps(_LLM_TOOLS)
)


def _resolve_demo_provider() -> str | None:
    pref = os.environ.get("SIGNET_LLM_PROVIDER")
    if pref in ("openai", "gemini") and os.environ.get(f"{pref.upper()}_API_KEY"):
        return pref
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return None


def _extract_action_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return json.loads(text[start : i + 1])
    raise ValueError(f"no JSON in LLM response: {text!r}")


def _plan_with_llm(prompt: str, provider: str) -> dict[str, Any]:
    import httpx as _httpx
    if provider == "openai":
        key = os.environ["OPENAI_API_KEY"]
        r = _httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": _LLM_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=30.0,
        )
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
    else:
        key = os.environ["GEMINI_API_KEY"]
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        r = _httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": key},
            headers={"content-type": "application/json"},
            json={
                "systemInstruction": {"parts": [{"text": _LLM_SYSTEM}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
            },
            timeout=30.0,
        )
        r.raise_for_status()
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
    body = _extract_action_json(text)
    name = body.get("name") or body.get("tool") or "noop"
    params = body.get("params") or body.get("arguments") or {}
    return {"type": "tool_call", "name": name, "params": params, "planner": provider}


def _get_demo_identity(request: Request):
    from signet import Identity as _SDKIdentity
    if getattr(app.state, "demo_identity", None) is None:
        tenant_id = _tenant_of(request)
        ident = _SDKIdentity.generate(principal_id="prn_demo_button")
        db.upsert_agent(
            app.state.db,
            agent_id=ident.agent_id,
            principal_id=ident.principal_id,
            algorithm=ident.algorithm,
            public_key=ident.public_key,
            tenant_id=tenant_id,
            hybrid_classical="Ed25519",
            hybrid_public_key=ident.ed25519_public,
        )
        app.state.demo_identity = ident
    return app.state.demo_identity


@app.post("/v1/demo/llm-fire")
async def demo_llm_fire(payload: DemoFireRequest, request: Request) -> dict[str, Any]:
    provider = payload.provider or _resolve_demo_provider()
    if not provider:
        raise HTTPException(
            400,
            "no LLM provider configured — set OPENAI_API_KEY or GEMINI_API_KEY in the verifier environment",
        )
    identity = _get_demo_identity(request)
    import asyncio as _asyncio
    from signet import Envelope as _SDKEnvelope
    try:
        action = await _asyncio.get_running_loop().run_in_executor(
            None, _plan_with_llm, payload.prompt, provider
        )
    except Exception as exc:
        raise HTTPException(502, f"llm planner failed: {exc}")

    sdk_env = _SDKEnvelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action=action,
    )
    sdk_env.sign(identity)
    env_dict = sdk_env.to_dict()
    env = Envelope(**env_dict)
    verdict = await submit_envelope(env, request)
    return {
        "envelope_id": env.envelope_id,
        "agent_id": identity.agent_id,
        "provider": provider,
        "action": action,
        "verdict": verdict.model_dump(),
    }


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
