from __future__ import annotations

import base64

import httpx

from .envelope import Envelope
from .identity import Identity

DEFAULT_VERIFIER = "http://localhost:8000"


def register(identity: Identity, verifier_url: str = DEFAULT_VERIFIER) -> dict:
    r = httpx.post(
        f"{verifier_url}/v1/identities",
        json={
            "agent_id": identity.agent_id,
            "principal_id": identity.principal_id,
            "algorithm": identity.algorithm,
            "public_key_b64": base64.b64encode(identity.public_key).decode(),
            "hybrid_classical": identity.hybrid_classical,
            "hybrid_public_key_b64": base64.b64encode(identity.ed25519_public).decode(),
        },
    )
    r.raise_for_status()
    return r.json()


def verify(envelope: Envelope, verifier_url: str = DEFAULT_VERIFIER) -> dict:
    r = httpx.post(f"{verifier_url}/v1/envelopes/verify", json=envelope.to_dict())
    r.raise_for_status()
    return r.json()


def submit(envelope: Envelope, verifier_url: str = DEFAULT_VERIFIER) -> dict:
    r = httpx.post(f"{verifier_url}/v1/envelopes/submit", json=envelope.to_dict())
    r.raise_for_status()
    return r.json()


def revoke(
    agent_id: str,
    reason: str = "unspecified",
    verifier_url: str = DEFAULT_VERIFIER,
) -> dict:
    r = httpx.post(
        f"{verifier_url}/v1/agents/{agent_id}/revoke",
        params={"reason": reason},
    )
    r.raise_for_status()
    return r.json()


def audit(
    agent_id: str | None = None,
    limit: int = 100,
    verifier_url: str = DEFAULT_VERIFIER,
) -> dict:
    params: dict[str, object] = {"limit": limit}
    if agent_id:
        params["agent_id"] = agent_id
    r = httpx.get(f"{verifier_url}/v1/audit", params=params)
    r.raise_for_status()
    return r.json()


def get_agent(agent_id: str, verifier_url: str = DEFAULT_VERIFIER) -> dict:
    r = httpx.get(f"{verifier_url}/v1/agents/{agent_id}")
    r.raise_for_status()
    return r.json()


def get_envelope(envelope_id: str, verifier_url: str = DEFAULT_VERIFIER) -> dict:
    r = httpx.get(f"{verifier_url}/v1/envelopes/{envelope_id}")
    r.raise_for_status()
    return r.json()
