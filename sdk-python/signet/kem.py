from __future__ import annotations

import base64
from typing import Any

import httpx

from .client import DEFAULT_VERIFIER


def keygen(tenant_id: str | None = None, verifier_url: str = DEFAULT_VERIFIER) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    r = httpx.post(f"{verifier_url}/v1/kem/keygen", json=payload)
    r.raise_for_status()
    return r.json()


def encapsulate(
    pq_public_b64: str,
    classical_public_b64: str,
    verifier_url: str = DEFAULT_VERIFIER,
) -> dict[str, Any]:
    r = httpx.post(
        f"{verifier_url}/v1/kem/encapsulate",
        json={
            "pq_public_b64": pq_public_b64,
            "classical_public_b64": classical_public_b64,
        },
    )
    r.raise_for_status()
    return r.json()


def decapsulate(
    kem_id: str,
    pq_ciphertext_b64: str,
    classical_ephemeral_public_b64: str,
    verifier_url: str = DEFAULT_VERIFIER,
) -> dict[str, Any]:
    r = httpx.post(
        f"{verifier_url}/v1/kem/decapsulate",
        json={
            "kem_id": kem_id,
            "pq_ciphertext_b64": pq_ciphertext_b64,
            "classical_ephemeral_public_b64": classical_ephemeral_public_b64,
        },
    )
    r.raise_for_status()
    return r.json()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)
