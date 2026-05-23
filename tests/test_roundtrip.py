"""End-to-end check: SDK signs, verifier accepts, tamper + revocation are rejected."""
from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import httpx

from signet import Envelope, Identity

VERIFIER = "http://localhost:8000"


def register(identity: Identity) -> None:
    r = httpx.post(
        f"{VERIFIER}/v1/identities",
        json={
            "agent_id": identity.agent_id,
            "principal_id": identity.principal_id,
            "algorithm": identity.algorithm,
            "public_key_b64": base64.b64encode(identity.public_key).decode(),
        },
    )
    r.raise_for_status()


def submit(env: Envelope) -> dict:
    r = httpx.post(f"{VERIFIER}/v1/envelopes/submit", json=env.to_dict())
    r.raise_for_status()
    return r.json()


def main() -> None:
    print("=== Signet round-trip test ===")
    identity = Identity.generate(principal_id="prn_demo")
    print(f"  agent_id   = {identity.agent_id}")
    print(f"  algorithm  = {identity.algorithm}")
    print(f"  public_key = {len(identity.public_key)} bytes\n")

    register(identity)

    env = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action={"type": "tool_call", "name": "book_meeting", "params": {"date": "2026-05-24"}},
    )
    t0 = time.perf_counter()
    env.sign(identity)
    sign_ms = (time.perf_counter() - t0) * 1000
    sig_bytes = base64.b64decode(env.signature["value"])
    print(f"  signature = {len(sig_bytes)} bytes ({sign_ms:.1f} ms)\n")

    verdict = submit(env)
    print(f"  valid envelope verdict = {verdict}")
    assert verdict["valid"] is True

    env.action["params"]["date"] = "2030-01-01"
    verdict = submit(env)
    print(f"  tampered envelope verdict = {verdict}")
    assert verdict["valid"] is False

    r = httpx.post(
        f"{VERIFIER}/v1/agents/{identity.agent_id}/revoke", params={"reason": "test"}
    )
    r.raise_for_status()

    env2 = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action={"type": "tool_call", "name": "book_meeting", "params": {"date": "2026-05-24"}},
    )
    env2.sign(identity)
    verdict = submit(env2)
    print(f"  post-revocation verdict = {verdict}")
    assert verdict["valid"] is False and verdict["reason"] == "revoked"

    print("\n=== All round-trip checks passed ===")


if __name__ == "__main__":
    main()
