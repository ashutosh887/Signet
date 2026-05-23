"""Seed a running verifier with a tenant, a policy, and a small envelope history
so the dashboard is alive on first load.

Usage:
    python scripts/demo_seed.py [--verifier http://localhost:8000]

Idempotent enough for repeated runs: re-running creates fresh agents and policies
but old ones stay in the DB. The dashboard shows whatever's there.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import httpx
from signet import Envelope, Identity


LEGIT_ACTIONS = (
    ("book_meeting", {"date": "2026-05-25", "attendees": 3}),
    ("send_email", {"to": "ops@acme.test", "size_kb": 2}),
    ("fetch_document", {"doc_id": "doc_4f2a"}),
    ("summarize", {"length": "short"}),
    ("search_kb", {"query": "Q2 OKRs"}),
)

ROGUE_ACTIONS = (
    ("exfiltrate_dump", {"target_url": "evil.test", "bytes": 50_000_000}),
    ("wire_transfer", {"amount": 250_000, "to_account": "AT22999"}),
    ("drop_table", {"name": "customers"}),
)


def _register(identity: Identity, verifier: str, tenant: str | None = None) -> None:
    body: dict[str, object] = {
        "agent_id": identity.agent_id,
        "principal_id": identity.principal_id,
        "algorithm": identity.algorithm,
        "public_key_b64": base64.b64encode(identity.public_key).decode(),
        "hybrid_public_key_b64": base64.b64encode(identity.ed25519_public).decode(),
        "hybrid_classical": "Ed25519",
    }
    if tenant:
        body["tenant_id"] = tenant
    httpx.post(f"{verifier}/v1/identities", json=body).raise_for_status()


def _submit(identity: Identity, name: str, params: dict, verifier: str) -> dict:
    env = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action={"type": "tool_call", "name": name, "params": params},
    )
    env.sign(identity)
    r = httpx.post(f"{verifier}/v1/envelopes/submit", json=env.to_dict())
    r.raise_for_status()
    return r.json()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--verifier", default="http://localhost:8000")
    p.add_argument("--tenant", default="acme")
    p.add_argument("--warmup", type=int, default=8, help="legit envelopes per agent")
    args = p.parse_args()

    V = args.verifier
    httpx.get(f"{V}/health", timeout=3).raise_for_status()
    print(f"verifier up at {V}")

    print(f"\n[1/4] creating policy for tenant '{args.tenant}'")
    pol = httpx.post(
        f"{V}/v1/policies",
        json={
            "name": "production-guardrails",
            "rules": [
                {"id": "deny_destructive", "effect": "deny",
                 "match": {"action_name": ["drop_*", "rm_rf*", "wire_transfer"]},
                 "reason": "destructive_or_high_value"},
                {"id": "deny_exfil", "effect": "deny",
                 "match": {"action_name": "exfiltrate_*"},
                 "reason": "data_exfiltration_attempt"},
                {"id": "allow", "effect": "allow"},
            ],
            "enabled": True,
        },
    ).json()
    print(f"  policy_id={pol['policy_id']}  name={pol['name']}")

    print("\n[2/4] provisioning 3 legit agents + 1 rogue agent")
    legit = []
    for i in range(3):
        ident = Identity.generate(principal_id=f"prn_{args.tenant}")
        _register(ident, V, args.tenant)
        legit.append(ident)
        print(f"  legit-{i+1:<2}  {ident.agent_id}")
    rogue = Identity.generate(principal_id=f"prn_{args.tenant}")
    _register(rogue, V, args.tenant)
    print(f"  rogue    {rogue.agent_id}")

    print(f"\n[3/4] warm-up: each legit agent fires {args.warmup} envelopes")
    for _ in range(args.warmup):
        for a in legit:
            _submit(a, *_pick(LEGIT_ACTIONS), V)
    print(f"  {args.warmup * len(legit)} envelopes submitted")

    print("\n[4/4] rogue fires 3 envelopes (policy will deny some, anomaly will score others)")
    for _ in range(3):
        name, params = _pick(ROGUE_ACTIONS)
        v = _submit(rogue, name, params, V)
        flag = "DENY" if not v["valid"] else f"score={v.get('anomaly_score')}"
        print(f"  {name:<22} {flag}")
        time.sleep(0.05)

    root = httpx.get(f"{V}/v1/audit/root").json()
    print(f"\nDone. Audit root: {root['root'][:24]}…  tree_size={root['tree_size']}")
    print("Open the dashboard at http://localhost:3000 to see the live stream.")


def _pick(seq):
    import random
    return random.choice(seq)


if __name__ == "__main__":
    main()
