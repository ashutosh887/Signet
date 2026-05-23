from __future__ import annotations

import argparse
import base64
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import httpx
from signet import Envelope, Identity


LEGIT_ACTIONS = (
    ("book_meeting",  {"with": "Akash", "date": "2026-05-25", "duration_min": 30}),
    ("book_meeting",  {"with": "Priya", "date": "2026-05-26", "duration_min": 60}),
    ("send_email",    {"to": "ops@acme.test", "subject": "deploy green", "body": "All checks passed."}),
    ("send_email",    {"to": "team@acme.test", "subject": "standup", "body": "See notes."}),
    ("fetch_document",{"doc_id": "doc_4f2a"}),
    ("fetch_document",{"doc_id": "doc_q2_okr"}),
    ("summarize",     {"source": "Q2 OKR doc", "length": "short"}),
    ("summarize",     {"source": "weekly standup", "length": "medium"}),
    ("search_kb",     {"query": "Q2 OKRs"}),
    ("search_kb",     {"query": "on-call runbook"}),
    ("set_reminder",  {"when": "2026-05-24T09:00:00Z", "what": "Review standup notes"}),
)

BORDERLINE_ACTIONS = (
    ("bulk_export",        {"rows": 25000, "format": "csv"}),
    ("download_attachment",{"size_mb": 480}),
    ("unusual_query",      {"sql": "select * from accounts"}),
    ("external_webhook",   {"url": "https://third.party/ingest"}),
)

ROGUE_ACTIONS = (
    ("exfiltrate_dump", {"target_url": "evil.test", "bytes": 50_000_000}),
    ("wire_transfer",   {"amount": 250_000, "to_account": "AT22999"}),
    ("drop_table",      {"name": "customers"}),
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
    p.add_argument("--tenant", default=None)
    p.add_argument("--warmup", type=int, default=10, help="legit envelopes per agent (canned, fast)")
    p.add_argument("--show", type=int, default=4, help="visible LEGIT envelopes per agent (varied)")
    p.add_argument("--borderline", type=int, default=4, help="borderline envelopes (suspicious shape)")
    p.add_argument("--rogue", type=int, default=3, help="rogue envelopes (policy-denied)")
    args = p.parse_args()

    V = args.verifier
    httpx.get(f"{V}/health", timeout=3).raise_for_status()
    print(f"verifier up at {V}")

    print(f"\n[1/5] creating policy (tenant={args.tenant or 'default'})")
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

    print("\n[2/5] provisioning 3 legit agents + 1 borderline + 1 rogue")
    legit: list[Identity] = []
    for i in range(3):
        ident = Identity.generate(principal_id=f"prn_acme_legit_{i+1}")
        _register(ident, V, args.tenant)
        legit.append(ident)
        print(f"  legit-{i+1:<2}    {ident.agent_id}")
    borderline = Identity.generate(principal_id="prn_acme_borderline")
    _register(borderline, V, args.tenant)
    print(f"  borderline {borderline.agent_id}")
    rogue = Identity.generate(principal_id="prn_acme_rogue")
    _register(rogue, V, args.tenant)
    print(f"  rogue      {rogue.agent_id}")

    print(f"\n[3/5] warm-up: each legit agent fires {args.warmup} canned envelopes (fills the window)")
    for _ in range(args.warmup):
        for a in legit:
            _submit(a, *random.choice(LEGIT_ACTIONS), V)
    # borderline agent gets NO warmup — its short history of out-of-vocab actions
    # is what pushes its anomaly score up
    print(f"  {args.warmup * len(legit)} envelopes submitted")

    print(f"\n[4/5] visible legit traffic: {args.show} envelopes per legit agent")
    for _ in range(args.show):
        for a in legit:
            v = _submit(a, *random.choice(LEGIT_ACTIONS), V)
            score = v.get("anomaly_score")
            print(f"  legit {a.agent_id[:18]}.. score={score}")
            time.sleep(0.02)

    print(f"\n[5a/5] borderline agent fires {args.borderline} oddly-shaped envelopes (anomaly should rise)")
    for _ in range(args.borderline):
        name, params = random.choice(BORDERLINE_ACTIONS)
        v = _submit(borderline, name, params, V)
        score = v.get("anomaly_score")
        print(f"  borderline {name:<18} score={score}")
        time.sleep(0.02)

    print(f"\n[5b/5] rogue fires {args.rogue} envelopes (policy denies them on the cryptographic side)")
    for _ in range(args.rogue):
        name, params = random.choice(ROGUE_ACTIONS)
        v = _submit(rogue, name, params, V)
        flag = f"DENY ({v['reason']})" if not v["valid"] else f"score={v.get('anomaly_score')}"
        print(f"  rogue {name:<22} {flag}")
        time.sleep(0.02)

    root = httpx.get(f"{V}/v1/audit/root").json()
    print(f"\nDone. Audit root: {root['root'][:24]}…  tree_size={root['tree_size']}")
    print("Open the dashboard at http://localhost:3000 to see the live stream.")


if __name__ == "__main__":
    main()
