from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import httpx

from .client import DEFAULT_VERIFIER, audit, get_agent, get_envelope, register, revoke, submit, verify
from .envelope import Envelope
from .identity import Identity


def _load_identity(path: Path) -> Identity:
    data = json.loads(path.read_text())
    return Identity(
        principal_id=data["principal_id"],
        agent_id=data["agent_id"],
        public_key=base64.b64decode(data["public_key_b64"]),
        _secret_key=base64.b64decode(data["secret_key_b64"]),
        ed25519_public=base64.b64decode(data["ed25519_public_b64"]),
        _ed25519_secret=base64.b64decode(data["ed25519_secret_b64"]),
        algorithm=data.get("algorithm", "ML-DSA-44"),
        hybrid_classical=data.get("hybrid_classical", "Ed25519"),
        _oqs_name=data.get("oqs_name", data.get("algorithm", "ML-DSA-44")),
    )


def _dump_identity(identity: Identity, path: Path) -> None:
    data = {
        "principal_id": identity.principal_id,
        "agent_id": identity.agent_id,
        "algorithm": identity.algorithm,
        "hybrid_classical": identity.hybrid_classical,
        "oqs_name": identity._oqs_name,
        "public_key_b64": base64.b64encode(identity.public_key).decode(),
        "secret_key_b64": base64.b64encode(identity._secret_key).decode(),
        "ed25519_public_b64": base64.b64encode(identity.ed25519_public).decode(),
        "ed25519_secret_b64": base64.b64encode(identity._ed25519_secret).decode(),
    }
    path.write_text(json.dumps(data, indent=2))


def cmd_keygen(args: argparse.Namespace) -> int:
    identity = Identity.generate(principal_id=args.principal, algorithm=args.algorithm)
    out = Path(args.out)
    _dump_identity(identity, out)
    print(json.dumps({
        "principal_id": identity.principal_id,
        "agent_id": identity.agent_id,
        "algorithm": identity.algorithm,
        "key_file": str(out),
    }, indent=2))
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    identity = _load_identity(Path(args.key))
    print(json.dumps(register(identity, verifier_url=args.verifier), indent=2))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    identity = _load_identity(Path(args.key))
    action = json.loads(args.action) if args.action else {"type": "tool_call", "name": "noop", "params": {}}
    envelope = Envelope(
        agent_id=identity.agent_id, principal_id=identity.principal_id, action=action
    )
    envelope.sign(identity, hybrid=not args.no_hybrid)
    output = json.dumps(envelope.to_dict(), indent=2)
    if args.out:
        Path(args.out).write_text(output)
    else:
        print(output)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.envelope).read_text())
    env = Envelope(
        agent_id=payload["agent_id"],
        principal_id=payload["principal_id"],
        action=payload["action"],
        envelope_id=payload["envelope_id"],
        envelope_version=payload["envelope_version"],
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        nonce=payload["nonce"],
        signature=payload["signature"],
    )
    print(json.dumps(verify(env, verifier_url=args.verifier), indent=2))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.envelope).read_text())
    env = Envelope(
        agent_id=payload["agent_id"],
        principal_id=payload["principal_id"],
        action=payload["action"],
        envelope_id=payload["envelope_id"],
        envelope_version=payload["envelope_version"],
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        nonce=payload["nonce"],
        signature=payload["signature"],
    )
    print(json.dumps(submit(env, verifier_url=args.verifier), indent=2))
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    print(json.dumps(revoke(args.agent_id, reason=args.reason, verifier_url=args.verifier), indent=2))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    print(json.dumps(audit(agent_id=args.agent, limit=args.limit, verifier_url=args.verifier), indent=2))
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    print(json.dumps(get_agent(args.agent_id, verifier_url=args.verifier), indent=2))
    return 0


def cmd_envelope(args: argparse.Namespace) -> int:
    print(json.dumps(get_envelope(args.envelope_id, verifier_url=args.verifier), indent=2))
    return 0


def cmd_anomaly_score(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.envelope).read_text())
    r = httpx.post(f"{args.verifier}/v1/anomaly/score", json=payload)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))
    return 0


def cmd_proof(args: argparse.Namespace) -> int:
    r = httpx.get(f"{args.verifier}/v1/envelopes/{args.envelope_id}/proof")
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))
    return 0


def cmd_policy_add(args: argparse.Namespace) -> int:
    rules = json.loads(Path(args.rules).read_text())
    r = httpx.post(
        f"{args.verifier}/v1/policies",
        json={"name": args.name, "rules": rules, "enabled": True},
    )
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))
    return 0


def cmd_policy_list(args: argparse.Namespace) -> int:
    r = httpx.get(f"{args.verifier}/v1/policies")
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="signet", description="Signet CLI")
    p.add_argument("--verifier", default=DEFAULT_VERIFIER, help="Verifier base URL")
    sub = p.add_subparsers(dest="command", required=True)

    pk = sub.add_parser("keygen", help="Generate a new identity")
    pk.add_argument("--principal", required=True)
    pk.add_argument("--algorithm", default="ML-DSA-44")
    pk.add_argument("--out", required=True)
    pk.set_defaults(func=cmd_keygen)

    pr = sub.add_parser("register", help="Register an identity with the verifier")
    pr.add_argument("--key", required=True)
    pr.set_defaults(func=cmd_register)

    ps = sub.add_parser("sign", help="Sign an action envelope")
    ps.add_argument("--key", required=True)
    ps.add_argument("--action", help="JSON action document")
    ps.add_argument("--no-hybrid", action="store_true")
    ps.add_argument("--out")
    ps.set_defaults(func=cmd_sign)

    pv = sub.add_parser("verify", help="Verify an envelope file against the verifier")
    pv.add_argument("envelope")
    pv.set_defaults(func=cmd_verify)

    psm = sub.add_parser("submit", help="Submit an envelope file to the verifier")
    psm.add_argument("envelope")
    psm.set_defaults(func=cmd_submit)

    prv = sub.add_parser("revoke", help="Revoke an agent")
    prv.add_argument("agent_id")
    prv.add_argument("--reason", default="manual")
    prv.set_defaults(func=cmd_revoke)

    pa = sub.add_parser("audit", help="List recent envelopes")
    pa.add_argument("--agent", help="Filter by agent_id")
    pa.add_argument("--limit", type=int, default=20)
    pa.set_defaults(func=cmd_audit)

    pag = sub.add_parser("agent", help="Fetch agent metadata")
    pag.add_argument("agent_id")
    pag.set_defaults(func=cmd_agent)

    pe = sub.add_parser("envelope", help="Fetch envelope by id")
    pe.add_argument("envelope_id")
    pe.set_defaults(func=cmd_envelope)

    pan = sub.add_parser("anomaly", help="Anomaly subcommands")
    an_sub = pan.add_subparsers(dest="anomaly_cmd", required=True)
    an_score = an_sub.add_parser("score", help="Score an envelope file")
    an_score.add_argument("--envelope", required=True)
    an_score.set_defaults(func=cmd_anomaly_score)

    pp = sub.add_parser("proof", help="Fetch Merkle inclusion proof for an envelope")
    pp.add_argument("envelope_id")
    pp.set_defaults(func=cmd_proof)

    ppol = sub.add_parser("policy", help="Policy subcommands")
    pol_sub = ppol.add_subparsers(dest="policy_cmd", required=True)
    pol_add = pol_sub.add_parser("add", help="Create a policy from a rules JSON file")
    pol_add.add_argument("--name", required=True)
    pol_add.add_argument("--rules", required=True, help="Path to rules JSON array")
    pol_add.set_defaults(func=cmd_policy_add)
    pol_list = pol_sub.add_parser("list", help="List policies")
    pol_list.set_defaults(func=cmd_policy_list)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
