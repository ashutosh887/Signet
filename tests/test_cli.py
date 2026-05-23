"""Argparse-level CLI smoke tests — verifies the subcommand surface promised in PRD §10.3."""
from signet.cli import build_parser


def test_all_subcommands_registered() -> None:
    p = build_parser()
    actions = next(a for a in p._actions if a.dest == "command")
    names = set(actions.choices.keys())
    for required in {
        "keygen", "register", "sign", "verify", "submit",
        "revoke", "audit", "agent", "envelope", "anomaly",
        "proof", "policy",
    }:
        assert required in names, f"missing subcommand: {required}"


def test_anomaly_score_subcommand_parses() -> None:
    p = build_parser()
    args = p.parse_args(["anomaly", "score", "--envelope", "/tmp/e.json"])
    assert args.command == "anomaly"
    assert args.envelope == "/tmp/e.json"


def test_proof_subcommand_parses() -> None:
    p = build_parser()
    args = p.parse_args(["proof", "env_abc"])
    assert args.envelope_id == "env_abc"


def test_policy_add_subcommand_parses() -> None:
    p = build_parser()
    args = p.parse_args(["policy", "add", "--name", "n", "--rules", "/tmp/r.json"])
    assert args.command == "policy"
    assert args.name == "n"
    assert args.rules == "/tmp/r.json"
