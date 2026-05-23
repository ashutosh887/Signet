"""@signet.wrap and signet.delegate smoke test."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import signet


def main() -> None:
    identity = signet.Identity.generate(principal_id="prn_wrap_test")
    signet.register(identity)

    @signet.wrap(identity=identity, capabilities=["book_meeting"])
    def my_agent(query: str) -> dict:
        return {
            "name": "book_meeting",
            "params": {"q": query, "date": "2026-05-24"},
        }

    out = my_agent("coffee with Akash on Monday")
    print("wrap result:")
    print(f"  envelope_id   = {out['envelope_id']}")
    print(f"  capabilities  = {out['capabilities']}")
    print(f"  action.name   = {out['action']['name']}")
    print(f"  verdict.valid = {out['verdict']['valid']}")
    print(f"  score         = {out['verdict']['anomaly_score']}")
    assert out["verdict"]["valid"] is True

    print("\nDelegating to a child agent ...")
    child, deleg = signet.delegate(identity, capabilities=["send_email"], ttl_seconds=900)
    signet.register(child)
    print(f"  parent_agent = {identity.agent_id}")
    print(f"  child_agent  = {child.agent_id}")
    print(f"  cap_id       = {deleg['action']['params']['cap_id']}")
    print(f"  signed by    = {deleg['signature']['algorithm']}")
    print("\nOK")


if __name__ == "__main__":
    main()
