from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass

from signet import Envelope, Identity, register, revoke, submit

VERIFIER = os.environ.get("SIGNET_VERIFIER_URL", "http://127.0.0.1:8000")


def _resolve_llm_provider() -> str | None:
    pref = os.environ.get("SIGNET_LLM_PROVIDER")
    if pref in ("openai", "gemini") and os.environ.get(f"{pref.upper()}_API_KEY"):
        return pref
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    return None


LLM_PROVIDER = _resolve_llm_provider()
LLM_PROMPTS = (
    "Schedule a 30-minute meeting with Akash on Monday at 4pm",
    "Send an email to ops@acme.test that the deploy is green",
    "Summarise the Q2 OKR doc in two sentences",
    "Search the internal knowledge base for the on-call runbook",
    "Set a reminder for tomorrow morning to review the standup notes",
    "Book a coffee chat with Priya for Thursday afternoon",
)

LEGIT_ACTIONS = (
    "book_meeting",
    "send_email",
    "fetch_document",
    "summarize",
    "translate",
    "search_kb",
    "draft_reply",
    "set_reminder",
)
ROGUE_ACTIONS = (
    "exfiltrate_dump",
    "wire_transfer",
    "drop_table",
    "spawn_shell",
    "patch_system",
)


def _llm_action() -> dict | None:
    if not LLM_PROVIDER:
        return None
    try:
        from llm_agent import plan_action  # type: ignore
        return plan_action(random.choice(LLM_PROMPTS), LLM_PROVIDER)
    except Exception as exc:
        print(f"  (LLM planner failed, falling back to canned: {exc})")
        return None


def _fire(identity: Identity, *, rogue: bool, use_llm: bool = True) -> dict:
    if rogue:
        name = random.choice(ROGUE_ACTIONS)
        params = {
            f"k{i}": "x" * random.randint(50, 300)
            for i in range(random.randint(8, 18))
        }
        action = {"type": "tool_call", "name": name, "params": params}
    else:
        llm = _llm_action() if use_llm else None
        if llm is not None:
            action = llm
        else:
            name = random.choice(LEGIT_ACTIONS)
            params = {f"p{i}": f"v{i}" for i in range(random.randint(1, 3))}
            action = {"type": "tool_call", "name": name, "params": params}
    env = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action=action,
    )
    env.sign(identity)
    return submit(env, verifier_url=VERIFIER)


def _provision(label: str) -> Identity:
    ident = Identity.generate(principal_id="prn_demo")
    register(ident, verifier_url=VERIFIER)
    print(f"  {label:<18} agent_id = {ident.agent_id}")
    return ident


def main() -> None:
    print("=== Signet rogue-agent demo ===")
    if LLM_PROVIDER:
        print(f"Legit agents will plan via real {LLM_PROVIDER.upper()} model.\n")
    else:
        print("(No LLM key found — legit agents use canned actions.)\n")

    print("Provisioning 3 legit agents + 1 rogue agent:")
    legit = [_provision(f"legit-{i+1}") for i in range(3)]
    rogue = _provision("rogue")
    print()

    print("Silent warm-up: each legit agent fires 22 envelopes to fill the window.")
    for _ in range(22):
        for a in legit:
            _fire(a, rogue=False, use_llm=False)  # canned for speed; window is just for feature stats
    print(f"  warm-up envelopes submitted: {22 * len(legit)}\n")

    print("Legit agents at steady-state — 3 envelopes each:")
    for _ in range(3):
        for a in legit:
            v = _fire(a, rogue=False)
            s = float(v["anomaly_score"] or 0.0)
            zone = "RED" if s >= 0.5 else "yellow" if s >= 0.2 else "green"
            print(f"  legit {a.agent_id[:20]} -> score={s:.3f}  [{zone}]")
            time.sleep(0.05)
    print()

    print("Rogue agent fires 3 anomalous envelopes:")
    rogue_scores: list[float] = []
    for i in range(3):
        v = _fire(rogue, rogue=True)
        s = float(v["anomaly_score"] or 0.0)
        rogue_scores.append(s)
        zone = "RED" if s >= 0.5 else "yellow" if s >= 0.2 else "green"
        print(f"  rogue #{i+1} score={s:.3f}  [{zone}]")
        time.sleep(1.0)
    print()

    if any(s >= 0.5 for s in rogue_scores):
        first_red = next(i for i, s in enumerate(rogue_scores, 1) if s >= 0.5)
        print(f"[OK] Rogue flagged within {first_red} envelope(s).\n")
    else:
        print("[!] Rogue not flagged in 3 envelopes. Adjust feature scaling.\n")

    print("Revoking rogue ...")
    revoke(rogue.agent_id, reason="anomaly_threshold_exceeded", verifier_url=VERIFIER)

    print("Rogue tries one more envelope after revocation:")
    v = _fire(rogue, rogue=True)
    print(f"  rogue post-revoke -> valid={v['valid']} reason={v['reason']}\n")
    assert v["valid"] is False and v["reason"] == "revoked"

    print("=== Demo complete. The rogue is dead. ===")


if __name__ == "__main__":
    main()
