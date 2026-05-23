from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv  # type: ignore
from signet import Envelope, Identity, register, submit

from llm_agent import plan_action  # type: ignore


def transcribe(audio_path: Path) -> str:
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        raise SystemExit("ELEVENLABS_API_KEY missing — populate .env or export it")
    with audio_path.open("rb") as fh:
        r = httpx.post(
            "https://api.elevenlabs.io/v1/speech-to-text",
            headers={"xi-api-key": key},
            data={"model_id": "scribe_v1"},
            files={"file": (audio_path.name, fh, "audio/wav")},
            timeout=60.0,
        )
    r.raise_for_status()
    body = r.json()
    return (body.get("text") or "").strip()


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    p = argparse.ArgumentParser()
    p.add_argument("--audio", required=True, help="Path to a WAV/MP3 file")
    p.add_argument("--provider", choices=("openai", "gemini"), default="openai")
    p.add_argument("--verifier", default=os.environ.get("SIGNET_VERIFIER_URL", "http://localhost:8000"))
    p.add_argument("--principal", default="prn_edge_demo")
    args = p.parse_args()

    audio = Path(args.audio).expanduser().resolve()
    if not audio.exists():
        raise SystemExit(f"audio not found: {audio}")

    print(f"[1/4] transcribing {audio.name} via ElevenLabs Scribe …")
    t0 = time.perf_counter()
    transcript = transcribe(audio)
    stt_ms = (time.perf_counter() - t0) * 1000
    print(f"  → {transcript!r}  ({stt_ms:.0f} ms)")
    if not transcript:
        return 1

    print(f"\n[2/4] planning with {args.provider} …")
    t0 = time.perf_counter()
    action = plan_action(transcript, args.provider)
    plan_ms = (time.perf_counter() - t0) * 1000
    print(f"  → action: {json.dumps(action)}  ({plan_ms:.0f} ms)")

    print("\n[3/4] generating identity + registering with verifier …")
    identity = Identity.generate(principal_id=args.principal)
    register(identity, verifier_url=args.verifier)
    print(f"  → agent_id: {identity.agent_id}")

    print("\n[4/4] signing envelope and submitting …")
    env = Envelope(
        agent_id=identity.agent_id, principal_id=identity.principal_id,
        action={**action, "voice_transcript": transcript},
    )
    env.sign(identity)
    verdict = submit(env, verifier_url=args.verifier)
    print(f"  → verdict: {json.dumps(verdict)}")
    if not verdict.get("valid"):
        return 1
    print("\nVoice → LLM → signed envelope ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
