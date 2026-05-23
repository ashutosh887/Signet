"""LLM agent: ask OpenAI or Gemini to plan a tool call, sign as a Signet
envelope, submit. Keys loaded from .env."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

from dotenv import load_dotenv  # type: ignore
from signet import Envelope, Identity, register, submit


TOOLS = [
    {
        "name": "book_meeting",
        "description": "Schedule a meeting on the calendar.",
        "params": {"with": "string", "date": "ISO date", "duration_min": "integer"},
    },
    {
        "name": "send_email",
        "description": "Send an email.",
        "params": {"to": "email address", "subject": "string", "body": "string"},
    },
    {
        "name": "summarize",
        "description": "Summarise a document or piece of text.",
        "params": {"source": "string", "length": "short|medium|long"},
    },
    {
        "name": "search_kb",
        "description": "Search the internal knowledge base.",
        "params": {"query": "string"},
    },
    {
        "name": "set_reminder",
        "description": "Set a reminder.",
        "params": {"when": "ISO datetime", "what": "string"},
    },
]

SYSTEM_PROMPT = (
    "You are an AI assistant that picks ONE tool call to fulfill a user request. "
    "Respond with ONLY a JSON object of the form "
    '{"name": <tool name>, "params": {...}}. No prose, no markdown, no code fences.'
    " Available tools: " + json.dumps(TOOLS)
)


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return json.loads(text[start : i + 1])
    raise ValueError(f"no JSON object in model response: {text!r}")


def call_openai(query: str) -> dict[str, Any]:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise SystemExit("OPENAI_API_KEY missing — populate .env or export it")
    r = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": query},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=30.0,
    )
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"]
    return _extract_json(text)


def call_gemini(query: str) -> dict[str, Any]:
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise SystemExit("GEMINI_API_KEY missing — populate .env or export it")
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    r = httpx.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        params={"key": key},
        headers={"content-type": "application/json"},
        json={
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": query}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        },
        timeout=30.0,
    )
    r.raise_for_status()
    text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
    return _extract_json(text)


def plan_action(query: str, provider: str) -> dict[str, Any]:
    if provider == "openai":
        body = call_openai(query)
    elif provider == "gemini":
        body = call_gemini(query)
    else:
        raise SystemExit(f"unknown provider: {provider}")
    name = body.get("name") or body.get("tool") or "noop"
    params = body.get("params") or body.get("arguments") or {}
    return {"type": "tool_call", "name": name, "params": params, "planner": provider}


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")

    p = argparse.ArgumentParser()
    p.add_argument("--provider", choices=("openai", "gemini"), default="openai")
    p.add_argument("--query", required=True, help="Natural-language instruction for the agent")
    p.add_argument("--verifier", default=os.environ.get("SIGNET_VERIFIER_URL", "http://localhost:8000"))
    p.add_argument("--principal", default="prn_demo")
    p.add_argument("--no-register", action="store_true",
                   help="Skip registration (e.g. when the identity is already known)")
    args = p.parse_args()

    print(f"[planner={args.provider}] {args.query!r}")
    t0 = time.perf_counter()
    action = plan_action(args.query, args.provider)
    plan_ms = (time.perf_counter() - t0) * 1000
    print(f"  → action: {json.dumps(action, indent=2)}")
    print(f"  plan latency: {plan_ms:.0f} ms")

    identity = Identity.generate(principal_id=args.principal)
    if not args.no_register:
        register(identity, verifier_url=args.verifier)

    env = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action=action,
    )
    env.sign(identity)
    verdict = submit(env, verifier_url=args.verifier)
    print(f"\n  verdict: {json.dumps(verdict, indent=2)}")
    if not verdict.get("valid"):
        return 1
    print(f"\nLive {args.provider} agent action signed + verified ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
