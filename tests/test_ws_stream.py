"""WebSocket stream smoke test."""
from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import httpx
import websockets

from signet import Envelope, Identity

VERIFIER_HTTP = "http://127.0.0.1:8000"
VERIFIER_WS = "ws://127.0.0.1:8000/ws/stream"


async def main() -> None:
    identity = Identity.generate(principal_id="prn_ws_test")
    httpx.post(
        f"{VERIFIER_HTTP}/v1/identities",
        json={
            "agent_id": identity.agent_id,
            "principal_id": identity.principal_id,
            "algorithm": identity.algorithm,
            "public_key_b64": base64.b64encode(identity.public_key).decode(),
        },
    ).raise_for_status()

    received: list[dict] = []

    async with websockets.connect(VERIFIER_WS) as ws:

        async def emit() -> None:
            for i in range(3):
                env = Envelope(
                    agent_id=identity.agent_id,
                    principal_id=identity.principal_id,
                    action={"type": "tool_call", "name": f"send_email", "params": {"i": i}},
                )
                env.sign(identity)
                httpx.post(
                    f"{VERIFIER_HTTP}/v1/envelopes/submit", json=env.to_dict()
                ).raise_for_status()
                await asyncio.sleep(0.05)

        async def collect() -> None:
            for _ in range(3):
                msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
                received.append(json.loads(msg))

        await asyncio.gather(emit(), collect())

    print(f"received {len(received)} stream events")
    for m in received:
        print(
            f"  {m['type']:11s} agent={m['agent_id']} "
            f"action={m['action']['name']} valid={m['verdict']['valid']}"
        )

    assert len(received) == 3
    assert all(m["type"] == "envelope" for m in received)
    assert all(m["verdict"]["valid"] for m in received)
    print("OK")


if __name__ == "__main__":
    asyncio.run(main())
