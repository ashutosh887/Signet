from __future__ import annotations

import argparse
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

from signet import Envelope, Identity, register, submit


load_dotenv(Path(__file__).resolve().parent / ".env")


class TriggerPayload(BaseModel):
    agent_id: str | None = None
    source: str = "esp32c3"
    action_name: str = "voice_trigger"
    params: dict[str, Any] = {}


VERIFIER_URL = os.environ.get("SIGNET_VERIFIER", "http://127.0.0.1:8000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    identity = Identity.generate(principal_id="prn_edge")
    register(identity, verifier_url=VERIFIER_URL)
    app.state.identity = identity
    print(f"[edge-gateway] device agent_id = {identity.agent_id}")
    yield


app = FastAPI(title="Signet Edge Gateway", version="0.0.1", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "device_agent_id": app.state.identity.agent_id}


@app.post("/edge/trigger")
def edge_trigger(payload: TriggerPayload) -> dict[str, Any]:
    identity: Identity = app.state.identity
    envelope = Envelope(
        agent_id=identity.agent_id,
        principal_id=identity.principal_id,
        action={
            "type": "tool_call",
            "name": payload.action_name,
            "params": {**payload.params, "source": payload.source},
        },
    )
    envelope.sign(identity)
    verdict = submit(envelope, verifier_url=VERIFIER_URL)
    return {
        "device_agent_id": identity.agent_id,
        "envelope_id": envelope.envelope_id,
        "verdict": verdict,
    }


def main() -> None:
    global VERIFIER_URL
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=int(os.environ.get("SIGNET_GATEWAY_PORT", 8001)), type=int)
    parser.add_argument("--verifier", default=VERIFIER_URL)
    args = parser.parse_args()

    VERIFIER_URL = args.verifier
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
