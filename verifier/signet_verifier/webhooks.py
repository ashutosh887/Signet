from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from typing import Any

import httpx

from . import db


async def _post(url: str, payload: dict[str, Any], secret: str | None) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"content-type": "application/json", "user-agent": "signet-verifier"}
    if secret:
        headers["X-Signet-Signature"] = (
            "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def emit(conn, event: str, payload: dict[str, Any]) -> None:
    targets = db.webhooks_for_event(conn, event)
    if not targets:
        return
    body = {"event": event, **payload}
    await asyncio.gather(*(_post(t["url"], body, t.get("secret")) for t in targets))
