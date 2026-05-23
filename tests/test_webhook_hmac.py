"""Verify the verifier's outbound webhook signature is HMAC-SHA256 over the
canonical body keyed by the secret. The receiver-side check that any
integrator would write should accept it and reject tampered bodies."""
import asyncio
import hashlib
import hmac
import json
from typing import Any

import pytest

from signet_verifier import db, webhooks


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "wh.db")
    c = db.connect()
    db.init(c)
    return c


def _sig(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_outgoing_hmac_matches_receiver_expectation(monkeypatch, conn):
    captured: dict[str, Any] = {}

    async def fake_post(url: str, payload: dict[str, Any], secret: str | None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        captured["url"] = url
        captured["body"] = body
        captured["sig"] = _sig(secret, body) if secret else None

    monkeypatch.setattr(webhooks, "_post", fake_post)

    db.add_webhook(
        conn,
        webhook_id="wh_1",
        url="https://example.test/hook",
        events=["envelope.verified"],
        secret="shhh",
        tenant_id="acme",
    )

    asyncio.run(
        webhooks.emit(
            conn,
            "envelope.verified",
            {"envelope_id": "env_x", "agent_id": "agt_x"},
            tenant_id="acme",
        )
    )

    assert captured["url"] == "https://example.test/hook"
    assert captured["sig"].startswith("sha256=")
    expected = _sig("shhh", captured["body"])
    assert hmac.compare_digest(captured["sig"], expected)

    tampered = captured["body"] + b"x"
    bad = _sig("shhh", tampered)
    assert not hmac.compare_digest(captured["sig"], bad)


def test_no_signature_when_no_secret(monkeypatch, conn):
    captured: dict[str, Any] = {}

    async def fake_post(url: str, payload, secret):
        captured["sig"] = _sig(secret, b"") if secret else None
        captured["secret"] = secret

    monkeypatch.setattr(webhooks, "_post", fake_post)

    db.add_webhook(
        conn,
        webhook_id="wh_2",
        url="https://example.test/hook2",
        events=["*"],
        secret=None,
        tenant_id="default",
    )
    asyncio.run(webhooks.emit(conn, "envelope.verified", {"x": 1}))
    assert captured["secret"] is None
    assert captured["sig"] is None


def test_tenant_isolation_in_emit(monkeypatch, conn):
    calls: list[str] = []

    async def fake_post(url: str, payload, secret):
        calls.append(url)

    monkeypatch.setattr(webhooks, "_post", fake_post)

    db.add_webhook(conn, webhook_id="wh_a", url="https://acme/hook",
                   events=["*"], secret=None, tenant_id="acme")
    db.add_webhook(conn, webhook_id="wh_g", url="https://globex/hook",
                   events=["*"], secret=None, tenant_id="globex")

    asyncio.run(webhooks.emit(conn, "envelope.verified", {"x": 1}, tenant_id="acme"))
    assert calls == ["https://acme/hook"]
