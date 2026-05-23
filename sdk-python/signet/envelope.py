from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from secrets import token_bytes, token_hex
from typing import Any

from .identity import Identity


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _expiry_iso(minutes: int = 5) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(minutes=minutes))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


@dataclass
class Envelope:
    agent_id: str
    principal_id: str
    action: dict[str, Any]
    envelope_id: str = field(default_factory=lambda: f"env_{token_hex(12)}")
    envelope_version: str = "signet/1"
    issued_at: str = field(default_factory=_now_iso)
    expires_at: str = field(default_factory=_expiry_iso)
    nonce: str = field(default_factory=lambda: base64.b64encode(token_bytes(16)).decode())
    signature: dict[str, Any] = field(default_factory=dict)

    def to_canonical_json(self) -> bytes:
        payload = {
            "envelope_version": self.envelope_version,
            "envelope_id": self.envelope_id,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "action": self.action,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, identity: Identity, hybrid: bool = True) -> None:
        payload = self.to_canonical_json()
        sig_bytes = identity.sign(payload)
        sig: dict[str, Any] = {
            "algorithm": identity.algorithm,
            "value": base64.b64encode(sig_bytes).decode(),
        }
        if hybrid:
            classical = identity.sign_classical(payload)
            sig["hybrid_classical"] = identity.hybrid_classical
            sig["hybrid_classical_value"] = base64.b64encode(classical).decode()
        self.signature = sig

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "envelope_id": self.envelope_id,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "action": self.action,
            "signature": self.signature,
        }
