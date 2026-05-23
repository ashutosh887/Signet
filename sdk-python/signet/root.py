from __future__ import annotations

import json
from dataclasses import dataclass
from secrets import token_hex

import oqs


_CANDIDATES = ("SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple")
ALGORITHM_LABEL = "SLH-DSA-SHA2-128s"


def _resolve() -> str:
    enabled = set(oqs.get_enabled_sig_mechanisms())
    for name in _CANDIDATES:
        if name in enabled:
            return name
    raise RuntimeError(
        "liboqs missing SLH-DSA / SPHINCS+. Rebuild with "
        "`-DOQS_MINIMAL_BUILD=...;SIG_sphincs_sha2_128s_simple`."
    )


@dataclass(slots=True)
class RootIdentity:
    root_id: str
    label: str
    algorithm: str
    public_key: bytes
    _secret_key: bytes
    _oqs_name: str

    @classmethod
    def generate(cls, label: str = "root") -> "RootIdentity":
        oqs_name = _resolve()
        with oqs.Signature(oqs_name) as signer:
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
        return cls(
            root_id=f"root_{token_hex(8)}",
            label=label,
            algorithm=ALGORITHM_LABEL,
            public_key=bytes(pk),
            _secret_key=bytes(sk),
            _oqs_name=oqs_name,
        )

    def sign(self, message: bytes) -> bytes:
        with oqs.Signature(self._oqs_name, self._secret_key) as signer:
            return bytes(signer.sign(message))


def attest_agent(
    root: RootIdentity,
    *,
    agent_id: str,
    principal_id: str,
    ml_dsa_public_key: bytes,
    ed25519_public_key: bytes | None = None,
    not_after_iso: str | None = None,
) -> dict:
    import base64
    payload = {
        "type": "signet/agent-attestation/v1",
        "root_id": root.root_id,
        "principal_id": principal_id,
        "agent_id": agent_id,
        "algorithm": "ML-DSA-44",
        "public_key_b64": base64.b64encode(ml_dsa_public_key).decode(),
    }
    if ed25519_public_key is not None:
        payload["hybrid_classical"] = "Ed25519"
        payload["hybrid_public_key_b64"] = base64.b64encode(ed25519_public_key).decode()
    if not_after_iso is not None:
        payload["not_after"] = not_after_iso
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = root.sign(canonical)
    return {
        "payload": payload,
        "root_algorithm": root.algorithm,
        "root_public_key_b64": base64.b64encode(root.public_key).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
    }


def verify_attestation(attestation: dict) -> bool:
    import base64
    oqs_name = _resolve()
    canonical = json.dumps(attestation["payload"], sort_keys=True, separators=(",", ":")).encode()
    sig = base64.b64decode(attestation["signature_b64"])
    pk = base64.b64decode(attestation["root_public_key_b64"])
    with oqs.Signature(oqs_name) as v:
        return bool(v.verify(canonical, sig, pk))
