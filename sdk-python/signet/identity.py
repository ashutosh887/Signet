from __future__ import annotations

from dataclasses import dataclass, field
from secrets import token_hex

import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_ALGO_CANDIDATES = ("ML-DSA-44", "Dilithium2")


def _resolve_algorithm(preferred: str) -> str:
    enabled = set(oqs.get_enabled_sig_mechanisms())
    if preferred in enabled:
        return preferred
    for name in _ALGO_CANDIDATES:
        if name in enabled:
            return name
    raise RuntimeError(
        f"liboqs does not expose {preferred} or a known alias; available: {sorted(enabled)}"
    )


@dataclass
class Identity:
    principal_id: str
    agent_id: str
    public_key: bytes
    _secret_key: bytes
    ed25519_public: bytes
    _ed25519_secret: bytes
    algorithm: str = "ML-DSA-44"
    hybrid_classical: str = "Ed25519"
    _oqs_name: str = field(default="ML-DSA-44", repr=False)

    @classmethod
    def generate(cls, principal_id: str, algorithm: str = "ML-DSA-44") -> "Identity":
        oqs_name = _resolve_algorithm(algorithm)
        with oqs.Signature(oqs_name) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        ed_secret = Ed25519PrivateKey.generate()
        ed_public = ed_secret.public_key()
        return cls(
            principal_id=principal_id,
            agent_id=f"agt_{token_hex(8)}",
            public_key=bytes(public_key),
            _secret_key=bytes(secret_key),
            ed25519_public=ed_public.public_bytes_raw(),
            _ed25519_secret=ed_secret.private_bytes_raw(),
            algorithm=algorithm,
            _oqs_name=oqs_name,
        )

    def sign(self, message: bytes) -> bytes:
        signer = getattr(self, "_external_signer", None)
        if signer is not None:
            return signer.sign(message)
        with oqs.Signature(self._oqs_name, self._secret_key) as ctx:
            return bytes(ctx.sign(message))

    def sign_classical(self, message: bytes) -> bytes:
        sk = Ed25519PrivateKey.from_private_bytes(self._ed25519_secret)
        return sk.sign(message)

    def with_signer(self, signer) -> "Identity":
        """Bind an external HSM/PKCS11 signer to this identity for the
        post-quantum half. Public key must match the externally-held key.
        """
        from dataclasses import replace as _replace
        clone = _replace(self, public_key=signer.public_key, algorithm=signer.algorithm)
        object.__setattr__(clone, "_external_signer", signer)
        return clone


def verify_signature(
    public_key: bytes, message: bytes, signature: bytes, algorithm: str = "ML-DSA-44"
) -> bool:
    oqs_name = _resolve_algorithm(algorithm)
    with oqs.Signature(oqs_name) as verifier:
        return bool(verifier.verify(message, signature, public_key))


def verify_classical(ed_public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed_public).verify(signature, message)
        return True
    except Exception:
        return False
