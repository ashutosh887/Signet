from __future__ import annotations

from typing import Protocol, runtime_checkable

import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@runtime_checkable
class Signer(Protocol):
    algorithm: str
    public_key: bytes

    def sign(self, message: bytes) -> bytes: ...


class SoftwareSigner:
    def __init__(self, algorithm: str, public_key: bytes, secret_key: bytes, oqs_name: str | None = None) -> None:
        self.algorithm = algorithm
        self.public_key = public_key
        self._secret_key = secret_key
        self._oqs_name = oqs_name or algorithm

    def sign(self, message: bytes) -> bytes:
        with oqs.Signature(self._oqs_name, self._secret_key) as signer:
            return bytes(signer.sign(message))


class SoftwareClassicalSigner:
    algorithm = "Ed25519"

    def __init__(self, secret_key: bytes) -> None:
        self._sk = Ed25519PrivateKey.from_private_bytes(secret_key)
        self.public_key = self._sk.public_key().public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)


class PKCS11Signer:
    """Stub for production HSMs (YubiHSM, AWS CloudHSM, Thales).

    The interface is intentionally identical to SoftwareSigner so the SDK
    can route signing to a real HSM without changing call sites. Wiring a
    concrete python-pkcs11 session is a deployment concern, not an SDK
    concern.
    """

    def __init__(self, *, slot: int, label: str, algorithm: str = "ML-DSA-44") -> None:
        self.slot = slot
        self.label = label
        self.algorithm = algorithm
        self.public_key = b""

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - deployment
        raise NotImplementedError(
            "PKCS11Signer is a deployment-time stub. Bind to python-pkcs11 "
            "or your HSM vendor's library to enable hardware signing."
        )
