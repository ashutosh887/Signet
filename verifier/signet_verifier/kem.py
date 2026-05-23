from __future__ import annotations

import hashlib
from dataclasses import dataclass

import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


PQ_ALGORITHM = "ML-KEM-768"
HYBRID_LABEL = "X25519+ML-KEM-768"


def _resolve_kem(preferred: str) -> str:
    enabled = set(oqs.get_enabled_kem_mechanisms())
    if preferred in enabled:
        return preferred
    for cand in (preferred, "Kyber768", "ML-KEM-768"):
        if cand in enabled:
            return cand
    raise RuntimeError(f"liboqs missing {preferred}; available: {sorted(enabled)}")


@dataclass(slots=True)
class KemKeypair:
    algorithm: str
    pq_public: bytes
    pq_secret: bytes
    classical_public: bytes
    classical_secret: bytes

    def public_bundle(self) -> bytes:
        return self.classical_public + self.pq_public


def generate() -> KemKeypair:
    name = _resolve_kem(PQ_ALGORITHM)
    with oqs.KeyEncapsulation(name) as kem:
        pq_pk = bytes(kem.generate_keypair())
        pq_sk = bytes(kem.export_secret_key())
    cl_sk = X25519PrivateKey.generate()
    cl_pk = cl_sk.public_key()
    return KemKeypair(
        algorithm=HYBRID_LABEL,
        pq_public=pq_pk,
        pq_secret=pq_sk,
        classical_public=cl_pk.public_bytes_raw(),
        classical_secret=cl_sk.private_bytes_raw(),
    )


def encapsulate(pq_public: bytes, classical_public: bytes) -> tuple[bytes, bytes, bytes]:
    # returns (pq_ciphertext, classical_ephemeral_public, shared_secret)
    name = _resolve_kem(PQ_ALGORITHM)
    with oqs.KeyEncapsulation(name) as kem:
        pq_ct, pq_ss = kem.encap_secret(pq_public)
    ephemeral = X25519PrivateKey.generate()
    cl_ss = ephemeral.exchange(X25519PublicKey.from_public_bytes(classical_public))
    shared = _combine(cl_ss, bytes(pq_ss))
    return bytes(pq_ct), ephemeral.public_key().public_bytes_raw(), shared


def decapsulate(
    pq_secret: bytes,
    pq_ciphertext: bytes,
    classical_secret: bytes,
    classical_ephemeral_public: bytes,
) -> bytes:
    name = _resolve_kem(PQ_ALGORITHM)
    with oqs.KeyEncapsulation(name, pq_secret) as kem:
        pq_ss = kem.decap_secret(pq_ciphertext)
    cl_sk = X25519PrivateKey.from_private_bytes(classical_secret)
    cl_ss = cl_sk.exchange(X25519PublicKey.from_public_bytes(classical_ephemeral_public))
    return _combine(cl_ss, bytes(pq_ss))


def _combine(classical_ss: bytes, pq_ss: bytes) -> bytes:
    h = hashlib.new("sha3_256")
    h.update(b"signet-hybrid-kem|")
    h.update(classical_ss)
    h.update(b"|")
    h.update(pq_ss)
    return h.digest()
