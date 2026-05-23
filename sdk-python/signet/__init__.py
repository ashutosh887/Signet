from .identity import Identity, verify_signature, verify_classical
from .envelope import Envelope
from .client import register, verify, submit, revoke, audit, get_agent, get_envelope
from .wrap import wrap, delegate
from .hsm import Signer, SoftwareSigner, SoftwareClassicalSigner, PKCS11Signer
from .mcp import SignetMCPMiddleware
from .root import RootIdentity, attest_agent, verify_attestation
from . import kem

__version__ = "0.3.0"
__all__ = [
    "Identity",
    "Envelope",
    "verify_signature",
    "verify_classical",
    "register",
    "verify",
    "submit",
    "revoke",
    "audit",
    "get_agent",
    "get_envelope",
    "wrap",
    "delegate",
    "Signer",
    "SoftwareSigner",
    "SoftwareClassicalSigner",
    "PKCS11Signer",
    "SignetMCPMiddleware",
    "RootIdentity",
    "attest_agent",
    "verify_attestation",
    "kem",
]
