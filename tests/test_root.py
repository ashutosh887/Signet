"""SLH-DSA-128s root key flow — generate, attest, verify."""
import oqs
import pytest

_SLH_NAMES = ("SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple")
_HAS_SLH = any(n in oqs.get_enabled_sig_mechanisms() for n in _SLH_NAMES)


pytestmark = pytest.mark.skipif(
    not _HAS_SLH,
    reason="liboqs build lacks SLH-DSA/SPHINCS+; rebuild with SIG_sphincs_sha2_128s_simple",
)


def test_root_keygen_and_attest_round_trip() -> None:
    import signet
    from signet.root import RootIdentity, attest_agent, verify_attestation

    root = RootIdentity.generate(label="ci-root")
    agent = signet.Identity.generate(principal_id="prn_ci")
    attestation = attest_agent(
        root,
        agent_id=agent.agent_id,
        principal_id=agent.principal_id,
        ml_dsa_public_key=agent.public_key,
        ed25519_public_key=agent.ed25519_public,
        not_after_iso="2026-12-31T00:00:00Z",
    )
    assert verify_attestation(attestation) is True


def test_tampered_attestation_rejected() -> None:
    import signet
    from signet.root import RootIdentity, attest_agent, verify_attestation

    root = RootIdentity.generate()
    agent = signet.Identity.generate(principal_id="prn_ci")
    att = attest_agent(
        root,
        agent_id=agent.agent_id, principal_id=agent.principal_id,
        ml_dsa_public_key=agent.public_key,
    )
    att["payload"]["principal_id"] = "prn_evil"
    assert verify_attestation(att) is False
