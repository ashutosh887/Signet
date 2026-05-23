"""Sparse Merkle Tree revocation registry — proof verification."""
from signet_verifier import smt


def test_empty_tree_root_is_stable() -> None:
    r1 = smt.compute_root([])
    r2 = smt.compute_root([])
    assert r1 == r2
    assert len(r1) == 64


def test_non_membership_proof_verifies_against_empty_root() -> None:
    root = smt.compute_root([])
    proof = smt.proof([], "agt_never_revoked")
    assert proof["revoked"] is False
    assert smt.verify_proof(proof, root) is True


def test_inclusion_proof_verifies() -> None:
    revoked = ["agt_alpha", "agt_bravo", "agt_charlie"]
    root = smt.compute_root(revoked)
    for agent in revoked:
        proof = smt.proof(revoked, agent)
        assert proof["revoked"] is True
        assert smt.verify_proof(proof, root) is True


def test_non_membership_proof_against_populated_tree() -> None:
    revoked = ["agt_alpha", "agt_bravo"]
    root = smt.compute_root(revoked)
    proof = smt.proof(revoked, "agt_not_in_set")
    assert proof["revoked"] is False
    assert smt.verify_proof(proof, root) is True


def test_proof_rejected_against_wrong_root() -> None:
    revoked = ["agt_alpha"]
    proof = smt.proof(revoked, "agt_alpha")
    wrong_root = smt.compute_root(["agt_different"])
    assert smt.verify_proof(proof, wrong_root) is False


def test_tampered_proof_fails() -> None:
    revoked = ["agt_alpha", "agt_bravo"]
    root = smt.compute_root(revoked)
    proof = smt.proof(revoked, "agt_alpha")
    proof["leaf_hash_hex"] = smt.EMPTY_LEAF.hex()  # claim it's not revoked
    assert smt.verify_proof(proof, root) is False
