from signet_verifier import merkle


def test_root_of_single_leaf_is_leaf() -> None:
    leaves = [merkle.leaf_hash({"envelope_id": "a"})]
    assert merkle.compute_root(leaves) == leaves[0]


def test_proof_round_trip_balanced() -> None:
    leaves = [merkle.leaf_hash({"envelope_id": f"e{i}"}) for i in range(8)]
    root = merkle.compute_root(leaves)
    for i, leaf in enumerate(leaves):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_proof(leaf, proof, root) is True


def test_proof_round_trip_odd_count_duplicates_last() -> None:
    leaves = [merkle.leaf_hash({"envelope_id": f"e{i}"}) for i in range(5)]
    root = merkle.compute_root(leaves)
    for i, leaf in enumerate(leaves):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_proof(leaf, proof, root)


def test_tampered_leaf_fails() -> None:
    leaves = [merkle.leaf_hash({"envelope_id": f"e{i}"}) for i in range(4)]
    root = merkle.compute_root(leaves)
    proof = merkle.inclusion_proof(leaves, 1)
    bad_leaf = merkle.leaf_hash({"envelope_id": "tampered"})
    assert merkle.verify_proof(bad_leaf, proof, root) is False
