from signet_verifier import kem


def test_kem_hybrid_round_trip() -> None:
    pair = kem.generate()
    ct, ephem, ss_a = kem.encapsulate(pair.pq_public, pair.classical_public)
    ss_b = kem.decapsulate(pair.pq_secret, ct, pair.classical_secret, ephem)
    assert ss_a == ss_b
    assert len(ss_a) == 32


def test_kem_independent_pairs_differ() -> None:
    a = kem.generate()
    b = kem.generate()
    assert a.pq_public != b.pq_public
    assert a.classical_public != b.classical_public
    ct_a, ephem_a, ss_a = kem.encapsulate(a.pq_public, a.classical_public)
    ct_b, ephem_b, ss_b = kem.encapsulate(b.pq_public, b.classical_public)
    assert ss_a != ss_b
