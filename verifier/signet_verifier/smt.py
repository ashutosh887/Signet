"""Sparse Merkle Tree of revoked agent IDs (RFC-DRAFT §6 Phase 1).

Keys are SHA3-256(agent_id) — 256-bit, treated as a path from root to leaf
(MSB first). The tree is implicitly of depth 256 with every absent key
hashing to a per-level empty hash.

Proofs are 256 sibling hashes. Verifier reconstructs the root by climbing
from leaf to root, using the supplied sibling at each level. A proof
verifies that:
  - leaf == H_leaf(present_marker)  → key IS revoked (inclusion)
  - leaf == EMPTY_LEAF               → key is NOT revoked (non-membership)

Both forms use the same proof structure; the leaf hash differs.

Implementation note: we don't store the full 2^256 tree. We only store the
set of present (revoked) keys, then compute the root and proofs lazily.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache

DEPTH = 256
PRESENT = b"\x01"           # marker stored at every revoked-key leaf
EMPTY_LEAF = hashlib.sha3_256(b"signet-smt-empty-leaf").digest()


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def key_path(agent_id: str) -> bytes:
    """256-bit path derived from the agent_id (big-endian MSB-first traversal)."""
    return _h(b"signet-smt-key|", agent_id.encode())


def present_leaf() -> bytes:
    return _h(b"signet-smt-leaf|", PRESENT)


@lru_cache(maxsize=DEPTH + 1)
def _empty_subtree_root(level: int) -> bytes:
    """Root of an all-empty subtree of the given level. level=0 is a leaf."""
    if level == 0:
        return EMPTY_LEAF
    sub = _empty_subtree_root(level - 1)
    return _h(b"signet-smt-node|", sub, sub)


def _bit(path: bytes, level_from_top: int) -> int:
    byte = path[level_from_top // 8]
    return (byte >> (7 - (level_from_top % 8))) & 1


def _build(keys: list[bytes], level_from_top: int) -> bytes:
    """Compute the subtree root over a sorted list of keys at this level.

    Each key in `keys` is the full 256-bit path; at the current level we
    split them by the next bit and recurse. Returns the subtree root.
    """
    if not keys:
        return _empty_subtree_root(DEPTH - level_from_top)
    if level_from_top == DEPTH:
        # We're at a leaf — at most one key terminates here.
        return present_leaf()
    left: list[bytes] = []
    right: list[bytes] = []
    for k in keys:
        if _bit(k, level_from_top) == 0:
            left.append(k)
        else:
            right.append(k)
    return _h(
        b"signet-smt-node|",
        _build(left, level_from_top + 1),
        _build(right, level_from_top + 1),
    )


def compute_root(revoked_agent_ids: list[str]) -> str:
    """Root of the SMT containing exactly the given revoked agent IDs."""
    paths = sorted(key_path(a) for a in revoked_agent_ids)
    return _build(paths, 0).hex()


def _siblings_for(target: bytes, others: list[bytes], level_from_top: int) -> list[str]:
    if level_from_top == DEPTH:
        return []
    bit = _bit(target, level_from_top)
    same_side: list[bytes] = []
    other_side: list[bytes] = []
    for k in others:
        if k == target:
            continue
        if _bit(k, level_from_top) == bit:
            same_side.append(k)
        else:
            other_side.append(k)
    sibling_root = _build(other_side, level_from_top + 1).hex()
    return [sibling_root] + _siblings_for(target, same_side, level_from_top + 1)


def proof(revoked_agent_ids: list[str], target_agent_id: str) -> dict[str, object]:
    paths = [key_path(a) for a in revoked_agent_ids]
    target = key_path(target_agent_id)
    is_member = target in paths
    siblings = _siblings_for(target, paths, 0)
    return {
        "agent_id": target_agent_id,
        "algorithm": "sha3-256",
        "depth": DEPTH,
        "key_path_hex": target.hex(),
        "leaf_hash_hex": (present_leaf() if is_member else EMPTY_LEAF).hex(),
        "siblings_hex": siblings,
        "revoked": is_member,
    }


def verify_proof(proof_dict: dict[str, object], expected_root_hex: str) -> bool:
    target = bytes.fromhex(str(proof_dict["key_path_hex"]))
    cur = bytes.fromhex(str(proof_dict["leaf_hash_hex"]))
    siblings = [bytes.fromhex(s) for s in proof_dict["siblings_hex"]]  # type: ignore[arg-type]
    if len(siblings) != DEPTH:
        return False
    for level_from_top in range(DEPTH - 1, -1, -1):
        sib = siblings[level_from_top]
        if _bit(target, level_from_top) == 0:
            cur = _h(b"signet-smt-node|", cur, sib)
        else:
            cur = _h(b"signet-smt-node|", sib, cur)
    return cur.hex() == expected_root_hex
