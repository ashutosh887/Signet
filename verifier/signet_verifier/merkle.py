from __future__ import annotations

import hashlib
import json
from typing import Any


def leaf_hash(envelope: dict[str, Any]) -> str:
    payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(b"\x00" + payload).hexdigest()


def _node_hash(left: str, right: str) -> str:
    return hashlib.sha3_256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def compute_root(leaves: list[str]) -> str:
    if not leaves:
        return hashlib.sha3_256(b"").hexdigest()
    layer = list(leaves)
    while len(layer) > 1:
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(_node_hash(left, right))
        layer = nxt
    return layer[0]


def inclusion_proof(leaves: list[str], index: int) -> list[dict[str, str]]:
    if not 0 <= index < len(leaves):
        raise IndexError(index)
    path: list[dict[str, str]] = []
    layer = list(leaves)
    idx = index
    while len(layer) > 1:
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            if i == idx or i + 1 == idx:
                sibling = right if i == idx else left
                position = "right" if i == idx else "left"
                path.append({"position": position, "hash": sibling})
            nxt.append(_node_hash(left, right))
        idx //= 2
        layer = nxt
    return path


def verify_proof(leaf: str, proof: list[dict[str, str]], root: str) -> bool:
    cur = leaf
    for step in proof:
        if step["position"] == "right":
            cur = _node_hash(cur, step["hash"])
        else:
            cur = _node_hash(step["hash"], cur)
    return cur == root
