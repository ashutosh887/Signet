from __future__ import annotations

import argparse
import hashlib
import os
import random
import secrets
import time

import httpx

DEFAULT_GATEWAY = "http://127.0.0.1:8001/edge/trigger"


def fake_fingerprint() -> str:
    return hashlib.sha256(os.urandom(3200)).hexdigest()


def fire(gateway: str) -> None:
    body = {
        "source": "esp32c3",
        "action_name": "voice_trigger",
        "params": {
            "fingerprint_sha256": fake_fingerprint(),
            "rms": round(random.uniform(2400, 7000), 1),
            "sample_rate": 16000,
            "nonce": secrets.token_hex(8),
        },
    }
    r = httpx.post(gateway, json=body, timeout=5.0)
    r.raise_for_status()
    out = r.json()
    print(
        f"[device] trigger fired -> envelope_id={out['envelope_id']} "
        f"valid={out['verdict']['valid']} score={out['verdict']['anomaly_score']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY)
    parser.add_argument(
        "--triggers", type=int, default=1, help="number of triggers (-1 for unbounded)"
    )
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between triggers")
    args = parser.parse_args()

    n = args.triggers
    while n != 0:
        fire(args.gateway)
        n = n - 1 if n > 0 else n
        if n != 0:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
