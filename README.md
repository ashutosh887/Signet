# Signet

**Post-quantum cryptographic identity for AI agents.**
Auth0 for the agent economy — born quantum-safe.

[![Signature](https://img.shields.io/badge/signature-ML--DSA--44%20·%20FIPS%20204-22d3ee)]()
[![KEM](https://img.shields.io/badge/KEM-ML--KEM--768%20·%20FIPS%20203-22d3ee)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-zinc)](LICENSE)

Every JWT, OAuth bearer token, and X.509 certificate that authenticates an AI
agent today is signed with RSA or ECDSA — both broken by Shor. Signet gives
each agent a NIST-finalized post-quantum identity, signs every action it takes
into a tamper-evident envelope, scores behavioural drift with a quantum-kernel
anomaly detector, and propagates revocation across the fleet in under a
second.

## What's in the box

| Component | What it does |
| --- | --- |
| `sdk-python/` | `signet.Identity`, `Envelope`, `wrap`, `delegate`, `register`, `verify`, `submit`, `revoke` |
| `verifier/` | FastAPI service — identity registry, ML-DSA-44 verification, SQLite log, WebSocket live stream, anomaly scorer |
| `dashboard/` | Next.js 16 + Tailwind UI: live action stream, agent registry, anomaly heatmap, one-click revoke |
| `firmware/` | ESP32-C3 reference firmware (I²S audio trigger → edge gateway → ML-DSA-44 sign → verifier) |
| `scripts/` | `demo_rogue.py`, `edge_gateway.py`, `simulate_edge_device.py` |

## Quick start

Requires macOS / Linux, Python 3.11, Node 20+, `cmake`, `ninja`.

```bash
# Python
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ./sdk-python -e ./verifier
pip install pennylane scikit-learn numpy

# liboqs shared library (brew ships static-only; oqs-python needs .dylib)
git clone https://github.com/open-quantum-safe/liboqs.git --branch 0.15.0 --depth 1 /tmp/liboqs
cd /tmp/liboqs && cmake -G Ninja -S . -B build \
    -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;KEM_ml_kem_512;KEM_ml_kem_768" \
    -DCMAKE_INSTALL_PREFIX=$HOME/_oqs -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel && cmake --install build
cd -

# Verifier (anomaly detector trains on first boot, ~30–60s)
cp verifier/.env.example verifier/.env
cd verifier && PYTHONPATH=. uvicorn signet_verifier.main:app --reload
```

Dashboard, in a second terminal:

```bash
cp dashboard/.env.example dashboard/.env.local
cd dashboard && pnpm install && pnpm dev
# http://localhost:3000
```

Rogue-agent demo, in a third terminal:

```bash
source .venv/bin/activate
python scripts/demo_rogue.py
```

You will see three legit agents holding green and a rogue going red within one
envelope, then killed by a revoke call. Optional edge agent (no hardware
required):

```bash
python scripts/edge_gateway.py --port 8001
python scripts/simulate_edge_device.py --triggers 3 --interval 2
```

## The action envelope

The atomic unit. Canonicalised JSON, ML-DSA-44 signature over every field
except `signature`.

```json
{
  "envelope_version": "signet/1",
  "envelope_id": "env_…",
  "agent_id": "agt_…",
  "principal_id": "prn_…",
  "issued_at": "2026-05-23T11:43:00.123Z",
  "expires_at": "2026-05-23T11:48:00.123Z",
  "nonce": "<base64 128-bit>",
  "action": { "type": "tool_call", "name": "book_meeting", "params": {} },
  "signature": { "algorithm": "ML-DSA-44", "value": "<base64 2420-byte>" }
}
```

## Verifier API

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/identities` | Register an agent's public key |
| `POST /v1/envelopes/verify` | Verify signature + expiry + revocation |
| `POST /v1/envelopes/submit` | Verify + persist + score + broadcast |
| `POST /v1/agents/{id}/revoke` | Revoke an agent |
| `GET  /v1/agents` | List registered agents |
| `GET  /v1/audit?limit=N` | Recent envelopes |
| `POST /v1/anomaly/score` | Score an envelope against the agent's window |
| `GET  /v1/anomaly/report` | Quantum vs RBF AUC report card |
| `WS   /ws/stream` | Live envelope and revocation events |

## Honest notes on the quantum components

- **ML-DSA-44** (FIPS 204) — production NIST signature, 2420-byte signatures,
  ~0.2 ms signing on M-series Apple Silicon, ~4× faster verify than RSA-2048.
- **ML-KEM-768** (FIPS 203) — paired with X25519 for hybrid session-key
  exchange during the migration window.
- **Quantum-kernel SVM** — six qubits, ZZ feature map (Havlíček 2019). We
  claim *cold-start advantage only*: 2–5% AUC over RBF in the 50–500-envelope
  regime per Liu-Arunachalam-Temme 2021 / Huang 2022. The verifier trains an
  RBF baseline alongside the quantum model on every boot and serves whichever
  wins on a held-out validation split; the choice is exposed at
  `GET /v1/anomaly/report`. Kernel is classically simulated on 6 qubits;
  PennyLane swaps in a real QPU later. Reproducible benchmark in
  `docs/benchmark/`.

## License

Apache 2.0.
