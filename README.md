# Signet

**Post-quantum cryptographic identity for AI agents.**

[![Signature](https://img.shields.io/badge/signature-ML--DSA--44%20·%20FIPS%20204-22d3ee)]()
[![KEM](https://img.shields.io/badge/KEM-ML--KEM--768%20·%20FIPS%20203-22d3ee)]()
[![Status](https://img.shields.io/badge/status-Phase%200%20MVP-f59e0b)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-zinc)](LICENSE)

Signet is an identity layer for AI agents, built on NIST-finalized post-quantum
cryptography. It gives every agent a verifiable identity, signs every action
into a tamper-evident envelope, scores behavioural drift with a quantum-kernel
anomaly detector, and propagates revocation across the fleet in under a second.

The full product specification is in [`docs/PRD.md`](docs/PRD.md). This README
documents the **Phase 0** hackathon deliverable.

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Repository structure](#repository-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Verifier API](#verifier-api)
- [Action envelope](#action-envelope)
- [Cryptographic primitives](#cryptographic-primitives)
- [Anomaly detection](#anomaly-detection)
- [Demo](#demo)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

The agent economy is being built on cryptographic primitives — JWT, OAuth, RSA,
ECDSA — that are broken by Shor's algorithm. NIST finalized post-quantum
replacements (FIPS 203 / 204 / 205) in August 2024, and major governments have
mandated migration windows ending 2027–2033. The agent-identity layer for that
window does not exist. Signet builds it.

Three planes on one spine:

- **Identity plane** — SDK + verifier + revocation registry. Cryptographic
  state of the world.
- **Behaviour plane** — anomaly detector + (hardcoded for Phase 0) policy
  checks. Semantic state of the world.
- **Observability plane** — dashboard + audit log + WebSocket event stream.
  What humans see.

The atomic data unit across all three is the **action envelope**: a canonical
JSON document signed with ML-DSA-44 (FIPS 204).

---

## Features

### Python SDK (`sdk-python/`)

- `Identity.generate()` — ML-DSA-44 keypair via `liboqs-python`
- `Envelope.sign(identity)` — canonical JSON signing (sorted-keys, no
  whitespace) with a 2420-byte ML-DSA-44 signature
- `verify_signature()` — standalone signature verification
- `register(identity, verifier_url)` — agent public-key registration
- `submit(envelope, verifier_url)` — sign + ship to verifier
- `verify(envelope, verifier_url)` — remote verify without persistence
- `revoke(agent_id, verifier_url)` — propagate revocation
- `@wrap(identity, capabilities=[...])` — decorator that signs and submits
  every return value of a Python agent function
- `delegate(parent, capabilities, ttl)` — issue capability-scoped child
  identities with a signed delegation envelope

### Verifier service (`verifier/`)

- FastAPI 0.115 application
- ML-DSA-44 signature verification through `liboqs-python` (Dilithium2 alias
  supported for older liboqs builds)
- SQLite envelope log (`signet.db`, WAL mode, indexed on agent_id and
  received_at)
- Identity registry — public key, principal, algorithm, revocation timestamp
- In-DB revocation with sub-second propagation to all subscribers
- WebSocket live stream (`/ws/stream`) — broadcasts every accepted envelope and
  revocation event to the dashboard
- Quantum-kernel anomaly detector — trains on boot, scores every submission
- Expiry / nonce / replay checks
- CORS-configurable, `.env`-driven

### Quantum anomaly detector (`verifier/signet_verifier/anomaly.py`)

- 6-qubit ZZ feature map (Havlíček 2019) in **PennyLane**
- 32-dimensional behavioural feature vector → PCA(6) → quantum kernel
- SVM classifier (scikit-learn) trained on synthetic legit/rogue windows
- **Classical RBF baseline trained side-by-side**; the verifier serves
  whichever wins on a held-out validation split
- AUC report card at `GET /v1/anomaly/report`
- Falls back to RBF on PennyLane import failure or unstable kernels

### Next.js dashboard (`dashboard/`)

- Next.js 16 + Tailwind v4, dark mode, monospace identifiers
- Live action stream via WebSocket
- Agent registry with status badges (active / revoked)
- Anomaly heatmap per agent over time
- One-click revoke button
- AUC scoreboard (quantum vs RBF, served model highlighted)

### ESP32-C3 firmware (`firmware/`)

- ESP-IDF 5.3+ CMake project, target `esp32-c3-devkitm-1`
- I²S audio capture at 16 kHz mono (TRWS2014B mic)
- Energy-threshold voice trigger (200 ms hold-down)
- JSON payload + audio fingerprint POSTed to the edge gateway
- Edge gateway (`scripts/edge_gateway.py`) holds the device identity, signs
  ML-DSA-44 envelopes, and forwards to the verifier
- Plan B path per PRD §15 — on-device pqm4 signing is the Phase 1 upgrade
- `scripts/simulate_edge_device.py` reproduces the wire protocol without
  hardware for offline demos

### Demo tooling (`scripts/`)

- `demo_rogue.py` — runs three legit agents and one rogue agent, demonstrates
  flagging within 3 envelopes and revocation kill
- `edge_gateway.py` — receives ESP32 fingerprints, signs envelopes
- `simulate_edge_device.py` — replays the ESP32 protocol from a laptop

---

## Architecture

```
   ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
   │ Python agents  │    │  ESP32-C3 +    │    │  MCP / A2A     │
   │ (wrap decor.)  │    │  edge gateway  │    │  servers (P1+) │
   └───────┬────────┘    └───────┬────────┘    └───────┬────────┘
           │                     │                     │
           └──────── signed action envelopes ──────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │     Signet Verifier         │
                  │  • ML-DSA-44 verify         │
                  │  • SQLite envelope log      │
                  │  • Revocation registry      │
                  │  • Anomaly scorer ──────────┼──► PennyLane 6-qubit
                  │  • WebSocket broadcast      │     ZZ kernel SVM
                  └──────────────┬──────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │   Next.js Dashboard         │
                  │   Live stream · heatmap     │
                  │   Registry · revoke         │
                  └─────────────────────────────┘
```

Full diagram (Mermaid) in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Repository structure

```
signet/
├── sdk-python/                 Python SDK — Identity, Envelope, wrap, client
│   ├── pyproject.toml
│   └── signet/
│       ├── identity.py         ML-DSA-44 keygen + sign/verify (liboqs)
│       ├── envelope.py         Canonical JSON envelope + sign helpers
│       ├── client.py           HTTP client — register, submit, verify, revoke
│       └── wrap.py             @wrap decorator + delegate()
│
├── verifier/                   FastAPI verifier service
│   ├── pyproject.toml
│   └── signet_verifier/
│       ├── main.py             FastAPI app, endpoints, lifespan
│       ├── db.py               SQLite schema + accessors
│       ├── anomaly.py          PennyLane quantum kernel + RBF baseline
│       └── stream.py           WebSocket broadcast hub
│
├── dashboard/                  Next.js 16 + Tailwind v4 UI
│   └── src/
│       ├── app/                Pages, layout, globals.css
│       ├── components/         UI primitives
│       └── lib/api.ts          Verifier REST + WebSocket client
│
├── firmware/                   ESP32-C3 edge agent (ESP-IDF)
│   ├── CMakeLists.txt
│   ├── sdkconfig.defaults
│   └── main/main.c             I²S capture + trigger + HTTP POST
│
├── scripts/
│   ├── demo_rogue.py           Three legit + one rogue agent demo
│   ├── edge_gateway.py         Signs envelopes for ESP32 device
│   └── simulate_edge_device.py Hardware-free ESP32 protocol replay
│
├── tests/                      pytest suite
│   ├── test_roundtrip.py       SDK ↔ verifier signed round-trip
│   ├── test_anomaly.py         Quantum + RBF separation on synthetic data
│   ├── test_wrap.py            @wrap decorator semantics
│   └── test_ws_stream.py       WebSocket broadcast
│
├── docs/
│   ├── PRD.md                  Full product spec (25 sections)
│   ├── ARCHITECTURE.md         System diagram + data flow
│   ├── QA.md                   12 prepared judge questions + answers
│   ├── RFC-DRAFT.md            IETF Internet-Draft outline (Phase 4)
│   └── benchmark/              Reproducible quantum vs RBF AUC benchmark
│
├── CLAUDE.md                   Codebase guide for AI assistants
└── README.md                   This file
```

---

## Requirements

- macOS 13+ or Linux (x86_64 / aarch64)
- Python 3.11
- Node.js 20+ and pnpm
- `cmake`, `ninja` (for building liboqs)
- (Optional) ESP-IDF 5.3+ for firmware build
- (Optional) USB-serial mic (TRWS2014B or equivalent I²S mic) for the live edge
  demo

---

## Installation

### 1. Build the liboqs shared library

Homebrew ships a static-only liboqs; `oqs-python` needs the shared library.

```bash
git clone --branch 0.15.0 --depth 1 \
  https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs
cmake -G Ninja -S . -B build \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;KEM_ml_kem_512;KEM_ml_kem_768" \
  -DCMAKE_INSTALL_PREFIX=$HOME/_oqs -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
cmake --install build
export DYLD_LIBRARY_PATH=$HOME/_oqs/lib   # Linux: LD_LIBRARY_PATH
```

### 2. Install Python packages

```bash
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ./sdk-python -e ./verifier
pip install pennylane scikit-learn numpy
```

### 3. Install dashboard dependencies

```bash
cd dashboard
pnpm install
```

### 4. (Optional) ESP-IDF for firmware

```bash
cd firmware
idf.py set-target esp32c3
idf.py menuconfig   # set Wi-Fi SSID, password, gateway URL
idf.py build flash monitor
```

---

## Usage

### Start the verifier

```bash
cp verifier/.env.example verifier/.env
cd verifier
PYTHONPATH=. uvicorn signet_verifier.main:app --reload
```

The anomaly detector trains on boot (~30–60 s). Disable with
`SIGNET_SKIP_TRAIN=1` for fast iteration.

### Start the dashboard

```bash
cp dashboard/.env.example dashboard/.env.local
cd dashboard
pnpm dev   # http://localhost:3000
```

### Wrap and run an agent

```python
import signet

identity = signet.Identity.generate(principal_id="prn_acme_co")
signet.register(identity)

@signet.wrap(identity, capabilities=["book_meeting"])
def schedule(query: str) -> dict:
    return {"name": "book_meeting", "params": {"query": query}}

result = schedule("coffee with Akash Monday 4pm")
print(result["envelope_id"], result["verdict"]["anomaly_score"])
```

Every call now produces a signed envelope on the dashboard.

### Revoke an agent

```python
signet.revoke(identity.agent_id, reason="suspected_compromise")
```

Subsequent submissions return `Verdict(valid=False, reason="revoked")`.

---

## Verifier API

| Method | Endpoint                          | Purpose                                     |
| ------ | --------------------------------- | ------------------------------------------- |
| GET    | `/health`                         | Liveness check                              |
| POST   | `/v1/identities`                  | Register an agent's ML-DSA-44 public key    |
| POST   | `/v1/envelopes/verify`            | Stateless verify (no log, no broadcast)     |
| POST   | `/v1/envelopes/submit`            | Verify + log + score + broadcast            |
| POST   | `/v1/anomaly/score`               | Score an envelope against the agent window  |
| GET    | `/v1/anomaly/report`              | Quantum vs RBF AUC report card              |
| POST   | `/v1/agents/{agent_id}/revoke`    | Revoke an agent                             |
| GET    | `/v1/agents`                      | List registered agents                      |
| GET    | `/v1/audit?limit=N&agent_id=...`  | Paginated envelope log                      |
| WS     | `/ws/stream`                      | Live envelope and revocation event stream   |

Pydantic models and response schemas are auto-published at `/docs` (Swagger UI)
and `/openapi.json`.

---

## Action envelope

The atomic unit. Canonical JSON (sorted keys, no whitespace), ML-DSA-44
signature over every field except `signature`. Full schema in PRD §8.3.

```json
{
  "envelope_version": "signet/1",
  "envelope_id": "env_01HXYZABCDEF...",
  "agent_id":    "agt_01HYABCDEF...",
  "principal_id":"prn_acme_co",
  "issued_at":   "2026-05-23T11:43:00.123Z",
  "expires_at":  "2026-05-23T11:48:00.123Z",
  "nonce":       "<base64 128-bit>",
  "action": {
    "type":   "tool_call",
    "name":   "book_meeting",
    "params": { "date": "2026-05-24", "attendees": ["x@y.com"] }
  },
  "signature": {
    "algorithm": "ML-DSA-44",
    "value":     "<base64 2420-byte signature>"
  }
}
```

Hybrid Ed25519 + ML-DSA-44 dual signatures are specified for the
2027–2033 migration window; the Phase 0 implementation ships ML-DSA-44 only.

---

## Cryptographic primitives

| Primitive          | Algorithm                    | Standard      | Use                                |
| ------------------ | ---------------------------- | ------------- | ---------------------------------- |
| Signature          | ML-DSA-44                    | FIPS 204      | Agent action signing               |
| Hybrid signature   | Ed25519 + ML-DSA-44          | CNSA 2.0      | Migration window (Phase 1)         |
| KEM                | ML-KEM-768                   | FIPS 203      | Session key exchange               |
| Hybrid KEM         | X25519 + ML-KEM-768          | RFC 9258 draft| Migration window (Phase 1)         |
| Long-lived signing | SLH-DSA-128s                 | FIPS 205      | Root keys (Phase 1)                |
| AEAD               | ChaCha20-Poly1305            | RFC 8439      | Symmetric encryption (Phase 1)     |
| KDF                | HKDF-SHA3-256                | RFC 5869      | Key derivation                     |
| Hash               | SHA3-256                     | FIPS 202      | Merkle log nodes (Phase 1)         |

Implementation library: `liboqs` 0.15.x via `liboqs-python` (server) and
`pqm4` (embedded, Phase 1 upgrade for on-device signing).

---

## Anomaly detection

The verifier extracts a 32-dimensional feature vector per envelope window
(action-type histogram, inter-arrival statistics, parameter cardinality,
capability-usage entropy, time-of-day fingerprint, success/error ratio),
reduces to 6 dimensions via PCA, encodes through a 6-qubit ZZ feature map, and
classifies with an SVM.

**Honest claim.** We claim *cold-start advantage only*: 2–5% AUC over RBF in
the small-sample regime per Havlíček 2019 / Liu-Arunachalam-Temme 2021 / Huang
2022. We do not claim asymptotic quantum advantage. The verifier trains an RBF
baseline alongside the quantum model on every boot and serves whichever wins
on a held-out validation split; the choice is exposed at
`GET /v1/anomaly/report`. Reproducible benchmark in
[`docs/benchmark/`](docs/benchmark/).

The 6-qubit kernel is classically simulated. PennyLane's hardware-agnostic
interface allows the same code to call a QPU when one is available.

---

## Demo

### Rogue-agent kill (no hardware)

```bash
# terminal 1
cd verifier && PYTHONPATH=. uvicorn signet_verifier.main:app --reload

# terminal 2
cd dashboard && pnpm dev

# terminal 3
source .venv/bin/activate
python scripts/demo_rogue.py
```

Three legit agents hold green; the rogue agent crosses the anomaly threshold
within three envelopes (~6 seconds) and is revoked on click. The rogue's next
envelope returns `verdict: revoked`.

### Edge agent (no hardware)

```bash
python scripts/edge_gateway.py --port 8001
python scripts/simulate_edge_device.py --triggers 3 --interval 2
```

### Edge agent (with ESP32-C3)

Flash the firmware (see [Installation](#installation) step 4), point the
gateway URL in `menuconfig` at `http://<laptop-ip>:8001`, and speak near the
mic. Envelopes appear on the dashboard within 2 seconds.

---

## Testing

```bash
source .venv/bin/activate
pytest tests/ -v
```

| Test                  | What it covers                                            |
| --------------------- | --------------------------------------------------------- |
| `test_roundtrip.py`   | Generate identity → sign → submit → verify on the server  |
| `test_anomaly.py`     | Quantum kernel + RBF separate legit/rogue on synthetic    |
| `test_wrap.py`        | `@wrap` decorator and `delegate()` semantics              |
| `test_ws_stream.py`   | WebSocket broadcast delivers envelope and revocation      |

---

## Documentation

- [`docs/PRD.md`](docs/PRD.md) — full product requirements document (25 sections)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system diagram and data flow
- [`docs/QA.md`](docs/QA.md) — 12 prepared judge questions with answers
- [`docs/RFC-DRAFT.md`](docs/RFC-DRAFT.md) — IETF Internet-Draft outline
- [`firmware/README.md`](firmware/README.md) — ESP32-C3 firmware notes
- [`CLAUDE.md`](CLAUDE.md) — codebase guide for AI assistants

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

Built for the QuantumX Hackathon, May 23, 2026. Cites and builds on
[akdeb/ElatoAI](https://github.com/akdeb/ElatoAI) as the ESP32 voice-agent
architectural reference.
