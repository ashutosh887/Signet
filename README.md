# Signet

**Post-Quantum Cryptographic Identity for AI Agents.**
*Auth0 for the agent economy, born quantum-safe.*

[![Phase](https://img.shields.io/badge/phase-0%20%E2%80%94%20hackathon%20MVP-6366f1)]()
[![Standard](https://img.shields.io/badge/signature-ML--DSA--44%20%2F%20FIPS%20204-22d3ee)]()
[![Standard](https://img.shields.io/badge/KEM-ML--KEM--768%20%2F%20FIPS%20203-22d3ee)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-zinc)](LICENSE)

Every JWT, OAuth bearer token, and X.509 certificate that authenticates an AI
agent today is signed with RSA or ECDSA. Every one of them breaks under Shor.
The AI agent economy is being built on a 2030 ticking time bomb. **Signet is
the layer that fixes it.**

Signet gives every agent a NIST-standard post-quantum identity, signs every
action it takes into a tamper-evident envelope, scores behaviour drift with a
quantum-kernel anomaly detector, and revokes compromise in under a second
across the whole fleet.

This repository is the **Phase 0 hackathon MVP** (PRD §9.1). It ships five
deliverables:

1. **Python SDK** — `signet.Identity.generate()`, `signet.wrap(agent)`,
   `signet.verify`, `signet.revoke`, `signet.delegate`. ML-DSA-44 via
   `liboqs-python`.
2. **FastAPI verifier service** — identity registry, signature verification,
   SQLite envelope log, in-memory revocation, WebSocket live stream.
3. **Quantum-kernel anomaly detector** — PennyLane 6-qubit ZZ feature map,
   trained alongside a classical RBF baseline, auto-fallback if RBF wins.
4. **Next.js dashboard** — live action stream, agent registry, anomaly heatmap,
   one-click revoke. Dark mode, monospace IDs.
5. **ESP32-C3 reference firmware** — I²S audio trigger → fingerprint → gateway
   signs ML-DSA-44 → submits to verifier. Plan B per PRD §15.

The full product specification is in [`docs/PRD.md`](docs/PRD.md). The mantra
is *Identity → Behavior → Observability. One spine. Don't side-quest.*

---

## Why this exists

Four things have to be true for the AI agent economy to scale safely:

| Property | What today's stack does | What Signet does |
| --- | --- | --- |
| Identity | JWT / OAuth bearer (RSA, ECDSA) | NIST ML-DSA-44 keypair per agent |
| Action provenance | Application logs | Verifier-signed envelope + audit log |
| Behaviour attestation | Manual review | Quantum-kernel SVM on a sliding window |
| Compromise response | Manual rotation | One-call revocation, <1s propagation |

The cryptographic primitives we use today (RSA-2048, ECDSA-P256) are all known
to break under a sufficiently large quantum computer running Shor's algorithm.
NIST finalized **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205
(SLH-DSA)** in August 2024 specifically because the world has to migrate.
**CNSA 2.0, EU CRA, and India's MeitY Task Force (Feb 2026) have all set
migration windows ending 2027–2033.** The agent identity layer for that window
does not exist. Signet builds it.

---

## Quick start

Requires: macOS or Linux, Python 3.11, Node 20+, `cmake`, `ninja`.

```bash
# 1. Clone and create a venv
git clone https://github.com/ashutoshjha/signet.git
cd signet
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ./sdk-python -e ./verifier
pip install fastapi 'uvicorn[standard]' httpx pydantic pennylane scikit-learn numpy

# 2. liboqs (post-quantum primitives, shared library)
# Build from source — the brew formula ships static-only, which oqs-python cannot use.
git clone https://github.com/open-quantum-safe/liboqs.git --branch 0.15.0 --depth 1 /tmp/liboqs
cd /tmp/liboqs && cmake -G Ninja -S . -B build \
    -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;KEM_ml_kem_512;KEM_ml_kem_768" \
    -DCMAKE_INSTALL_PREFIX=$HOME/_oqs -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel && cmake --install build
cd -

# 3. Start the verifier (trains the anomaly detector on first boot, ~30–60s)
cd verifier && PYTHONPATH=. uvicorn signet_verifier.main:app --reload
```

In a second terminal, start the dashboard:

```bash
cd dashboard && pnpm install && pnpm dev
# open http://localhost:3000
```

In a third terminal, run the rogue-agent demo (PRD §14):

```bash
source .venv/bin/activate
python scripts/demo_rogue.py
```

You will see three legit agents staying green (`score ≈ 0.15`) and a rogue
agent getting flagged red within a single envelope (`score ≈ 0.95`), then
killed by a revocation call.

Optional: bring up the edge agent simulator (Plan B for the ESP32-C3):

```bash
python scripts/edge_gateway.py --port 8001    # in one terminal
python scripts/simulate_edge_device.py --triggers 3 --interval 2  # in another
```

---

## What's in the box

```
signet/
├── sdk-python/           Python SDK     (signet.Identity, Envelope, wrap, delegate, …)
├── verifier/             FastAPI service (sigs, registry, SQLite log, ws/stream, anomaly)
├── dashboard/            Next.js 16 + Tailwind dark UI
├── firmware/             ESP32-C3 ESP-IDF reference firmware
├── scripts/
│   ├── demo_rogue.py            PRD §14 rogue-agent kill demo
│   ├── edge_gateway.py          Plan-B gateway that signs on behalf of the device
│   └── simulate_edge_device.py  Device-less driver for the edge demo
├── tests/                Round-trip, WebSocket, anomaly, wrap smoke tests
├── docs/
│   ├── PRD.md            Full Product Requirements Document
│   ├── ARCHITECTURE.md   Mermaid system diagram
│   └── RFC-DRAFT.md      IETF Internet-Draft outline (Phase 4)
└── README.md
```

---

## The action envelope

The atomic unit of work in Signet is a **signed action envelope** (PRD §8.3).
Everything an agent does — call a tool, send an email, place a trade — is
canonicalized, signed with ML-DSA-44, sent to the verifier, scored, and logged.

```json
{
  "envelope_version": "signet/1",
  "envelope_id": "env_…",
  "agent_id": "agt_…",
  "principal_id": "prn_…",
  "issued_at": "2026-05-23T11:43:00.123Z",
  "expires_at": "2026-05-23T11:48:00.123Z",
  "nonce": "<base64-128bit>",
  "action": {
    "type": "tool_call",
    "name": "book_meeting",
    "params": {"date": "2026-05-24"}
  },
  "signature": {
    "algorithm": "ML-DSA-44",
    "value": "<base64-2420-bytes>"
  }
}
```

Canonicalization is JCS-shaped (RFC 8785-style sorted-key compact JSON).
The signature covers every field of the envelope except `signature` itself.

---

## Honest claims

Three quantum components, three honest defences (PRD §13).

**ML-DSA-44 signing.** NIST FIPS 204. Replaces ECDSA/RSA. 2420-byte signatures
(38× ECDSA-P256). Verification is ~4× faster than RSA-2048; signing latency is
**0.2 ms locally on M-series Apple Silicon** in this implementation. Hybrid
Ed25519 + ML-DSA-44 mode is Phase 1.

**ML-KEM-768 KEM.** NIST FIPS 203. Hybrid X25519 + ML-KEM-768 is the
session-key transport. The edge-agent path uses the same hybrid.

**Quantum-kernel SVM anomaly detection.** Six qubits, ZZ feature map (Havlíček
2019), Pauli-Z expectation kernel. We claim **cold-start advantage only** —
2–5% AUC over RBF in the regime of 50–500 envelopes per agent (Liu–Arunachalam–
Temme 2021; Huang 2022). We do **not** claim asymptotic quantum advantage; the
verifier trains an RBF baseline alongside the quantum model on every boot and
serves whichever wins on a held-out validation split. The choice is exposed at
`GET /v1/anomaly/report`. The kernel evaluation is classically simulated on 6
qubits; PennyLane's hardware-agnostic interface lets us swap a real QPU in
later. See `docs/benchmark/` for the reproducible bench.

---

## Verifier API

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/identities` | Register an agent's public key |
| `POST /v1/envelopes/verify` | Verify signature + expiry + revocation |
| `POST /v1/envelopes/submit` | Verify + persist + score + broadcast |
| `POST /v1/agents/{id}/revoke` | Revoke an agent |
| `GET  /v1/agents` | List registered agents |
| `GET  /v1/audit?limit=N` | Recent envelopes (paginated) |
| `POST /v1/anomaly/score` | Score an envelope against the agent's window |
| `GET  /v1/anomaly/report` | Trained-model report card (quantum vs RBF) |
| `WS   /ws/stream` | Live envelope + revocation events |

---

## The demo

Live demo path is locked at 5 minutes (PRD §14):

1. Three legit agents firing actions — all green on the dashboard.
2. ESP32-C3 picks up a voice trigger, fingerprint goes to the gateway, the
   gateway signs ML-DSA-44, the envelope appears on the dashboard.
3. Rogue agent toggled on — anomaly heatmap goes green → yellow → red within
   one envelope (well inside the PRD's 3-envelope budget).
4. Click revoke. Revocation propagates instantly. The rogue's next envelope is
   rejected with `verdict: revoked`.
5. Show the audit log + Merkle inclusion roadmap.

The whole thing is driven by `scripts/demo_rogue.py` and the dashboard.

---

## Roadmap

Phase 0 is what this repository ships. The full product roadmap is in
[`docs/PRD.md`](docs/PRD.md):

- **Phase 1 (M+1):** PyPI release, hybrid Ed25519 + ML-DSA, async SDK,
  rate-limited verifier, Postgres backend, Sparse Merkle revocation.
- **Phase 2 (M+2):** TypeScript SDK, LangChain / CrewAI / AutoGen integrations,
  MCP `Authorization-Signet` header proposal, A2A mutual auth.
- **Phase 3 (M+3):** Enterprise — HSM (YubiHSM / CloudHSM), multi-tenancy,
  SOC 2 prep, HIPAA template, FROST-Dilithium threshold sigs when ready.
- **Phase 4 (M+4 to M+6):** IETF Internet-Draft, W3C `did:signet:` method,
  USENIX Security 2027 submission.
- **Phase 5 (M+6 to M+12):** zk-STARK envelope proofs, federated quantum ML,
  PQ-secured agent payments, browser + mobile SDKs, ROS 2 robotics SDK.

---

## License

Apache 2.0.

## Security

`security@signet.dev`. Disclosures should be signed against the maintainer's
public ML-DSA key (`docs/security/maintainer.pub`, Phase 1).

---

**Build mantra:** *Identity → Behavior → Observability. One spine. Don't
side-quest.*
