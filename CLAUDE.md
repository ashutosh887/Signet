# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this repo is

Signet — a post-quantum cryptographic identity layer for AI agents. Pitch: *Auth0 for AI agents, born quantum-safe*. The PRD (`docs/PRD.md`) is the binding spec; when the PRD and conversation conflict, ask before deviating.

The hackathon shipped both Phase 0 and a slice of Phase 1+ work that the founder explicitly approved. The PRD's "non-goals for Phase 0" (multi-tenancy, HSM, TypeScript SDK, MCP/A2A integration, policy engine) are now built — they are no longer off-limits.

## What's shipped (current ground truth)

Verify against the code before recommending — file paths can rename.

**Identity plane.** ML-DSA-44 sign/verify via `liboqs-python`. Hybrid Ed25519 + ML-DSA-44 default-on; verifier requires both when an Ed25519 pubkey is registered. Canonical JSON (sort_keys, separators=(",",":")) over every field except `signature`. Replay cache (LRU 4096) keyed by `agent_id:nonce`.

**Verifier service (`verifier/signet_verifier/`).** FastAPI. SQLite with idempotent migrations. Endpoints:

- Identity: `/v1/identities`, `/v1/agents`, `/v1/agents/{id}`, `/v1/agents/{id}/revoke`
- Envelopes: `/v1/envelopes/verify`, `/v1/envelopes/submit`, `/v1/envelopes/{id}`, `/v1/envelopes/{id}/proof`
- Audit: `/v1/audit`, `/v1/audit/root`
- Anomaly: `/v1/anomaly/score`, `/v1/anomaly/report`
- Webhooks: `/v1/webhooks` (POST/GET), `/v1/webhooks/{id}` (DELETE) — HMAC-SHA256 in `X-Signet-Signature`
- Policy engine: `/v1/policies` (POST/GET), `/v1/policies/{id}` (DELETE), `/v1/policies/evaluate`
- KEM: `/v1/kem/keygen`, `/v1/kem/encapsulate`, `/v1/kem/decapsulate` — hybrid X25519 + ML-KEM-768
- Ops: `/health`, `/metrics` (Prometheus), `/ws/stream` (WebSocket)

Tenancy: every agent/envelope/webhook/policy/kem-key row carries `tenant_id`. When `SIGNET_API_KEYS` is set (JSON map `{"key":"tenant"}` or comma-separated), the middleware resolves the caller's tenant from `X-API-Key` and filters list/audit/revoke/verify endpoints to that tenant. No API-key configuration → single `default` tenant, backward-compatible.

**Python SDK (`sdk-python/signet/`).**
- `Identity.generate/sign/sign_classical/with_signer`, `verify_signature`, `verify_classical`
- `Envelope` with default-hybrid `.sign(identity, hybrid=True)`
- HTTP client: `register`, `submit`, `verify`, `revoke`, `audit`, `get_agent`, `get_envelope`
- `@wrap` decorator, `delegate()` for capability chains
- `SignetMCPMiddleware` for MCP/A2A tool dispatch
- `signet.kem` helpers (keygen/encapsulate/decapsulate)
- `Signer` protocol + `SoftwareSigner`, `SoftwareClassicalSigner`, `PKCS11Signer` stub for HSMs
- CLI (`signet` entry point): `keygen / register / sign / verify / submit / revoke / audit / agent / envelope / anomaly score / proof / policy {add,list}`

**TypeScript SDK (`sdk-ts/`).** Cross-language. `generateIdentity`, `newEnvelope`, `signEnvelope`, `verifyEnvelope`, `register`, `submit`, `verify`, `revoke`, `audit`, `inclusionProof`, `canonicalize`. ML-DSA-44 via `@noble/post-quantum`, Ed25519 via `@noble/curves`. Vitest tests + a `test/interop.mjs` script that proves TS-signed envelopes verify against the Python verifier.

**Quantum anomaly detector (`verifier/signet_verifier/anomaly.py`).** PennyLane 6-qubit ZZ feature map kernel + PCA(6) + sklearn SVM. RBF baseline trained side-by-side; served model decided on held-out AUC. `AnomalyDetector.explain()` returns the top-3 most anomalous features by z-score; surfaced in `/v1/anomaly/score` as `top_features`.

**Merkle audit log (`verifier/signet_verifier/merkle.py`).** SHA3-256 leaves (`H(0x00 || canonical_json)`), SHA3-256 node hashes (`H(0x01 || left || right)`), duplicate-last on odd levels. Inclusion proofs verifiable client-side (`verify_proof`) — see also Python tests `tests/test_merkle.py`.

**Sparse Merkle Tree revocation (`verifier/signet_verifier/smt.py`).** 256-deep tree of `SHA3-256(agent_id)` → presence-marker leaves. Same proof shape verifies both inclusion (revoked) and non-membership (not revoked); leaf hash differs. Endpoints: `GET /v1/revocations/root`, `GET /v1/agents/{id}/revocation-proof`. The boolean column remains the fast path; SMT is the federated/cross-verifier-checkable artifact.

**Dashboard (`dashboard/`).** Next.js 16, Tailwind v4, dark mode default. Live envelope stream via WebSocket, agent registry with revoke button, anomaly heatmap, AUC report card, Merkle inclusion-proof modal triggered by clicking a stream row.

**ESP32-C3 firmware (`firmware/`).** I²S audio trigger → gateway-side ML-DSA-44 signing (Plan B per PRD §15). On-device pqm4 port remains Phase 1+.

**Tests (`tests/`).** SDK round-trip, anomaly fit, `@wrap`/`delegate`, WebSocket broadcast, policy engine (5), Merkle proofs (4), KEM hybrid round-trip (2), CLI surface (4), tenancy isolation (4), webhook HMAC + tenant filter (3). All green.

**Observability.** Prometheus counters/histograms at `/metrics`. Structured JSON logging via `SIGNET_LOG_LEVEL`. Optional CORS allowlist via `SIGNET_CORS_ORIGINS`.

## Architecture (three planes)

The PRD describes one spine with three planes:

- **Identity plane** — SDK + verifier + revocation registry + KEM. Cryptographic state.
- **Behavior plane** — anomaly engine + policy engine. Semantic state.
- **Observability plane** — dashboard + audit log + webhooks. What humans see.

The atomic unit is the **action envelope** (PRD §8.3, RFC-DRAFT §4). JCS canonicalization over every field except `signature`. Hybrid signature when both keys are registered.

Monorepo layout: `/sdk-python`, `/sdk-ts`, `/verifier`, `/dashboard`, `/firmware`, `/scripts`, `/tests`, `/docs`.

## Cryptographic decisions (do not change without justification)

- Signing: **ML-DSA-44** (FIPS 204). 2420-byte signatures. Hybrid with Ed25519.
- KEM: **ML-KEM-768** (FIPS 203), hybrid with X25519. Combined via SHA3-256.
- Long-lived root keys: **SLH-DSA-SHA2-128s** (FIPS 205). Lives in `signet.root` (`RootIdentity`, `attest_agent`, `verify_attestation`). Verifier endpoint `/v1/identities/attested`. CLI: `signet root {keygen,attest}`. Liboqs name in 0.15.x is `SPHINCS+-SHA2-128s-simple`.
- AEAD: ChaCha20-Poly1305 (planned, not in critical path). KDF: HKDF-SHA3-256. Hash: SHA3-256 (Merkle).
- Library: `liboqs` 0.15.x via `liboqs-python` (server). `@noble/post-quantum` (TS).

If you reach for RSA, ECDSA, or plain SHA-256, stop. The entire point of Signet is that those primitives are the problem.

## Honest quantum claims (the line)

PRD §13 and `docs/QA.md` are non-negotiable. Do not drift toward:

- Claiming asymptotic quantum advantage in anomaly detection. The claim is **cold-start advantage** (2–5% AUC over RBF on small per-tenant samples, per Havlíček 2019 / Liu-Arunachalam-Temme 2021 / Huang 2022). Switches to classical online learners at >100K samples per agent.
- Claiming the quantum kernel needs a real QPU today. It's classically simulated on 6 qubits.
- Hand-waving the 38× signature-size overhead vs ECDSA. Acknowledge it; defend it on horizon and verify-throughput grounds.

Reproducible benchmark in `docs/benchmark/`.

## Demo script (PRD §14)

The 5-minute demo is the artifact. Optimize for this path:

1. Three legit agents firing actions, all green.
2. ESP32-C3 voice trigger → gateway signs → envelope on dashboard.
3. Rogue agent toggled on — heatmap goes green→yellow→red in 3 envelopes / ~6 s.
4. Click revoke. Rogue's next envelope rejected with `verdict: revoked`.
5. Click any green envelope on the dashboard → Merkle inclusion proof modal.

If a change breaks any step, that's a release blocker — fix or revert before moving on.

## Commands (actual, not planned)

```bash
# Python SDK
pip install -e ./sdk-python
signet keygen --principal prn_acme --out agent.key

# Verifier (uses ./verifier/signet.db unless SIGNET_DB_PATH set)
pip install -e ./verifier
uvicorn signet_verifier.main:app --reload

# TypeScript SDK
cd sdk-ts && pnpm install && pnpm build && pnpm test

# Dashboard
cd dashboard && pnpm dev

# Tests
pytest tests/ -v

# ESP32-C3 (firmware)
cd firmware && idf.py build flash monitor
```

## Pre-flight checks (PRD §15)

Verify before Hour 0, in this order:

1. `liboqs-python` installs and ML-DSA-44 sign/verify works end-to-end.
2. ESP32-C3 flashes with ESP-IDF; TRWS2014B mic captures 16 kHz I²S audio cleanly.
3. `mupq/pqm4` Dilithium RISC-V port builds for `target=esp32c3`. If not, gateway-side signing is the documented Plan B — don't burn hours.
4. PennyLane quantum kernel tutorial runs end-to-end on a toy dataset.
