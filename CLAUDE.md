# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Signet — a post-quantum cryptographic identity layer for AI agents. Pitch is *Auth0 for AI agents, born quantum-safe*. The full PRD is the source of truth for product scope; treat it as the spec. When the PRD and conversation conflict, ask before deviating.

The hackathon submission is **Phase 0 only**. Sections 9.2–9.6 of the PRD (Phases 1–5) are roadmap, not build targets. Do not scaffold Phase 1+ features unless explicitly asked.

## Phase 0 scope (the only thing that ships in the hackathon window)

Five deliverables, locked. Don't add a sixth without approval.

1. **Python SDK** — `signet.wrap(agent)`, `signet.sign`, `signet.verify`, `signet.revoke`. ML-DSA-44 via `liboqs-python`.
2. **FastAPI verifier service** — three endpoints: `/v1/envelopes/verify`, `/v1/envelopes/submit`, `/v1/agents/{id}/revoke`. SQLite envelope log, in-memory revocation registry.
3. **Quantum anomaly detector** — PennyLane, 6-qubit ZZ feature map, SVM. PCA-reduce 32-dim feature vector to 6-dim before encoding. Fallback to classical RBF SVM if quantum kernel doesn't separate cleanly on the synthetic demo data.
4. **Next.js dashboard** — live action stream (WebSocket), agent registry, anomaly heatmap, revoke button. Dark mode, monospace IDs.
5. **ESP32-C3 firmware** — I²S audio trigger → envelope assemble → sign → POST to verifier. On-device ML-DSA-44 via pqm4 RISC-V port if it builds; gateway-side signing as Plan B.

Explicit non-goals for Phase 0 (per PRD §9.1): multi-tenancy, HSM, TypeScript SDK, MCP/A2A integration, policy engine beyond hardcoded rules.

## Architecture (three planes)

The PRD describes one spine with three planes — keep this mental model when adding code:

- **Identity plane** — SDK + verifier + revocation registry. Cryptographic state.
- **Behavior plane** — anomaly engine + (hardcoded for Phase 0) policy checks. Semantic state.
- **Observability plane** — dashboard + audit log + (Phase 1+) webhooks. What humans see.

The atomic data unit across all three is the **action envelope** (PRD §8.3). Treat its schema as load-bearing — canonicalize with JCS (RFC 8785) over all fields except `signature`. Hybrid signature = `Ed25519_sig || ML-DSA-44_sig` concatenated; verifier requires both valid.

Planned monorepo layout (per build plan §15): `/sdk-python`, `/verifier`, `/dashboard`, `/firmware`, `/docs`.

## Cryptographic decisions (do not change without justification)

- Signing: **ML-DSA-44** (FIPS 204). 2420-byte signatures. Hybrid with Ed25519 during 2027–2033 migration window.
- KEM: **ML-KEM-768** (FIPS 203), hybrid with X25519 per RFC 9258 draft.
- Long-lived root keys: **SLH-DSA-128s** (FIPS 205) — hash-based, no lattice assumption.
- AEAD: ChaCha20-Poly1305. KDF: HKDF-SHA3-256. Hash: SHA3-256 (Merkle).
- Library: `liboqs` 0.13+ (`liboqs-python` server side, `pqm4` embedded).

If you find yourself reaching for RSA, ECDSA, or plain SHA-256 in this codebase, stop and reconsider — the entire point of Signet is that those primitives are the problem.

## Honest quantum claims (this is the line)

PRD §13 and the Q&A defense notebook (§17) are non-negotiable. Do not let docs, READMEs, or marketing copy drift toward:

- Claiming asymptotic quantum advantage in anomaly detection. The claim is **cold-start advantage** (small per-tenant samples, 2–5% AUC over RBF per Havlíček 2019 / Liu-Arunachalam-Temme 2021 / Huang 2022). Switches to classical online learners at >100K samples per agent.
- Claiming the quantum kernel needs a real QPU today. It's classically simulated on 6 qubits (where simulation is tractable). PennyLane's hardware-agnostic interface bridges to QPUs later.
- Hand-waving the 38× signature-size overhead vs ECDSA. Acknowledge it; defend it on horizon and verify-throughput grounds.

The benchmark comparing classical RBF, Isolation Forest, quantum kernel SVM, and quantum-kernel-with-classical-embeddings must be reproducible and checked into the repo.

## Demo script and the rogue-agent kill (PRD §14)

The 5-minute demo is the artifact. When building, optimize for the demo path:

1. Three legit agents firing actions, all green.
2. ESP32-C3 picks up a voice trigger, signs on-device, envelope appears on dashboard.
3. Rogue agent toggled on — anomaly heatmap goes green→yellow→red within **3 envelopes / ~6 seconds**. Tune the threshold to hit this.
4. Click revoke. Revocation propagates. Rogue's next envelope is rejected with `verdict: revoked`.
5. Show Merkle inclusion proof for one envelope.

If a change you're making breaks any step of this script, that's a release blocker — fix or revert before moving on.

## Build mantra (from the PRD)

> *Identity → Behavior → Observability. One spine. Don't side-quest.*

Three features locked. No fourth. Demo > production. No Phase 1+ creep.

## Commands

No code is checked in yet — commands below are the planned shape per PRD §10.3 and §15. Update this section as the SDK/verifier/dashboard land.

- Python SDK install (planned): `pip install -e ./sdk-python`
- Verifier dev (planned): `uvicorn verifier.main:app --reload`
- Dashboard dev (planned): `cd dashboard && pnpm dev`
- ESP32 firmware build (planned): `cd firmware && idf.py build flash monitor`
- CLI (planned surface): `signet keygen`, `signet sign`, `signet verify`, `signet revoke`, `signet audit`, `signet anomaly score`

## Pre-flight checks before the hackathon (PRD §15 "pre-hackathon")

Verify before Hour 0, in this order:

1. `liboqs-python` installs and ML-DSA-44 sign/verify works end-to-end.
2. ESP32-C3 flashes with ESP-IDF; TRWS2014B mic captures 16 kHz I²S audio cleanly.
3. `mupq/pqm4` Dilithium RISC-V port builds for `target=esp32c3`. If it doesn't, switch to gateway-side signing for the demo — do not burn hours debugging the port.
4. PennyLane quantum kernel tutorial runs end-to-end on a toy dataset.
