# Signet
## Product Requirements Document — v1.0

*The Post-Quantum Cryptographic Identity Layer for AI Agents*

**Author:** Ashutosh Jha
**Status:** Hackathon MVP scope + 6-month product roadmap
**Date:** May 23, 2026
**Repo:** `github.com/ashutoshjha/signet`
**Tagline:** *Auth0 for AI agents, born quantum-safe.*

---

## Table of Contents

1. Executive Summary
2. Vision, Mission, Positioning
3. The Problem
4. Market Opportunity & Sizing
5. Competitive Landscape
6. Target Personas
7. Product Architecture (High-Level)
8. Core Technical Specification
9. Feature Catalogue (by Phase)
10. SDK & API Design
11. Data Model
12. Security & Threat Model
13. Quantum Components — Defensible Justification
14. Hackathon Demo Script
15. Hour-by-Hour Build Plan
16. Slide Deck Outline
17. Q&A Defense Notebook
18. Go-to-Market Strategy
19. Pricing & Business Model
20. Compliance & Governance
21. Risks & Mitigations
22. Success Metrics
23. Career & Resume Positioning
24. Open Questions
25. Appendices — RFC outline, glossary, references

---

## 1. Executive Summary

Signet is a developer-grade infrastructure layer that gives every AI agent a NIST-standard post-quantum cryptographic identity. It ships as a Python and TypeScript SDK, a verifier service, a quantum-machine-learning anomaly detector for behavior drift, and a dashboard for observability and revocation. Hardware demo on an Espressif ESP32-C3 running ML-DSA-44 signing on-device.

The thesis is that the AI agent economy of 2026–2030 — Anthropic Computer Use, OpenAI Operator, Google Mariner, Microsoft Copilot agents, MCP servers, A2A networks, ElatoAI's voice agents on edge hardware — is being built on top of identity primitives (JWT, OAuth 2.0, X.509, RSA, ECDSA) that all break under Shor's algorithm. NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in August 2024 specifically because the world has to migrate, and major governments (US CNSA 2.0, EU CRA, India's MeitY Feb 2026 Task Force) have converged on a 2027–2033 migration window. The agent identity layer for that window does not exist.

Signet builds it. The hackathon scope (10 hours) ships a working SDK, verifier, anomaly detector, ESP32 demo, and dashboard. The 6-month roadmap extends to MCP/A2A integration, language SDK coverage, HSM support, multi-tenant verifier, policy engine, IETF RFC draft, USENIX Security paper submission, and the YC W27 / senior-engineer interview wedge for Anthropic, OpenAI, Microsoft, Google, and Cloudflare.

---

## 2. Vision, Mission, Positioning

**Vision.** Every AI agent in the world has a cryptographic identity that survives the quantum era.

**Mission.** Ship the developer infrastructure — SDK, verifier, anomaly detection, edge primitives — that makes post-quantum signed agent actions as easy as `signet.wrap(agent)`.

**Positioning statement.** *Auth0 for AI agents, born quantum-safe.* Stripe-grade developer experience, NIST-grade cryptography.

**Product north star metric.** Number of verifier-signed agent actions per day across all design partners. Year-1 goal: 1M/day. Year-2: 1B/day.

**Why now.** Three trends converged in 2024–2026:
- The AI agent stack standardized (MCP shipped Nov 2024; A2A protocol followed; Operator/Mariner/Computer Use all GA by mid-2025).
- NIST finalized post-quantum standards (Aug 2024) and major platforms (Apple iMessage PQ3, Signal PQXDH, Cloudflare hybrid Kyber TLS, AWS KMS post-quantum hybrid) shipped production PQC.
- Major governments mandated migration windows (CNSA 2.0 in the US, CRA in the EU, MeitY Task Force in India — Feb 2026). Critical infrastructure has 2027–2033 deadlines.

The intersection — *agent identity for the post-quantum era* — has no incumbent.

---

## 3. The Problem

### 3.1 What breaks

Every AI agent that takes an action on a human's behalf needs to answer four questions cryptographically:

- **Identity.** Which agent did this?
- **Authorization.** On whose behalf, with what scope?
- **Integrity.** Was the action message tampered with in transit?
- **Provenance.** Can we replay the audit log six months from now and prove it?

Today, the answers are JWT, OAuth 2.0 access tokens, X.509 client certs, mTLS, RSA signatures, ECDSA signatures. Every one of these primitives is broken by a sufficiently large cryptographically-relevant quantum computer (CRQC) running Shor's algorithm. NIST, NSA, ENISA, India's MeitY, and the EU agree.

### 3.2 The harvest-now-decrypt-later (HNDL) problem applied to agents

A nation-state adversary or well-resourced criminal group can passively record agent traffic *today* — agent registration handshakes, signed action envelopes, OAuth flows — and decrypt them in 2030–2035 when CRQCs come online. Every action your agent takes today that is signed with RSA or ECDSA is on a 5-to-10-year ticking time bomb. Healthcare records prescribed by an AI scribe, financial trades executed by an AI fund agent, contracts signed by a procurement agent, child-care actions taken by an ElatoAI voice toy — all retroactively forgeable, retroactively decryptable, retroactively impersonable.

### 3.3 The behavior-drift problem

Identity is necessary but not sufficient. A correctly-authenticated agent can still be compromised — prompt injection, jailbroken system message, credential theft, supply-chain attack on the LLM provider. We need *behavioral* attestation in addition to *cryptographic* attestation. Today, observability tools (Datadog, Honeycomb, LangSmith) log agent actions but don't flag drift. Anomaly detection on agent behavior in low-data, high-dimensional regimes is a research-frontier problem where quantum kernel methods have published, reproducible advantages over classical RBF kernels (Havlíček et al. 2019; Liu & Huang 2021; Huang et al. 2022 Nature Communications).

### 3.4 What Signet solves

| Capability | Today's state | Signet |
|---|---|---|
| Agent identity | Ad-hoc, RSA/ECDSA-based | NIST ML-DSA-44 signed |
| Action provenance | App-layer logs | Verifier-signed Merkle log |
| Behavior anomaly | Manual review | Quantum-kernel SVM, real-time |
| Key compromise response | Manual rotation | One-call revocation, propagated |
| Quantum-safe transport | Patchy | Hybrid X25519+ML-KEM-768 |
| Edge agents | No standard | ESP32 reference + protocol |
| Multi-agent delegation | Bearer tokens | Verifiable capability chains |
| Compliance audit trail | Built per-customer | Standard signed log format |

---

## 4. Market Opportunity & Sizing

**Addressable agent population 2026–2030.** McKinsey (Jan 2025) projects 350M deployed enterprise AI agents by 2028. Anthropic's Computer Use, OpenAI Operator, Google Mariner, and Microsoft Copilot Studio have a combined developer count north of 5M. The MCP ecosystem (open-source, Anthropic-led) had ~14,000 community servers by Q1 2026.

**Comparable market.** Identity-as-a-service for humans: Okta ($14B market cap), Auth0 (Okta acquisition $6.5B, 2021), JumpCloud, Ping Identity ($2.8B PE exit 2022). Identity-as-a-service for agents is the next layer of the same stack. Stripe analog: Stripe started after PayPal owned online payments and built a developer-first reimagining; Signet starts after Okta owns human identity and builds the agent-first reimagining.

**Bottom-up sizing.** If 100M agents are deployed by 2028 and each pays $0.50/month for identity (consistent with Auth0 pricing), that's a $600M ARR opportunity. Add enterprise tier ($10K–$500K/year) on top.

**Adjacent revenue.** Compliance reports, audit log retention, HSM integrations, PQC-migration consulting for non-agent systems on the same SDK chassis.

---

## 5. Competitive Landscape

| Player | What they do | Why Signet wins |
|---|---|---|
| **Auth0 / Okta** | Human identity, OIDC, RSA/ECDSA | Built for humans, not agents; not post-quantum |
| **Hashicorp Vault** | Secrets management | Storage, not identity protocol; not PQ |
| **AWS KMS / Azure Key Vault** | Key management | Cloud-locked; opaque; not agent-shaped |
| **WorkOS** | Auth for B2B SaaS | Same as Auth0; not agent-focused |
| **Stytch** | Developer-first auth | Same as above |
| **Clerk / Supabase Auth** | Auth for indie devs | Not enterprise; not PQ; not agent |
| **MCP itself** | Agent protocol | Defines transport, not identity |
| **DID / Verifiable Credentials W3C** | Decentralized identity | Standards body, no shipping SDK; we comply with DID |
| **liboqs / PQClean** | PQC primitives library | Library, not product; we use it |
| **Cloudflare PQ TLS** | Transport-layer PQC | Transport, not application identity |
| **OpenAgents / Coinbase AgentKit** | Agent dev tools | Tools, not identity; payments-focused |

Signet is the only player at the intersection of (post-quantum) × (AI agents) × (developer SDK + verifier).

---

## 6. Target Personas

**Primary persona: The AI-agent platform engineer.**
- Builds an agent product (B2B SaaS, AI scribe, AI voice toy, automated trader, AI procurement assistant).
- Pain: needs to prove which agent did what, especially when customers ask, regulators audit, or things go wrong.
- Today's hack: home-grown JWT layer with RSA, opaque audit log, no anomaly detection.
- Decision criteria: SDK ergonomics, latency overhead, compliance story, ability to revoke.

**Secondary persona: The compliance & security officer.**
- Works at a healthcare/fintech/regulated company adopting AI agents.
- Pain: cannot deploy agents to production without an audit trail and revocation path that survives regulatory review.
- Decision criteria: SOC 2, ISO 27001, HIPAA, audit log immutability, key management story, post-quantum readiness for CNSA 2.0.

**Tertiary persona: The edge / IoT product engineer.**
- Builds AI on devices (ElatoAI toys, smart-home agents, robotics, medical IoT).
- Pain: PQC primitives don't fit on constrained hardware easily; no reference implementation for edge agents.
- Decision criteria: footprint (RAM, flash), CPU cost, battery cost, signing throughput.

**Tertiary persona: The standards / research engineer.**
- Works on MCP, A2A, IETF PQUIP WG, NIST PQC migration.
- Pain: no reference implementation of agent-PQC interop.
- Signet's role: open-source reference + RFC submission.

---

## 7. Product Architecture (High-Level)

See `ARCHITECTURE.md` for the Mermaid diagram.

Three planes:

- **Identity plane** (SDK + verifier + revocation registry) — cryptographic state of the world.
- **Behavior plane** (anomaly engine + policy engine) — semantic state of the world.
- **Observability plane** (dashboard + audit log + webhooks) — what humans see.

---

## 8. Core Technical Specification

### 8.1 Identity Model

Every entity in the system has a cryptographic identity bound to a public key:

- **Principal** — a human or organization that owns agents (e.g., a developer, an enterprise tenant).
- **Agent** — a specific deployed instance (e.g., `crewai-procurement-bot-v3`, `elato-toy-device-#34122`).
- **Capability** — a scoped permission ("can call API X with payload schema Y", "can spend up to $Z in a TTL window").
- **Delegation** — a capability transferred from parent to child agent with cryptographic chain.
- **Audit Record** — an immutable, signed envelope of an action that happened.

Identity is a triple: `(principal_id, agent_id, public_key_material)`. Public-key material is post-quantum:

- Signing keys: ML-DSA-44 (FIPS 204), 1312-byte public, 2528-byte private, 2420-byte signature.
- KEM keys: ML-KEM-768 (FIPS 203), 1184-byte public, 2400-byte private.
- Hybrid mode (migration window): paired with Ed25519 + X25519.
- Optional: SLH-DSA (FIPS 205) for long-lived identities (hash-based, no lattice assumption).
- Optional: Falcon-512 (FIPS 206 draft) for size-constrained deployments.

### 8.2 Cryptographic Primitives

| Primitive | Algorithm | Standard | Use |
|---|---|---|---|
| KEM | ML-KEM-768 | FIPS 203 | Session key exchange |
| Hybrid KEM | X25519 + ML-KEM-768 | RFC 9258 draft | Migration window |
| Signature | ML-DSA-44 | FIPS 204 | Agent action signing |
| Hybrid signature | Ed25519 + ML-DSA-44 | CNSA 2.0 hybrid | Migration window |
| Long-term signature | SLH-DSA-128s | FIPS 205 | Root keys, low-rotation |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | Symmetric encryption |
| KDF | HKDF-SHA3-256 | RFC 5869 | Key derivation |
| Hash | SHA3-256 | FIPS 202 | Merkle log nodes |
| TRNG | OS getrandom + optional QRNG | NIST SP 800-90B | Key generation |

Implementation library: `liboqs` 0.13+ via `liboqs-python` (server side), `pqm4` (embedded), `pqcrypto` Rust crate (alt server).

### 8.3 Action Envelope Format

The atomic unit of work in Signet. JSON serialization (also wire-efficient CBOR/MessagePack supported).

```json
{
  "envelope_version": "signet/1",
  "envelope_id": "env_01HXYZABCDEF...",
  "agent_id": "agt_01HYABCDEF...",
  "principal_id": "prn_01HZABCDEF...",
  "parent_envelope_id": "env_01HX...",
  "delegation_chain": ["cap_01HX...", "cap_01HY..."],
  "issued_at": "2026-05-23T11:43:00.123Z",
  "expires_at": "2026-05-23T11:48:00.123Z",
  "nonce": "base64-128-bit-random",
  "action": {
    "type": "tool_call",
    "name": "book_meeting",
    "params": {"date": "2026-05-24", "attendees": ["x@y.com"]},
    "params_hash": "sha3-256:..."
  },
  "context": {
    "ip_hash": "sha3-256:...",
    "user_agent_hash": "sha3-256:...",
    "geo_region": "ap-south-1",
    "device_fingerprint": "..."
  },
  "policy_attestations": [
    {"policy_id": "pol_max_spend", "result": "allowed", "evidence": "..."}
  ],
  "signature": {
    "algorithm": "ML-DSA-44",
    "hybrid_classical": "Ed25519",
    "value": "base64-2420-bytes",
    "hybrid_classical_value": "base64-64-bytes",
    "signed_payload_hash": "sha3-256:..."
  }
}
```

Canonicalization for signing: JCS (RFC 8785) over all fields except `signature`. Hybrid signature mode: concatenate (Ed25519_sig || ML-DSA-44_sig) — verifier requires both valid.

### 8.4 Verifier Service

Stateless HTTP/gRPC service. One responsibility per endpoint:

- `POST /v1/envelopes/verify` — verify signature, check expiry, check revocation, return decision.
- `POST /v1/envelopes/submit` — verify + log to Merkle journal + emit webhook.
- `GET /v1/agents/{id}` — fetch agent metadata + public key.
- `POST /v1/agents/{id}/revoke` — revocation registry update; propagates to all subscribers within 30 seconds.
- `GET /v1/audit/{principal_id}` — paginated audit log with proof-of-inclusion against Merkle root.
- `GET /v1/policies/{principal_id}` — list active policies.
- `POST /v1/anomaly/score` — return anomaly score for an envelope (sync mode) or stream (async).

Storage: PostgreSQL for agent/principal metadata; append-only log for envelopes (Vector + S3 in prod, SQLite in dev); Redis for revocation cache and rate limiting.

### 8.5 Quantum Anomaly Detector

Inputs: stream of recent envelopes per agent (sliding window of N=50).
Features (per agent, per window):
- Action type histogram (categorical → one-hot top-K).
- Inter-arrival time distribution (mean, var, p95).
- Parameter cardinality (how many unique destinations/values/etc.).
- Capability usage diversity (Shannon entropy over delegation chain ids).
- Time-of-day fingerprint (24-dim circular embedding).
- Geographic dispersion.
- Tool-call success/error ratio.

Total: ~32-dim feature vector per window.

Model: **Quantum kernel SVM** using a 6-qubit ZZ feature map (Havlíček 2019), trained via PennyLane + scikit-learn. Reduce 32-dim feature vector to 6-dim via PCA before encoding.

Why quantum kernel here, defensibly:
- Small training set (cold-start regime: tens to hundreds of agents per tenant).
- High-dimensional input, low effective rank (PCA reduction loses information).
- ZZ feature map produces kernel matrices that are conjectured hard to simulate classically beyond ~50 qubits (Liu, Arunachalam, Temme 2021 — *Nature Physics*).
- Published empirical AUC gains 2–5% over RBF in this regime (Schuld 2024 review, Huang et al. 2022 *Nature Communications*).

Fallback: classical RBF kernel SVM. At >100K samples per agent (mature production regime), switch to classical online learner (Vowpal Wabbit, river). The quantum kernel is the cold-start advantage, not the asymptotic advantage. **Be honest about this in Q&A.**

### 8.6 Edge Agent Protocol

For constrained devices (Cortex-M class, RISC-V class, ESP32 family):

- ESP32-C3 (RISC-V, 400KB RAM, 4MB flash) is the reference target.
- Use pqm4 / pqm4-rv32 ports for Kyber-512 (footprint-optimized) and ML-DSA-44 (signing only; key gen done off-device).
- Provisioning: device gets keypair burned into eFuse/NVS during manufacturing. Production: HSM-backed CA signs device certs.
- Boot: hybrid X25519+ML-KEM-512 handshake to verifier. Session key derived via HKDF.
- Action: feature extraction on-device, envelope assembled with on-device ML-DSA-44 signature, transmitted over session.
- Update: signed firmware updates (SLH-DSA root-of-trust) over the same channel.
- Battery profile: signing ~150ms on ESP32-C3 @ 160MHz. Aim for 1Hz signing rate sustained.

The hackathon demo prop is the C3 + TRWS2014B mic acting as a voice-activated agent endpoint.

---

## 9. Feature Catalogue (by Phase)

### 9.1 Phase 0 — Hackathon MVP

- Python SDK: `signet.wrap(agent)`, `signet.verify(envelope)`, `signet.revoke(agent_id)`.
- ML-DSA-44 sign/verify via liboqs-python.
- FastAPI verifier service.
- SQLite envelope log + revocation registry.
- Quantum kernel SVM anomaly detector (PennyLane, 6-qubit ZZ map).
- Next.js dashboard.
- ESP32-C3 reference firmware.
- Rogue-agent demo script.
- README.md + Mermaid architecture.
- Five-slide PPT.

Non-goals: multi-tenancy, HSM, TypeScript SDK, MCP/A2A integration, policy engine beyond hardcoded rules.

### 9.2–9.6 Phases 1–5

See PRD source for Phase 1 (hardening), Phase 2 (integrations), Phase 3 (enterprise), Phase 4 (research & standards), Phase 5 (long-term). These are roadmap, not Phase 0 build targets.

---

## 10. SDK & API Design

### 10.1 Python SDK

```python
import signet

identity = signet.Identity.generate(principal_id="prn_acme_co", algorithm="ML-DSA-44")
signet.register(identity)

@signet.wrap(identity=identity, capabilities=["book_meeting"])
def my_agent(query: str) -> dict:
    return {"type": "tool_call", "name": "book_meeting", "params": {"date": "2026-05-24"}}

result = my_agent("schedule a coffee chat")

envelope = signet.Envelope(
    agent_id=identity.agent_id,
    principal_id=identity.principal_id,
    action={"type": "tool_call", "name": "book_meeting", "params": {}},
)
envelope.sign(identity)
verdict = signet.verify(envelope)

signet.revoke(identity.agent_id, reason="suspected_compromise")
```

### 10.3 CLI

```bash
signet keygen --algo ml-dsa-44 --out ./agent.key
signet sign --key ./agent.key --action '{"type":"tool_call","name":"x"}'
signet verify --envelope ./env.json
signet revoke <agent_id> --reason compromise
signet audit --since 2026-05-01
signet anomaly score --envelope ./env.json
```

---

## 13. Quantum Components — Defensible Justification

Three quantum components, three honest defenses.

### 13.1 Post-quantum signing (ML-DSA-44)
NIST FIPS 204. Replaces ECDSA/RSA. 2420-byte signature, 4× faster verify than RSA-2048. The right cost for a 5–10-year-horizon problem.

### 13.2 Post-quantum KEM (ML-KEM-768)
NIST FIPS 203. Hybrid X25519+ML-KEM-768 for defense-in-depth during migration.

### 13.3 Quantum kernel SVM for anomaly detection

Six qubits, ZZ feature map (Havlíček 2019), Pauli-Z expectation kernels.

**Honest claim:** cold-start advantage only. In the regime of 50–500 envelopes per agent (first month of a new tenant), quantum kernels show 2–5% AUC over RBF per Havlíček 2019 / Liu-Arunachalam-Temme 2021 / Huang 2022. At >100K samples per tenant, we switch to classical online learners.

**What we do NOT claim:** asymptotic quantum advantage, need for a real QPU today (we simulate on 6 qubits, where simulation is tractable), or that quantum is required for the demo to work — classical RBF is the documented fallback.

Reproducible benchmark in `docs/benchmark/`.

---

## 14. Hackathon Demo Script (5 minutes)

1. **0:00 — 0:30** Hook. 25-second pitch.
2. **0:30 — 1:15** Dashboard: 3 legit agents firing actions, all green.
3. **1:15 — 2:00** ESP32-C3 voice trigger → on-device sign → envelope on dashboard.
4. **2:00 — 3:30** Rogue agent toggled on. Anomaly heatmap goes green → yellow → red in 3 envelopes / ~6 seconds. Click revoke. Next envelope rejected with `verdict: revoked`.
5. **3:30 — 4:15** Merkle inclusion proof for one envelope.
6. **4:15 — 5:00** Closing: why this matters; roadmap.
7. **5:00 — 7:00** Q&A — see §17 of full PRD.

---

## 17. Q&A Defense Notebook

12 rehearsed Q&As. Highlights:

- **Q1 quantum kernel vs RBF:** cold-start advantage only; reproducible bench in repo.
- **Q2 38× sig-size overhead:** hybrid during migration; verify is 4× faster than RSA-2048.
- **Q3 production trust:** this is a 10-hour prototype; deployment path requires Trail of Bits / NCC audit.
- **Q10 quantum-on-simulator:** correct — kernel circuit run classically on 6 qubits; PennyLane bridges to QPUs later.

Full Q&A in the PRD source for the live event.

---

## 25. Appendices

### Appendix B — Glossary

- **CRQC** — Cryptographically Relevant Quantum Computer.
- **HNDL** — Harvest-Now-Decrypt-Later.
- **ML-DSA** — Module-Lattice-based Digital Signature Algorithm (FIPS 204).
- **ML-KEM** — Module-Lattice-based Key Encapsulation Mechanism (FIPS 203).
- **SLH-DSA** — Stateless Hash-Based Digital Signature Algorithm (FIPS 205).
- **MCP** — Model Context Protocol (Anthropic, Nov 2024).
- **A2A** — Agent-to-Agent protocol.
- **Envelope** — Signet's atomic signed unit of agent action.

### Appendix C — References

- Havlíček et al. (2019). *Supervised learning with quantum-enhanced feature spaces.* Nature 567.
- Liu, Arunachalam, Temme (2021). *A rigorous and robust quantum speed-up in supervised machine learning.* Nature Physics 17.
- Huang et al. (2022). *Quantum advantage in learning from experiments.* Science 376.
- NIST FIPS 203 / 204 / 205 (2024).
- NSA CNSA 2.0 (2022).
- pqm4: `github.com/mupq/pqm4`.
- liboqs: `github.com/open-quantum-safe/liboqs`.
- PennyLane: `pennylane.ai`.

---

**Build mantra:** *Identity → Behavior → Observability. One spine. Don't side-quest.*

**Last updated:** May 23, 2026.
**Owner:** Ashutosh Jha.
