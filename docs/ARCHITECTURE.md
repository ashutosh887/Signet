# Signet Architecture

Three planes, one spine.

```mermaid
flowchart TB
  subgraph Clients["Clients"]
    A1["LLM Agent<br/>(Claude / GPT / Gemini)"]
    A2["Edge Agent<br/>(ESP32-C3 + mic)"]
    A3["MCP Server<br/>(Phase 2)"]
  end

  subgraph SDK["Signet SDK (Python today, TS/Go/Rust later)"]
    S1["Identity.generate<br/>(ML-DSA-44)"]
    S2["Envelope.sign<br/>(JCS canonical JSON + signature)"]
    S3["wrap / delegate<br/>(capability chains)"]
  end

  subgraph GW["Edge Gateway (Phase 0 Plan B)"]
    G1["receives trigger fingerprint<br/>signs ML-DSA-44 envelope"]
  end

  subgraph Verifier["FastAPI Verifier (identity plane)"]
    V1["signature verify<br/>(liboqs ML-DSA-44)"]
    V2["agent registry<br/>+ revocation"]
    V3["SQLite envelope log<br/>(WAL, append-only)"]
    V4["WebSocket fan-out<br/>(/ws/stream)"]
  end

  subgraph QAE["Anomaly Engine (behavior plane)"]
    Q1["32-d feature extraction<br/>(action hist, params, timing)"]
    Q2["StandardScaler + PCA(6)"]
    Q3["6-qubit ZZ feature map<br/>(PennyLane)"]
    Q4["Quantum SVM (precomputed kernel)"]
    Q5["Classical RBF SVM baseline"]
    Q6["auto-select winner on validation AUC"]
  end

  subgraph Dash["Next.js Dashboard (observability plane)"]
    DA["live action stream"]
    DB["agent registry + revoke"]
    DC["anomaly heatmap"]
    DD["detector report card<br/>(q_auc vs rbf_auc)"]
  end

  A1 --> SDK
  A3 --> SDK
  A2 --> GW
  GW --> SDK
  SDK -- "signed envelopes (HTTPS)" --> Verifier
  Verifier --> QAE
  Verifier --> Dash
  QAE -- "score per envelope" --> Verifier
```

## Identity plane

- **SDK** holds the ML-DSA-44 secret key and produces canonical, signed
  envelopes. JCS-shaped canonicalisation (`json.dumps(sort_keys=True,
  separators=(",", ":"))` for Phase 0; RFC 8785-strict in Phase 1).
- **Verifier** stores the public key on registration and checks every
  submission with `oqs.Signature("ML-DSA-44").verify(payload, sig, pubkey)`.
- **Revocation** is a single boolean column in the SQLite agents table for
  Phase 0; the in-memory cache flips immediately and is broadcast on the
  WebSocket. Phase 1 swaps in a Sparse Merkle Tree with proof-of-non-membership.

## Behavior plane

- 32-d feature vector per sliding window of N=20 envelopes per agent.
- Standard-scaled, PCA-reduced to 6 dimensions, encoded into a 6-qubit ZZ
  feature map (Havlíček 2019).
- The verifier trains both a quantum-kernel SVC (precomputed kernel from
  PennyLane's `default.qubit`) and a classical RBF SVC at boot and serves
  whichever wins on a stratified held-out split.
- A cold-start guardrail (out-of-vocabulary action ratio) is OR-ed with the
  ML score so partial windows can't sneak unknown actions past the detector.

## Observability plane

- WebSocket `/ws/stream` broadcasts every accepted envelope and every
  revocation as JSON.
- Dashboard subscribes once, keeps a 80-envelope ring buffer in memory, polls
  `/v1/agents` every 5 s for revocation state.
- All identifiers (`agt_*`, `env_*`, `prn_*`) render in monospace.
- Dark mode is the only mode.

## Edge agent (Phase 0 plan B)

- ESP32-C3 firmware (`firmware/`) does I²S audio capture and a 200 ms
  RMS-energy trigger. On trigger it POSTs `{fingerprint_sha256, rms, nonce}`
  to the **edge gateway** (`scripts/edge_gateway.py`).
- The gateway holds the device's registered ML-DSA-44 identity. It signs the
  envelope on the device's behalf and submits it to the verifier.
- On-device signing (pqm4 RISC-V port) is Phase 1; we documented but did not
  attempt it in the hackathon window per PRD §15.
