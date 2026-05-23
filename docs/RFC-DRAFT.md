# draft-jha-pquip-agent-identity-00

**Working name:** *Post-Quantum Identity for Autonomous Agents*

**Status:** Internet-Draft outline. Target submission: IETF 121 (Nov 2026) or
IETF 122 (Mar 2027) per PRD §9.5.

**Stream:** IETF PQUIP WG (Post-Quantum Use in Protocols).

---

## Abstract

This document specifies a post-quantum cryptographic identity layer for
autonomous AI agents. It defines (a) an agent identity model, (b) a canonical
action-envelope format with mandatory-to-implement post-quantum signature
algorithms, (c) a revocation propagation protocol, and (d) audit log
requirements suitable for compliance-grade retention. The design assumes
deployment across the 2027–2033 PQ migration window mandated by NIST CNSA 2.0,
the EU Cyber Resilience Act, and India's MeitY Task Force.

## 1. Introduction

Every authentication primitive used to identify an AI agent today (JWT
bearer tokens, OAuth 2.0, X.509 client certificates, mTLS) is signed with
RSA or ECDSA, both of which are broken by a CRQC running Shor's algorithm.
This document specifies a replacement.

## 2. Terminology

Following [RFC2119] / [RFC8174].

- **Principal** — a human or organization owning one or more agents.
- **Agent** — a deployed AI instance, addressed by `agent_id`.
- **Envelope** — the atomic signed unit of agent action. See §4.
- **Verifier** — a service that validates envelopes against registered
  identities and a revocation registry.
- **Capability** — a scoped permission delegated by a principal to an agent
  or by a parent agent to a child agent.

## 3. Identity Model

An identity is a triple `(principal_id, agent_id, public_key)`.

- `principal_id` is an ULID-style identifier prefixed `prn_`.
- `agent_id` is an ULID-style identifier prefixed `agt_`.
- `public_key` is post-quantum (mandatory: ML-DSA-44, FIPS 204).

A registration is the binding of an `agent_id` to a `public_key` at a
verifier. Registration MAY be self-asserted in Phase 0; production
deployments SHOULD be HSM- or CA-backed.

## 4. Action Envelope

### 4.1 Schema

```json
{
  "envelope_version": "signet/1",
  "envelope_id": "env_…",
  "agent_id": "agt_…",
  "principal_id": "prn_…",
  "parent_envelope_id": "env_…",       // optional, for delegation
  "delegation_chain": ["cap_…", "cap_…"], // optional
  "issued_at": "RFC3339",
  "expires_at": "RFC3339",
  "nonce": "<base64, 128 bits>",
  "action": { "type": "…", "name": "…", "params": { … } },
  "context": { "ip_hash": "…", "geo_region": "…" }, // optional
  "policy_attestations": [ … ],                    // optional
  "signature": {
    "algorithm": "ML-DSA-44",
    "hybrid_classical": "Ed25519",                 // optional
    "value": "<base64>",
    "hybrid_classical_value": "<base64>"           // optional
  }
}
```

### 4.2 Canonicalization

Implementations MUST canonicalize the envelope with **JSON Canonicalization
Scheme** [RFC8785] over all fields **except** `signature`. The signature
covers the canonical byte sequence.

### 4.3 Mandatory-to-implement signature

- **MTI**: ML-DSA-44 [FIPS204].
- **Recommended (migration window)**: Hybrid Ed25519 + ML-DSA-44, signature
  bytes = `Ed25519_sig || ML-DSA-44_sig`. Verifier MUST validate both.
- **Optional (long-lived root keys)**: SLH-DSA-128s [FIPS205].

## 5. Hybrid Signing

The verifier MUST accept hybrid signatures during the 2027–2033 migration
window. Concrete byte layout of the hybrid signature SHALL be:

```
signature.value = base64( Ed25519_sig (64 bytes) || ML-DSA-44_sig (2420 bytes) )
```

The total length is fixed (2484 bytes). The verifier MUST reject if either
component fails.

## 6. Revocation Propagation

Revocation is event-driven. A verifier publishes an `agent.revoked` event
on every revocation channel (WebSocket, webhook, gRPC stream). The
propagation SLA is 30 seconds across federated verifiers and immediate
within a single verifier instance.

Phase 1 introduces a Sparse Merkle Tree of revoked agent IDs; verifiers
serve proofs of non-membership at `GET /v1/agents/{id}/revocation-proof`.

## 7. Audit Log Requirements

A conforming verifier MUST:

1. Append every accepted envelope to a tamper-evident log.
2. Periodically anchor the Merkle root of the log to a public timestamping
   authority (Roughtime per [I-D.roughtime] is RECOMMENDED).
3. Expose proof-of-inclusion at `GET /v1/envelopes/{id}/proof`.

## 8. Behavior Attestation (informative)

This section is informative. It documents the quantum-kernel SVM anomaly
detector used as the Signet reference implementation but does not require
conforming verifiers to implement it.

## 9. Security Considerations

- HNDL is the motivating threat (§3 PRD).
- All long-lived (>1 year) keys SHOULD be SLH-DSA, not ML-DSA, due to the
  defense-in-depth argument against an unforeseen lattice break.
- Verifiers MUST maintain a replay cache covering at least `expires_at -
  issued_at` for every accepted envelope.
- Hybrid mode is REQUIRED at production migration boundaries until
  IETF-deprecated.

## 10. IANA Considerations

This document requests registration of:

- Media type `application/signet+json` for canonical envelopes.
- Algorithm identifier `ML-DSA-44` in the COSE/JOSE algorithm registry
  (already proposed for [I-D.ietf-cose-dilithium]).

## 11. Acknowledgments

The author thanks the IETF PQUIP WG, the NIST PQC standardization team,
and the open-quantum-safe project for `liboqs`.

## 12. References

### Normative

- [FIPS204] *Module-Lattice-Based Digital Signature Standard*, NIST, Aug 2024.
- [FIPS203] *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, NIST, Aug 2024.
- [FIPS205] *Stateless Hash-Based Digital Signature Standard*, NIST, Aug 2024.
- [RFC8785] *JSON Canonicalization Scheme (JCS)*, Rundgren, Jordan, 2020.
- [RFC2119] / [RFC8174] *Key words for use in RFCs to Indicate Requirement Levels*.

### Informative

- Havlíček, V. et al. (2019). *Supervised learning with quantum-enhanced
  feature spaces.* Nature 567.
- Liu, Y., Arunachalam, S., Temme, K. (2021). *A rigorous and robust quantum
  speed-up in supervised machine learning.* Nature Physics 17.
- Huang, H. et al. (2022). *Quantum advantage in learning from experiments.*
  Science 376.
- NSA CNSA 2.0 (2022).

## Appendix A. Sample envelope

See `docs/PRD.md` §8.3.

## Appendix B. Implementation status

- Open-source reference implementation: `github.com/ashutoshjha/signet`.
- Conformance test vectors: Phase 1 deliverable.
