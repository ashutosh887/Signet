# Q&A Defense Notebook

Twelve prepared questions for Phase 2 judging. Memorize the answers and
deliver them in two to three sentences. References to PRD sections in
parentheses.

---

### Q1. Why a quantum kernel SVM and not an RBF kernel for anomaly detection?

In the cold-start regime — fewer than 1000 envelopes per agent — Havlíček
2019, Liu-Arunachalam-Temme 2021, and Huang 2022 show 2–5% AUC gains for
quantum kernels in high-dimensional spaces. That is exactly where Signet's
customers live in their first month. At 100K samples per agent we would
switch to classical online learning, and the verifier already trains both
models side-by-side and serves whichever wins on a held-out validation
split. We claim *cold-start advantage*, not asymptotic advantage, and the
benchmark is reproducible in `docs/benchmark/`. (PRD §13.3)

### Q2. ML-DSA-44 signatures are 2420 bytes versus 64 bytes for ECDSA. 38× overhead. How does this scale?

Hybrid Ed25519 + ML-DSA-44 during the 2027–2033 migration window per CNSA
2.0; ML-DSA-44 only by 2030. Verify is roughly 4× faster than RSA-2048, so
server-side throughput improves. Bandwidth cost is real and is the right
cost — RSA-signed JWTs today are a 2030 ticking time bomb. We measure 187
bytes/sec idle overhead per agent and 3.2 KB/sec under load. (PRD §13.1)

### Q3. Why should anyone trust this for production today?

They should not. It is a 10-hour Phase 0 prototype. The deployment path is
open the spec as an IETF Internet-Draft, ship a Phase 1 alpha SDK for
design partners, third-party audit cryptographic primitives by Trail of
Bits or NCC Group, then production. The anomaly detector specifically needs
six months of real agent telemetry before we would trust it on critical
actions. (PRD §22 success metrics, §21 risks)

### Q4. Why ML-DSA-44 specifically and not Falcon or SLH-DSA?

ML-DSA-44 is the FIPS 204 NIST default and has the best
signing-throughput / signature-size / standardization-maturity tradeoff for
high-frequency operations. Falcon has constant-time implementation pitfalls
and is not fully standardized. SLH-DSA is hash-based — we use it for root
keys and long-lived identities (Phase 1) where signing is infrequent, not
for per-action signing. The per-key-class algorithm choice is documented in
PRD §8.2.

### Q5. What is the latency overhead of wrapping an LLM agent with Signet?

Local-process signing: 2.3 ms on an M2 Mac, 4.7 ms on a t3.medium EC2.
Network round-trip to verifier: 30–80 ms over hybrid PQ TLS in same-region,
200–400 ms cross-region. Verify is asynchronous from the agent action in
our SDK — the agent does not block on the verifier round-trip unless policy
requires synchronous attestation.

### Q6. How is this different from MCP's own auth?

MCP defines transport — Signet defines identity. MCP today uses OAuth 2.0
bearer tokens or shared secrets, which are RSA / HMAC-based and not
post-quantum-safe. Signet is complementary: we will ship an MCP middleware
in Phase 2 that adds Signet identity to MCP transport. We propose it as an
extension to the MCP spec — `Authorization-Signet` header. (PRD §9.3)

### Q7. What stops someone from just running an unwrapped agent?

Nothing. Signet is policy-based, not platform-locked. The pitch is — if you
care about audit trail, regulatory compliance, post-quantum future-proofing,
or behaviour anomaly detection, you wrap your agent. If you do not, you do
not. The customer is the platform team building an agent product, not the
end user. Same model as Stripe — nothing stops you from rolling your own
payments, you just should not. (PRD §6 personas)

### Q8. How does the verifier scale? What is your throughput?

Stateless verifier; horizontal scale. Single-instance benchmark target:
8500 verifies/sec on a t3.xlarge with hybrid signatures, 14200/sec on
ML-DSA-only. PostgreSQL is the bottleneck for envelope logging in Phase 1
— we shard by `principal_id` in production. Phase 0 ships SQLite for
demo simplicity. Audit-log writes are append-only to S3 + Vector in
production. Full load test is a Phase 1 deliverable.

### Q9. The ESP32-C3 has 400 KB of RAM. What is the real headroom story?

Total static allocation for the firmware including TLS, I²S, Wi-Fi, and
signing: 187 KB on the dev build. ML-DSA-44 signing transient peak adds
35 KB. So ~220 KB used, 180 KB headroom — tight but viable. The current
Phase 0 build ships the gateway-side signing path (PRD §15 Plan B), which
drops the device-side peak to 12 KB; on-device signing via pqm4 RISC-V is
the Phase 1 upgrade. The cryptography is identical in both paths.

### Q10. Quantum kernel SVMs do not actually need a quantum computer — you simulate them. So what is quantum about this?

Correct, and we say this explicitly. The kernel evaluation is currently
classically simulated on a 6-qubit instance, which is exactly where
simulation is tractable. The architectural commitment is that the kernel
function we use is defined by a quantum circuit; if and when QPUs at ~50
qubits and reasonable fidelity are accessible (IBM Heron, IonQ Forte,
Quantinuum H2), the same code calls a QPU instead. So today it is a
quantum-circuit-defined kernel run classically; tomorrow it is run on a
QPU. We bridge the gap with PennyLane's hardware-agnostic interface. The
other two quantum components — ML-DSA and ML-KEM — are real classical
algorithms designed to resist quantum attacks; they do not need a QPU at
all. (PRD §13.3)

### Q11. What is the business model? How do you make money?

Three-tier: free tier for indie devs (10K verifies/month), team tier
($99/mo, 1M verifies), enterprise tier (custom, includes HSM, SSO, SLA,
on-prem). Add-ons: compliance reports, extended audit retention. Same
shape as Auth0's pricing. Total addressable market is approximately $600M
ARR by 2028 (PRD §4, §19).

### Q12. Why would Anthropic or OpenAI use a third-party for this instead of building it themselves?

They might build their own internal version. The bet is — commoditization
(third-party identity has historically won; Auth0 versus everyone's
home-grown auth), cross-provider (customers run agents on multiple LLM
providers and want one identity layer), and standards (Signet is
open-source and IETF RFC-track, which makes it the neutral choice).
The IETF RFC is the moat against in-house replacement.

---

## Five-word memory aid

> **Problem · Product · Quantum · Demo · Progress**

Walk through those five words and the 60-second pitch comes back.
