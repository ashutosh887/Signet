# @signet/sdk — TypeScript SDK

Cross-language SDK for the Signet post-quantum identity layer. Envelopes
signed here verify against the Python verifier (same JCS canonicalisation,
same hybrid Ed25519 + ML-DSA-44 envelope schema).

## Install

```bash
pnpm install
pnpm build
```

## Usage

```ts
import { generateIdentity, newEnvelope, signEnvelope, register, submit } from "@signet/sdk";

const id = await generateIdentity("prn_acme");
await register(id, { verifierUrl: "http://localhost:8000" });

const env = newEnvelope(id.agentId, id.principalId, {
  type: "tool_call",
  name: "book_meeting",
  params: { date: "2026-05-24" },
});
const signed = signEnvelope(env, id);
const verdict = await submit(signed, { verifierUrl: "http://localhost:8000" });
console.log(verdict);
```

Set `apiKey` in client options for multi-tenant verifiers.

## Crypto

- ML-DSA-44 via `@noble/post-quantum`
- Ed25519 hybrid via `@noble/curves`
- Canonical JSON (Python-compatible) — see `src/canonical.ts`
