import { describe, expect, it } from "vitest";
import { generateIdentity, newEnvelope, signEnvelope, verifyEnvelope } from "../src/envelope.js";

describe("envelope round-trip", () => {
  it("sign + verify with hybrid", async () => {
    const id = await generateIdentity("prn_test");
    const env = newEnvelope(id.agentId, id.principalId, { type: "tool_call", name: "noop", params: {} });
    const signed = signEnvelope(env, id, true);
    expect(verifyEnvelope(signed, id.publicKey, id.ed25519Public)).toBe(true);
  });
  it("verify fails on tamper", async () => {
    const id = await generateIdentity("prn_test");
    const env = newEnvelope(id.agentId, id.principalId, { type: "tool_call", name: "noop", params: {} });
    const signed = signEnvelope(env, id, false);
    signed.action.name = "evil";
    expect(verifyEnvelope(signed, id.publicKey)).toBe(false);
  });
});
