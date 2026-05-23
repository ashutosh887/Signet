import { generateIdentity, newEnvelope, signEnvelope, register, submit } from "../dist/index.js";

const V = "http://localhost:8767";

const id = await generateIdentity("prn_ts_interop");
await register(id, { verifierUrl: V });
const env = newEnvelope(id.agentId, id.principalId, {
  type: "tool_call",
  name: "book_meeting",
  params: { date: "2026-05-24" },
});
const signed = signEnvelope(env, id);
const verdict = await submit(signed, { verifierUrl: V });
console.log(JSON.stringify(verdict, null, 2));
if (!verdict.valid) {
  console.error("CROSS-LANGUAGE VERIFICATION FAILED");
  process.exit(1);
}
console.log("CROSS-LANG OK");
