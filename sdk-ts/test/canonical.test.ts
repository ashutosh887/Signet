import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/canonical.js";

describe("canonicalize", () => {
  it("sorts keys at every level", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ b: { d: 4, c: 3 }, a: 1 })).toBe('{"a":1,"b":{"c":3,"d":4}}');
  });
  it("matches Python json.dumps(sort_keys=True, separators=(',', ':'))", () => {
    const payload = {
      envelope_version: "signet/1",
      envelope_id: "env_abc",
      agent_id: "agt_x",
      principal_id: "prn_p",
      issued_at: "2026-05-23T00:00:00.000Z",
      expires_at: "2026-05-23T00:05:00.000Z",
      nonce: "n",
      action: { type: "tool_call", name: "x", params: { a: 1 } },
    };
    expect(canonicalize(payload)).toBe(
      '{"action":{"name":"x","params":{"a":1},"type":"tool_call"},'
      + '"agent_id":"agt_x","envelope_id":"env_abc","envelope_version":"signet/1",'
      + '"expires_at":"2026-05-23T00:05:00.000Z","issued_at":"2026-05-23T00:00:00.000Z",'
      + '"nonce":"n","principal_id":"prn_p"}'
    );
  });
});
