import type { EnvelopeData, Identity } from "./envelope.js";

const b64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));

export type ClientOpts = {
  verifierUrl?: string;
  apiKey?: string;
};

const DEFAULT_URL = "http://localhost:8000";

async function post(url: string, body: unknown, apiKey?: string): Promise<unknown> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiKey) headers["x-api-key"] = apiKey;
  const r = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function get(url: string, apiKey?: string): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (apiKey) headers["x-api-key"] = apiKey;
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

export async function register(identity: Identity, opts: ClientOpts = {}): Promise<unknown> {
  const url = (opts.verifierUrl ?? DEFAULT_URL) + "/v1/identities";
  return post(url, {
    agent_id: identity.agentId,
    principal_id: identity.principalId,
    algorithm: identity.algorithm,
    public_key_b64: b64(identity.publicKey),
    hybrid_classical: "Ed25519",
    hybrid_public_key_b64: b64(identity.ed25519Public),
  }, opts.apiKey);
}

export async function submit(env: EnvelopeData, opts: ClientOpts = {}): Promise<unknown> {
  const url = (opts.verifierUrl ?? DEFAULT_URL) + "/v1/envelopes/submit";
  return post(url, env, opts.apiKey);
}

export async function verify(env: EnvelopeData, opts: ClientOpts = {}): Promise<unknown> {
  const url = (opts.verifierUrl ?? DEFAULT_URL) + "/v1/envelopes/verify";
  return post(url, env, opts.apiKey);
}

export async function revoke(agentId: string, reason = "manual", opts: ClientOpts = {}): Promise<unknown> {
  const base = opts.verifierUrl ?? DEFAULT_URL;
  const url = `${base}/v1/agents/${encodeURIComponent(agentId)}/revoke?reason=${encodeURIComponent(reason)}`;
  return post(url, {}, opts.apiKey);
}

export async function audit(opts: ClientOpts & { agentId?: string; limit?: number } = {}): Promise<unknown> {
  const base = opts.verifierUrl ?? DEFAULT_URL;
  const qs = new URLSearchParams();
  if (opts.agentId) qs.set("agent_id", opts.agentId);
  qs.set("limit", String(opts.limit ?? 100));
  return get(`${base}/v1/audit?${qs}`, opts.apiKey);
}

export async function inclusionProof(envelopeId: string, opts: ClientOpts = {}): Promise<unknown> {
  const base = opts.verifierUrl ?? DEFAULT_URL;
  return get(`${base}/v1/envelopes/${encodeURIComponent(envelopeId)}/proof`, opts.apiKey);
}
