export const VERIFIER_HTTP =
  process.env.NEXT_PUBLIC_VERIFIER_HTTP ?? "http://127.0.0.1:8000";
export const VERIFIER_WS =
  process.env.NEXT_PUBLIC_VERIFIER_WS ?? "ws://127.0.0.1:8000/ws/stream";

export type Agent = {
  agent_id: string;
  principal_id: string;
  algorithm: string;
  registered_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
};

export type Envelope = {
  envelope_id: string;
  agent_id: string;
  principal_id: string;
  action: {
    type?: string;
    name?: string;
    params?: Record<string, unknown>;
  };
  verdict: string;
  reason: string | null;
  anomaly_score: number | null;
  received_at: string;
};

export type AnomalyReport = {
  trained: boolean;
  quantum_auc?: number;
  rbf_auc?: number;
  chosen?: string;
  threshold?: number;
};

export type StreamEvent =
  | {
      type: "envelope";
      envelope_id: string;
      agent_id: string;
      principal_id: string;
      action: Envelope["action"];
      verdict: { valid: boolean; reason: string | null; anomaly_score: number | null };
      received_at: string;
    }
  | { type: "revocation"; agent_id: string; reason: string };

export async function fetchAgents(): Promise<Agent[]> {
  const r = await fetch(`${VERIFIER_HTTP}/v1/agents`, { cache: "no-store" });
  const j = await r.json();
  return j.agents ?? [];
}

export async function fetchAudit(limit = 200): Promise<Envelope[]> {
  const r = await fetch(`${VERIFIER_HTTP}/v1/audit?limit=${limit}`, {
    cache: "no-store",
  });
  const j = await r.json();
  return j.envelopes ?? [];
}

export async function fetchAnomalyReport(): Promise<AnomalyReport> {
  const r = await fetch(`${VERIFIER_HTTP}/v1/anomaly/report`, {
    cache: "no-store",
  });
  return r.json();
}

export async function revokeAgent(agent_id: string, reason: string) {
  const r = await fetch(
    `${VERIFIER_HTTP}/v1/agents/${agent_id}/revoke?reason=${encodeURIComponent(reason)}`,
    { method: "POST" },
  );
  return r.json();
}

export type InclusionProof = {
  envelope_id: string;
  algorithm: string;
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  root: string;
  proof: { position: "left" | "right"; hash: string }[];
};

export async function fetchInclusionProof(
  envelope_id: string,
): Promise<InclusionProof> {
  const r = await fetch(
    `${VERIFIER_HTTP}/v1/envelopes/${envelope_id}/proof`,
    { cache: "no-store" },
  );
  if (!r.ok) throw new Error(`proof HTTP ${r.status}`);
  return r.json();
}
