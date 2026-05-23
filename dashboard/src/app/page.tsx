"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  Agent,
  AnomalyReport,
  Envelope,
  StreamEvent,
  VERIFIER_WS,
  fetchAgents,
  fetchAnomalyReport,
  fetchAudit,
  revokeAgent,
} from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui";

const MAX_STREAM = 80;

function toneOf(score: number | null | undefined) {
  if (score == null) return "neutral" as const;
  if (score >= 0.5) return "bad" as const;
  if (score >= 0.2) return "warn" as const;
  return "ok" as const;
}

function shortId(id: string) {
  return id.length > 22 ? `${id.slice(0, 22)}…` : id;
}

function timeOnly(iso: string) {
  try {
    const d = new Date(iso);
    return (
      d.toLocaleTimeString("en-GB", { hour12: false }) +
      "." +
      String(d.getMilliseconds()).padStart(3, "0")
    );
  } catch {
    return iso;
  }
}

export default function Dashboard() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stream, setStream] = useState<Envelope[]>([]);
  const [report, setReport] = useState<AnomalyReport | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    fetchAgents().then(setAgents).catch(() => {});
    fetchAudit()
      .then((rows) => setStream(rows.slice(0, MAX_STREAM)))
      .catch(() => {});
    fetchAnomalyReport().then(setReport).catch(() => {});

    const ws = new WebSocket(VERIFIER_WS);
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as StreamEvent;
        if (msg.type === "envelope") {
          const item: Envelope = {
            envelope_id: msg.envelope_id,
            agent_id: msg.agent_id,
            principal_id: msg.principal_id,
            action: msg.action,
            verdict: msg.verdict.valid ? "valid" : "invalid",
            reason: msg.verdict.reason,
            anomaly_score: msg.verdict.anomaly_score,
            received_at: msg.received_at,
          };
          setStream((prev) => [item, ...prev].slice(0, MAX_STREAM));
        } else if (msg.type === "revocation") {
          fetchAgents().then(setAgents).catch(() => {});
        }
      } catch {
        /* ignore */
      }
    };
    return () => ws.close();
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      fetchAgents().then(setAgents).catch(() => {});
    }, 5000);
    return () => clearInterval(id);
  }, []);

  const heatmap = useMemo(() => {
    const K = 16;
    const byAgent = new Map<string, (number | null)[]>();
    for (const e of stream) {
      const arr = byAgent.get(e.agent_id) ?? [];
      if (arr.length < K) arr.push(e.anomaly_score);
      byAgent.set(e.agent_id, arr);
    }
    return Array.from(byAgent.entries()).map(([agent_id, scores]) => ({
      agent_id,
      scores: scores.slice(0, K),
    }));
  }, [stream]);

  const onRevoke = async (id: string) => {
    if (typeof window !== "undefined" && !window.confirm(`Revoke ${id}?`))
      return;
    await revokeAgent(id, "manual");
    fetchAgents().then(setAgents).catch(() => {});
  };

  const liveCount = agents.filter((a) => !a.revoked_at).length;
  const revokedCount = agents.length - liveCount;

  return (
    <main className="flex flex-col gap-6 p-6 max-w-[1400px] mx-auto w-full">
      <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between border-b border-neutral-800 pb-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-xl font-semibold tracking-tight text-neutral-100">
            Signet
          </h1>
          <p className="text-sm text-neutral-400 max-w-xl">
            Post-quantum cryptographic identity for AI agents.
            <br />
            Auth0 for the agent economy — born quantum-safe.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <Badge tone={connected ? "ok" : "bad"}>
            ws · {connected ? "live" : "offline"}
          </Badge>
          <Badge tone="neutral">
            agents · {liveCount} live / {revokedCount} revoked
          </Badge>
          {report?.trained && (
            <Badge tone="accent">
              detector · {report.chosen} · q={report.quantum_auc?.toFixed(3)}{" "}
              rbf={report.rbf_auc?.toFixed(3)}
            </Badge>
          )}
        </div>
      </header>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 flex flex-col gap-6">
          <Card>
            <CardHeader className="flex items-center justify-between">
              <CardTitle>Agents</CardTitle>
              <span className="text-[11px] text-neutral-500 mono">
                ML-DSA-44
              </span>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead className="text-[11px] uppercase tracking-wider text-neutral-500 bg-neutral-900/30">
                  <tr>
                    <th className="text-left px-4 py-2 font-medium">Agent</th>
                    <th className="text-left px-4 py-2 font-medium">State</th>
                    <th className="text-right px-4 py-2 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {agents.length === 0 && (
                    <tr>
                      <td
                        className="px-4 py-6 text-neutral-500 text-center text-xs"
                        colSpan={3}
                      >
                        No agents yet. Run{" "}
                        <span className="mono text-neutral-400">
                          python scripts/demo_rogue.py
                        </span>
                        .
                      </td>
                    </tr>
                  )}
                  {agents.map((a) => (
                    <tr
                      key={a.agent_id}
                      className="border-t border-neutral-800/60"
                    >
                      <td className="px-4 py-2 mono text-neutral-200 text-xs">
                        {a.agent_id}
                      </td>
                      <td className="px-4 py-2">
                        {a.revoked_at ? (
                          <Badge tone="bad">revoked</Badge>
                        ) : (
                          <Badge tone="ok">active</Badge>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={!!a.revoked_at}
                          onClick={() => onRevoke(a.agent_id)}
                        >
                          Revoke
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Anomaly heatmap</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {heatmap.length === 0 && (
                <div className="text-neutral-500 text-xs py-3 text-center">
                  no envelopes yet
                </div>
              )}
              {heatmap.map(({ agent_id, scores }) => (
                <div key={agent_id} className="flex items-center gap-3">
                  <span className="mono text-[11px] text-neutral-400 w-44 truncate">
                    {shortId(agent_id)}
                  </span>
                  <div className="flex gap-1 flex-1">
                    {scores.map((s, i) => {
                      const tone = toneOf(s);
                      const bg =
                        tone === "ok"
                          ? "bg-emerald-700/60"
                          : tone === "warn"
                          ? "bg-amber-600/70"
                          : tone === "bad"
                          ? "bg-rose-700/70"
                          : "bg-neutral-700/40";
                      return (
                        <div
                          key={i}
                          title={s == null ? "no score" : s.toFixed(3)}
                          className={`h-5 flex-1 rounded-sm ${bg}`}
                        />
                      );
                    })}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-7">
          <Card className="overflow-hidden">
            <CardHeader className="flex items-center justify-between">
              <CardTitle>Live envelope stream</CardTitle>
              <span className="text-[11px] text-neutral-500 mono">
                last {stream.length}
              </span>
            </CardHeader>
            <CardContent className="p-0">
              <div className="text-[11px] uppercase tracking-wider text-neutral-500 bg-neutral-900/30 px-4 py-2 grid grid-cols-12 gap-2">
                <span className="col-span-2">Time</span>
                <span className="col-span-3">Agent</span>
                <span className="col-span-3">Action</span>
                <span className="col-span-2">Verdict</span>
                <span className="col-span-2 text-right">Score</span>
              </div>
              <div className="max-h-[640px] overflow-y-auto">
                {stream.length === 0 && (
                  <div className="text-neutral-500 text-xs py-8 text-center">
                    streaming…
                  </div>
                )}
                {stream.map((e) => {
                  const tone = toneOf(e.anomaly_score);
                  return (
                    <div
                      key={e.envelope_id + e.received_at}
                      className="px-4 py-2 border-t border-neutral-800/60 grid grid-cols-12 gap-2 items-center text-sm"
                    >
                      <span className="col-span-2 mono text-[11px] text-neutral-500">
                        {timeOnly(e.received_at)}
                      </span>
                      <span className="col-span-3 mono text-[11px] text-neutral-300 truncate">
                        {shortId(e.agent_id)}
                      </span>
                      <span className="col-span-3 mono text-[11px] text-neutral-200 truncate">
                        {e.action?.name ?? "—"}
                      </span>
                      <span className="col-span-2">
                        <Badge tone={e.verdict === "valid" ? "ok" : "bad"}>
                          {e.verdict}
                          {e.reason ? `:${e.reason}` : ""}
                        </Badge>
                      </span>
                      <span className="col-span-2 text-right">
                        <Badge tone={tone}>
                          {e.anomaly_score == null
                            ? "—"
                            : e.anomaly_score.toFixed(3)}
                        </Badge>
                      </span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      </section>
    </main>
  );
}
