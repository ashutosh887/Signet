"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  Agent,
  AnomalyReport,
  Envelope,
  FIRMWARE_PATH,
  InclusionProof,
  LLMFireResult,
  StreamEvent,
  VERIFIER_WS,
  fetchAgents,
  fetchAnomalyReport,
  fetchAudit,
  fetchInclusionProof,
  fireLLMAction,
  getApiKey,
  revokeAgent,
  setApiKey,
} from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CopyButton,
  Stat,
} from "@/components/ui";

const MAX_STREAM = 120;
const ANOMALY_RED = 0.5;
const ANOMALY_AMBER = 0.2;

function toneOf(score: number | null | undefined) {
  if (score == null) return "neutral" as const;
  if (score >= ANOMALY_RED) return "bad" as const;
  if (score >= ANOMALY_AMBER) return "warn" as const;
  return "ok" as const;
}

function shortId(id: string, len = 14) {
  return id.length > len + 4 ? `${id.slice(0, len)}…${id.slice(-4)}` : id;
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

function relative(iso: string) {
  try {
    const ms = Date.now() - new Date(iso).getTime();
    if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    return `${Math.floor(ms / 3_600_000)}h ago`;
  } catch {
    return iso;
  }
}

const HOW_IT_WORKS = [
  {
    n: "1",
    title: "Agent registers",
    body: "Every AI agent generates an ML-DSA-44 (FIPS 204) keypair and hands the verifier its public key.",
  },
  {
    n: "2",
    title: "Action is signed",
    body: "Before acting, the agent wraps the call in a canonical-JSON envelope and signs it. Hybrid Ed25519 + ML-DSA-44.",
  },
  {
    n: "3",
    title: "Verifier judges",
    body: "Signature checked, replay nonce remembered, tenant policy run, quantum-kernel anomaly score computed. <50 ms.",
  },
  {
    n: "4",
    title: "Logged + streamed",
    body: "Every envelope hashes into a SHA3-256 Merkle log and lands here in real time. Revocation propagates over WebSocket.",
  },
];

export default function Dashboard() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stream, setStream] = useState<Envelope[]>([]);
  const [report, setReport] = useState<AnomalyReport | null>(null);
  const [connected, setConnected] = useState(false);
  const [proof, setProof] = useState<InclusionProof | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [apiKey, setApiKeyState] = useState<string>("");
  const [firePrompt, setFirePrompt] = useState<string>(
    "Schedule a 30-minute meeting with Akash on Monday at 4pm",
  );
  const [fireBusy, setFireBusy] = useState(false);
  const [fireResult, setFireResult] = useState<LLMFireResult | null>(null);
  const [fireError, setFireError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const stored = getApiKey();
    if (stored) setApiKeyState(stored);
  }, []);

  const onApiKeyChange = (next: string) => {
    setApiKeyState(next);
    setApiKey(next || null);
    fetchAgents().then(setAgents).catch(() => setAgents([]));
    fetchAudit()
      .then((rows) => setStream(rows.slice(0, MAX_STREAM)))
      .catch(() => setStream([]));
  };

  const showProof = async (envelope_id: string) => {
    setProofError(null);
    try {
      const p = await fetchInclusionProof(envelope_id);
      setProof(p);
    } catch (e) {
      setProof(null);
      setProofError((e as Error).message);
    }
  };

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

  const stats = useMemo(() => {
    const total = stream.length;
    const valid = stream.filter((e) => e.verdict === "valid").length;
    const denied = total - valid;
    const scored = stream.filter((e) => typeof e.anomaly_score === "number");
    const avgScore = scored.length
      ? scored.reduce((s, e) => s + (e.anomaly_score || 0), 0) / scored.length
      : null;
    const peakScore = scored.length
      ? Math.max(...scored.map((e) => e.anomaly_score || 0))
      : null;
    return { total, valid, denied, avgScore, peakScore };
  }, [stream]);

  const heatmap = useMemo(() => {
    const K = 18;
    const byAgent = new Map<string, { scores: (number | null)[]; lastSeen: string }>();
    for (const e of stream) {
      const existing = byAgent.get(e.agent_id) ?? { scores: [], lastSeen: e.received_at };
      if (existing.scores.length < K) existing.scores.push(e.anomaly_score);
      byAgent.set(e.agent_id, existing);
    }
    return Array.from(byAgent.entries()).map(([agent_id, v]) => ({
      agent_id,
      scores: v.scores.slice(0, K),
      lastSeen: v.lastSeen,
    }));
  }, [stream]);

  const onFire = async () => {
    if (!firePrompt.trim() || fireBusy) return;
    setFireBusy(true);
    setFireError(null);
    setFireResult(null);
    try {
      const res = await fireLLMAction(firePrompt.trim());
      setFireResult(res);
    } catch (e) {
      setFireError((e as Error).message);
    } finally {
      setFireBusy(false);
    }
  };

  const onRevoke = async (id: string) => {
    if (typeof window !== "undefined" && !window.confirm(`Revoke ${id}? This is a one-click kill for the agent.`))
      return;
    await revokeAgent(id, "manual_dashboard_revoke");
    fetchAgents().then(setAgents).catch(() => {});
  };

  const liveCount = agents.filter((a) => !a.revoked_at).length;
  const revokedCount = agents.length - liveCount;

  return (
    <main className="flex flex-col gap-8 px-6 py-8 lg:px-10 lg:py-10 max-w-[1500px] mx-auto w-full">
      {/* HERO */}
      <header className="flex flex-col gap-5">
        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-4">
          <div className="flex flex-col gap-2">
            <div className="flex items-baseline gap-3">
              <h1 className="text-3xl font-semibold tracking-tight text-neutral-50">
                Signet
              </h1>
              <span className="mono text-[12px] text-neutral-500 uppercase tracking-widest">
                Live verifier
              </span>
            </div>
            <p className="text-[15px] text-neutral-400 max-w-2xl leading-relaxed">
              Every AI agent action below is{" "}
              <span className="text-neutral-200">signed</span> with NIST-finalised
              post-quantum cryptography (ML-DSA-44), checked against a tenant{" "}
              <span className="text-neutral-200">policy</span>, scored by a{" "}
              <span className="text-neutral-200">quantum-kernel anomaly model</span>,
              and appended to a tamper-evident{" "}
              <span className="text-neutral-200">Merkle audit log</span>.
            </p>
          </div>
          <div className="flex flex-col items-start lg:items-end gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={connected ? "ok" : "bad"} className="gap-1.5">
                <span
                  className={`inline-block w-1.5 h-1.5 rounded-full ${
                    connected ? "bg-emerald-400 animate-pulse" : "bg-rose-400"
                  }`}
                />
                {connected ? "WebSocket connected" : "Disconnected"}
              </Badge>
              {report?.trained ? (
                <Badge tone="accent">
                  Detector · {report.chosen?.toUpperCase()} · AUC{" "}
                  {(report.chosen === "quantum"
                    ? report.quantum_auc
                    : report.rbf_auc)?.toFixed(3)}
                </Badge>
              ) : (
                <Badge tone="muted">Detector training…</Badge>
              )}
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="X-API-Key (multi-tenant; optional)"
                value={apiKey}
                onChange={(e) => onApiKeyChange(e.target.value)}
                className="bg-neutral-900/60 border border-neutral-800 rounded-md px-2.5 py-1.5 text-[12px] mono text-neutral-200 placeholder:text-neutral-600 focus:outline-none focus:border-neutral-700 w-72"
              />
              <span className="text-[11px] text-neutral-600">
                {apiKey ? "scoped" : "default tenant"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* HOW IT WORKS */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {HOW_IT_WORKS.map((step) => (
          <Card key={step.n} className="px-5 py-4 flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <span className="w-7 h-7 rounded-full bg-indigo-500/15 text-indigo-300 mono text-xs flex items-center justify-center border border-indigo-500/30">
                {step.n}
              </span>
              <span className="text-sm font-semibold text-neutral-100">
                {step.title}
              </span>
            </div>
            <p className="text-[12px] text-neutral-400 leading-relaxed">
              {step.body}
            </p>
          </Card>
        ))}
      </section>

      {/* KPIs */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat
          label="Envelopes"
          value={stats.total}
          hint={`${stats.valid} verified · ${stats.denied} denied`}
        />
        <Stat
          label="Active agents"
          value={liveCount}
          hint={`${revokedCount} revoked`}
          tone={revokedCount > 0 ? "warn" : "ok"}
        />
        <Stat
          label="Peak anomaly"
          value={stats.peakScore == null ? "—" : stats.peakScore.toFixed(3)}
          hint={`threshold ≥ ${ANOMALY_RED.toFixed(2)} fires alert`}
          tone={
            stats.peakScore == null
              ? "neutral"
              : stats.peakScore >= ANOMALY_RED
              ? "bad"
              : stats.peakScore >= ANOMALY_AMBER
              ? "warn"
              : "ok"
          }
        />
        <Stat
          label="Signature scheme"
          value={
            <span className="mono text-base">
              ML-DSA-44 + Ed25519
            </span>
          }
          hint="Hybrid · FIPS 204 + RFC 8032"
          tone="accent"
        />
      </section>

      <Card className="px-5 py-4 flex flex-col gap-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-neutral-100">
              Live LLM action
            </div>
            <p className="text-[12px] text-neutral-500 leading-relaxed max-w-2xl">
              Hit the button — the verifier asks a real LLM to plan a tool call,
              signs the result with ML-DSA-44, and submits the envelope. It
              appears in the stream below within a second.
            </p>
          </div>
          {fireResult && (
            <Badge tone={fireResult.verdict.valid ? "ok" : "bad"}>
              {fireResult.verdict.valid ? "verified" : "denied"} ·{" "}
              {fireResult.action?.name ?? "—"} · {fireResult.provider}
            </Badge>
          )}
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={firePrompt}
            onChange={(e) => setFirePrompt(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onFire();
            }}
            placeholder="What should the agent do?"
            className="flex-1 bg-neutral-900/60 border border-neutral-800 rounded-md px-3 py-2 text-[13px] text-neutral-100 placeholder:text-neutral-600 focus:outline-none focus:border-neutral-700"
          />
          <Button onClick={onFire} disabled={fireBusy || !firePrompt.trim()}>
            {fireBusy ? "Planning…" : "Fire LLM action"}
          </Button>
        </div>
        {fireError && (
          <div className="text-rose-400 text-[12px] break-words">
            {fireError}
          </div>
        )}
      </Card>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT */}
        <div className="lg:col-span-5 flex flex-col gap-5">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle subtitle="Each agent holds a post-quantum keypair. Click revoke to kill it — propagates in <1 s.">
                  Registered agents
                </CardTitle>
                <Badge tone="muted">
                  {liveCount} active · {revokedCount} revoked
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead className="text-[10px] uppercase tracking-[0.08em] text-neutral-500 bg-neutral-900/40">
                  <tr>
                    <th className="text-left px-5 py-2.5 font-medium">Agent</th>
                    <th className="text-left px-3 py-2.5 font-medium">Principal</th>
                    <th className="text-left px-3 py-2.5 font-medium">State</th>
                    <th className="text-right px-5 py-2.5 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {agents.length === 0 && (
                    <tr>
                      <td
                        className="px-5 py-8 text-neutral-500 text-center text-xs"
                        colSpan={4}
                      >
                        No agents registered yet. Run{" "}
                        <span className="mono text-neutral-300">
                          python scripts/demo_seed.py
                        </span>
                        .
                      </td>
                    </tr>
                  )}
                  {agents.map((a) => (
                    <tr
                      key={a.agent_id}
                      className="border-t border-neutral-800/60 hover:bg-neutral-900/30"
                    >
                      <td className="px-5 py-2.5 mono text-[12px] text-neutral-200">
                        {shortId(a.agent_id, 18)}
                      </td>
                      <td className="px-3 py-2.5 mono text-[11px] text-neutral-500">
                        {shortId(a.principal_id, 12)}
                      </td>
                      <td className="px-3 py-2.5">
                        {a.revoked_at ? (
                          <Badge tone="bad">revoked</Badge>
                        ) : (
                          <Badge tone="ok">active</Badge>
                        )}
                      </td>
                      <td className="px-5 py-2.5 text-right">
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
              <CardTitle subtitle="Latest 18 envelopes per agent. Darker red = higher anomaly score. Hover a cell for the exact value.">
                Behaviour heatmap
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex items-center gap-3 text-[11px] text-neutral-500">
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-sm bg-emerald-700/60" />
                  <span>normal &lt; {ANOMALY_AMBER}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-sm bg-amber-600/70" />
                  <span>suspicious</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-sm bg-rose-700/70" />
                  <span>anomaly ≥ {ANOMALY_RED}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-sm bg-neutral-700/40" />
                  <span>no score</span>
                </div>
              </div>
              {heatmap.length === 0 && (
                <div className="text-neutral-500 text-xs py-6 text-center">
                  No envelopes yet — seed data or fire an agent.
                </div>
              )}
              <div className="flex flex-col gap-2">
                {heatmap.map(({ agent_id, scores, lastSeen }) => (
                  <div key={agent_id} className="flex items-center gap-3">
                    <div className="flex flex-col gap-0 w-44 shrink-0">
                      <span className="mono text-[11px] text-neutral-300 truncate">
                        {shortId(agent_id, 16)}
                      </span>
                      <span className="text-[10px] text-neutral-600">
                        last {relative(lastSeen)}
                      </span>
                    </div>
                    <div className="flex gap-1 flex-1 min-w-0">
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
                            title={s == null ? "no score" : `score ${s.toFixed(3)}`}
                            className={`h-6 flex-1 rounded-sm ${bg}`}
                          />
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle subtitle="Click any verified envelope on the right to fetch its inclusion proof against this root.">
                Audit log integrity
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 text-[12px]">
              <div className="flex items-center justify-between">
                <span className="text-neutral-500">Algorithm</span>
                <Badge tone="muted">SHA3-256</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-neutral-500">Tree size</span>
                <span className="mono text-neutral-200 tabular-nums">
                  {stats.total} leaves
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-neutral-500">Hybrid signature</span>
                <span className="mono text-neutral-200">
                  Ed25519 ‖ ML-DSA-44
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-neutral-500">KEM</span>
                <span className="mono text-neutral-200">
                  X25519 + ML-KEM-768
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-neutral-500">Root keys</span>
                <span className="mono text-neutral-200">SLH-DSA-128s</span>
              </div>
              <p className="text-neutral-500 leading-relaxed pt-2">
                Inclusion proofs are verifiable client-side — no need to trust
                the verifier to know your envelope made it into the log.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* RIGHT */}
        <div className="lg:col-span-7">
          <Card className="overflow-hidden">
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle subtitle="Every envelope as it lands. Green rows clickable — see Merkle proof. Red rows are denied (signature, policy, expiry, or replay).">
                  Live action stream
                </CardTitle>
                <Badge tone="muted">{stream.length} recent</Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="text-[10px] uppercase tracking-[0.08em] text-neutral-500 bg-neutral-900/40 px-5 py-2.5 grid grid-cols-12 gap-2">
                <span className="col-span-2">Time</span>
                <span className="col-span-3">Agent</span>
                <span className="col-span-3">Tool call</span>
                <span className="col-span-2">Verdict</span>
                <span className="col-span-2 text-right">Anomaly</span>
              </div>
              <div className="max-h-[820px] overflow-y-auto">
                {stream.length === 0 && (
                  <div className="text-neutral-500 text-sm py-10 text-center">
                    Waiting for the first envelope. Try{" "}
                    <span className="mono text-neutral-300">
                      python scripts/demo_rogue.py
                    </span>
                    .
                  </div>
                )}
                {stream.map((e) => {
                  const tone = toneOf(e.anomaly_score);
                  const isValid = e.verdict === "valid";
                  const leftAccent = !isValid
                    ? "border-l-2 border-l-rose-700/70"
                    : tone === "bad"
                    ? "border-l-2 border-l-rose-700/70"
                    : tone === "warn"
                    ? "border-l-2 border-l-amber-600/70"
                    : "border-l-2 border-l-transparent";
                  return (
                    <button
                      key={e.envelope_id + e.received_at}
                      type="button"
                      onClick={() => isValid && showProof(e.envelope_id)}
                      disabled={!isValid}
                      className={`w-full text-left px-5 py-2.5 border-t border-neutral-800/60 grid grid-cols-12 gap-2 items-center text-sm transition-colors ${leftAccent} ${
                        isValid
                          ? "hover:bg-neutral-800/30 cursor-pointer"
                          : "opacity-80 cursor-default"
                      }`}
                    >
                      <span className="col-span-2 mono text-[11px] text-neutral-500 tabular-nums">
                        {timeOnly(e.received_at)}
                      </span>
                      <span className="col-span-3 mono text-[11px] text-neutral-300 truncate">
                        {shortId(e.agent_id, 14)}
                      </span>
                      <span className="col-span-3 mono text-[12px] text-neutral-100 truncate">
                        {e.action?.name ?? "—"}
                      </span>
                      <span className="col-span-2">
                        {isValid ? (
                          <Badge tone="ok">verified</Badge>
                        ) : (
                          <Badge tone="bad" className="truncate max-w-full">
                            {e.reason || "denied"}
                          </Badge>
                        )}
                      </span>
                      <span className="col-span-2 text-right">
                        {e.anomaly_score == null ? (
                          <span className="text-neutral-600 text-xs">—</span>
                        ) : (
                          <Badge tone={tone}>
                            <span className="tabular-nums">
                              {e.anomaly_score.toFixed(3)}
                            </span>
                          </Badge>
                        )}
                      </span>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* PROOF MODAL */}
      {(proof || proofError) && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={() => {
            setProof(null);
            setProofError(null);
          }}
        >
          <div
            className="bg-neutral-950 border border-neutral-800 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-5 border-b border-neutral-800 flex items-start justify-between gap-4">
              <div className="flex flex-col gap-1">
                <h3 className="text-lg font-semibold text-neutral-50 tracking-tight">
                  Tamper-evident audit proof
                </h3>
                <p className="text-[12px] text-neutral-500 leading-relaxed max-w-xl">
                  This envelope is one leaf of a SHA3-256 Merkle tree. The
                  verifier proves it&apos;s in the log by handing you a small set
                  of sibling hashes — combine them up the tree and you get the
                  same root the verifier publishes. No trust required.
                </p>
              </div>
              <button
                type="button"
                className="text-neutral-500 hover:text-neutral-200 text-sm px-2 py-1 rounded border border-neutral-800 hover:border-neutral-700"
                onClick={() => {
                  setProof(null);
                  setProofError(null);
                }}
              >
                Close
              </button>
            </div>
            <div className="px-6 py-5 flex flex-col gap-4">
              {proofError && (
                <div className="text-rose-400 text-sm">
                  Could not fetch proof: {proofError}
                </div>
              )}
              {proof && (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <ProofField label="Envelope" value={proof.envelope_id} mono />
                    <ProofField label="Hash function" value={proof.algorithm} />
                    <ProofField
                      label="Leaf index"
                      value={`#${proof.leaf_index} of ${proof.tree_size}`}
                    />
                    <ProofField
                      label="Sibling hashes"
                      value={String(proof.proof.length)}
                      hint={
                        proof.proof.length === 0
                          ? "single-leaf tree"
                          : `log₂(${proof.tree_size}) path`
                      }
                    />
                  </div>

                  <ProofHash label="Leaf hash" value={proof.leaf_hash} />
                  <ProofHash label="Merkle root" value={proof.root} />

                  <div className="flex flex-col gap-2">
                    <span className="text-[11px] uppercase tracking-[0.08em] text-neutral-500">
                      Proof path · combine leaf → root
                    </span>
                    {proof.proof.length === 0 && (
                      <span className="text-neutral-500 text-sm">
                        This tree only has one leaf, so the leaf hash is the root.
                      </span>
                    )}
                    <ol className="flex flex-col gap-1.5 mono text-[11px]">
                      {proof.proof.map((step, i) => (
                        <li
                          key={i}
                          className="flex items-center gap-3 px-3 py-2 rounded-md bg-neutral-900/60 border border-neutral-800/60"
                        >
                          <span className="text-neutral-600 tabular-nums w-6">
                            {String(i).padStart(2, "0")}
                          </span>
                          <span
                            className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                              step.position === "left"
                                ? "text-indigo-300 border-indigo-900 bg-indigo-950/40"
                                : "text-emerald-300 border-emerald-900 bg-emerald-950/40"
                            }`}
                          >
                            sibling {step.position}
                          </span>
                          <span className="text-neutral-300 break-all flex-1">
                            {step.hash}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <footer className="text-[11px] text-neutral-600 pt-6 border-t border-neutral-900 flex flex-wrap gap-3 justify-between">
        <span>
          Identity → Behaviour → Observability. One spine. Signet · localhost
          verifier.
        </span>
        <span className="flex gap-3">
          <a
            className="hover:text-neutral-300"
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
          >
            API explorer
          </a>
          <a
            className="hover:text-neutral-300"
            href="http://localhost:8000/metrics"
            target="_blank"
            rel="noreferrer"
          >
            Prometheus
          </a>
          <a
            className="hover:text-neutral-300"
            href="http://localhost:8000/v1/audit/root"
            target="_blank"
            rel="noreferrer"
          >
            Merkle root
          </a>
          {FIRMWARE_PATH && (
            <a
              className="hover:text-neutral-300"
              href={`vscode://file/${FIRMWARE_PATH}`}
              title="Open the ESP32 firmware in VS Code / PlatformIO"
            >
              Open firmware in VS Code
            </a>
          )}
        </span>
      </footer>
    </main>
  );
}

function ProofField({
  label,
  value,
  mono,
  hint,
}: {
  label: string;
  value: string;
  mono?: boolean;
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-1 px-3 py-2 rounded-md border border-neutral-800/60 bg-neutral-900/40">
      <span className="text-[10px] uppercase tracking-[0.08em] text-neutral-500">
        {label}
      </span>
      <span
        className={`text-[12px] text-neutral-100 ${mono ? "mono" : ""} truncate`}
      >
        {value}
      </span>
      {hint && <span className="text-[11px] text-neutral-600">{hint}</span>}
    </div>
  );
}

function ProofHash({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-[0.08em] text-neutral-500">
          {label}
        </span>
        <CopyButton text={value} />
      </div>
      <span className="mono text-[11px] text-neutral-200 break-all px-3 py-2 rounded-md bg-neutral-900/60 border border-neutral-800/60">
        {value}
      </span>
    </div>
  );
}
