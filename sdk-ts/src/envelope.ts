import { randomBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";

import { canonicalBytes } from "./canonical.js";

export type Action = {
  type?: string;
  name?: string;
  params?: Record<string, unknown>;
  [k: string]: unknown;
};

export type Identity = {
  agentId: string;
  principalId: string;
  algorithm: "ML-DSA-44";
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  ed25519Public: Uint8Array;
  ed25519Secret: Uint8Array;
};

export type EnvelopeData = {
  envelope_version: string;
  envelope_id: string;
  agent_id: string;
  principal_id: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  action: Action;
  signature?: Record<string, unknown>;
};

const b64 = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b));

function hexRandom(n: number): string {
  const bytes = randomBytes(n);
  return Array.from(bytes).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function isoNow(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

function isoIn(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export async function generateIdentity(principalId: string): Promise<Identity> {
  const seed = randomBytes(32);
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const edSecret = ed25519.utils.randomPrivateKey();
  const edPublic = ed25519.getPublicKey(edSecret);
  return {
    agentId: "agt_" + hexRandom(8),
    principalId,
    algorithm: "ML-DSA-44",
    publicKey,
    secretKey,
    ed25519Public: edPublic,
    ed25519Secret: edSecret,
  };
}

export function newEnvelope(
  agentId: string,
  principalId: string,
  action: Action,
  ttlMinutes = 5,
): EnvelopeData {
  return {
    envelope_version: "signet/1",
    envelope_id: "env_" + hexRandom(12),
    agent_id: agentId,
    principal_id: principalId,
    issued_at: isoNow(),
    expires_at: isoIn(ttlMinutes),
    nonce: b64(randomBytes(16)),
    action,
  };
}

function payloadBytes(env: EnvelopeData): Uint8Array {
  const { signature: _sig, ...rest } = env;
  return canonicalBytes(rest);
}

export function signEnvelope(env: EnvelopeData, identity: Identity, hybrid = true): EnvelopeData {
  const payload = payloadBytes(env);
  const pqSig = ml_dsa44.sign(identity.secretKey, payload);
  const signature: Record<string, unknown> = {
    algorithm: identity.algorithm,
    value: b64(pqSig),
  };
  if (hybrid) {
    const cl = ed25519.sign(payload, identity.ed25519Secret);
    signature.hybrid_classical = "Ed25519";
    signature.hybrid_classical_value = b64(cl);
  }
  return { ...env, signature };
}

export function verifyEnvelope(env: EnvelopeData, publicKey: Uint8Array, ed25519Public?: Uint8Array): boolean {
  const payload = payloadBytes(env);
  const sig = env.signature ?? {};
  const pqSigB64 = sig.value as string | undefined;
  if (!pqSigB64) return false;
  const pqSig = Uint8Array.from(atob(pqSigB64), (c) => c.charCodeAt(0));
  if (!ml_dsa44.verify(publicKey, payload, pqSig)) return false;
  if (ed25519Public && sig.hybrid_classical_value) {
    const clSig = Uint8Array.from(atob(sig.hybrid_classical_value as string), (c) => c.charCodeAt(0));
    return ed25519.verify(clSig, payload, ed25519Public);
  }
  return true;
}
