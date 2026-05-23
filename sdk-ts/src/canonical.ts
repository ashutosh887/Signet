/**
 * Canonical JSON serialization compatible with Python's
 *   json.dumps(payload, sort_keys=True, separators=(",", ":"))
 *
 * Approximates RFC 8785 JCS — same sort order at every level, no
 * whitespace, no trailing newline. The Python verifier signs the same
 * canonical form, so envelopes signed here verify there.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Number.isInteger(value)) return value.toString();
    return value.toString();
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]));
    return "{" + parts.join(",") + "}";
  }
  throw new Error("unsupported value: " + typeof value);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
