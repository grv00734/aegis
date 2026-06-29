/**
 * The Vault holds the mapping between real confidential values and the opaque
 * tokens that take their place in outbound traffic.
 *
 * Two token strategies:
 *  - default: a stable index placeholder `[[REDACTED:TYPE:N]]` (mapping kept in
 *    memory for this request).
 *  - encryption mode (constructed with a key): an AES-256-GCM token
 *    `[[AEGIS:<ciphertext>]]`. The ciphertext carries the value, so restoration
 *    works by decryption — statelessly, even across restarts/instances.
 *
 * SECURITY: a Vault is created fresh per request and lives only in memory for
 * the duration of that request/response pair. Real values are never written to
 * disk, never logged, and never sent upstream (only placeholders/ciphertext are).
 */
import { encrypt, decrypt, AEGIS_TOKEN_RE } from "../crypto.js";

const PLACEHOLDER_RE = /\[\[REDACTED:[A-Z0-9_]+:\d+\]\]/g;
/** Matches either token kind, for the fast map-based restore pass. */
const ANY_TOKEN_RE = /\[\[(?:REDACTED:[A-Z0-9_]+:\d+|AEGIS:[A-Za-z0-9_-]+)\]\]/g;

export class Vault {
  private counter = 0;
  /** real value -> token (so repeated values map to the same token). */
  private forward = new Map<string, string>();
  /** token -> real value (for restoration). */
  private backward = new Map<string, string>();
  private key?: Buffer;

  /** Pass a key to enable encryption mode; omit for index placeholders. */
  constructor(key?: Buffer) {
    this.key = key;
  }

  /** Return a stable token for a given real value + type. */
  placeholderFor(value: string, type: string): string {
    const existing = this.forward.get(value);
    if (existing) return existing;

    const token = this.key
      ? `[[AEGIS:${encrypt(value, this.key)}]]`
      : `[[REDACTED:${type}:${++this.counter}]]`;
    this.forward.set(value, token);
    this.backward.set(token, value);
    return token;
  }

  /** Swap any tokens found in `text` back to their real values. */
  restore(text: string): string {
    if (this.backward.size === 0 && !this.key) return text;
    let out = text;
    // 1) fast path: exact tokens we minted this request.
    if (this.backward.size > 0) {
      out = out.replace(ANY_TOKEN_RE, (t) => this.backward.get(t) ?? t);
    }
    // 2) stateless path: decrypt any remaining encrypted tokens.
    if (this.key) {
      out = out.replace(AEGIS_TOKEN_RE, (m, blob: string) => decrypt(blob, this.key!) ?? m);
    }
    return out;
  }

  get size(): number {
    return this.backward.size;
  }

  /** Whether this vault should process responses (has entries or a key). */
  get active(): boolean {
    return this.backward.size > 0 || !!this.key;
  }

  /** Recursively restore tokens in every string within a JSON-like value. */
  restoreDeep<T>(value: T): T {
    if (this.backward.size === 0 && !this.key) return value;
    if (typeof value === "string") return this.restore(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => this.restoreDeep(v)) as unknown as T;
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = this.restoreDeep(v);
      }
      return out as unknown as T;
    }
    return value;
  }
}

export { PLACEHOLDER_RE };
