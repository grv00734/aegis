/**
 * Optional encryption mode for redaction.
 *
 * Instead of replacing a confidential value with an index placeholder, we
 * AES-256-GCM-encrypt it with a LOCAL key and embed the ciphertext in the token
 * that goes to the AI: `[[AEGIS:<base64url(iv|tag|ciphertext)>]]`. On the
 * response, any such token is decrypted back to the real value.
 *
 * The key lives only on this machine (~/.aegis/redaction.key, 0600) and is never
 * sent anywhere. Because the token carries the encrypted value, restoration is
 * stateless — it survives proxy restarts and works across instances that share
 * the key. GCM's auth tag means a token mangled by the model fails closed
 * (decrypt returns null) rather than producing garbage.
 */
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { aegisHome } from "./ca.js";

export const AEGIS_TOKEN_RE = /\[\[AEGIS:([A-Za-z0-9_-]+)\]\]/g;

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Load the local redaction key, creating a fresh 256-bit key on first use. */
export function loadOrCreateKey(dir: string = aegisHome()): Buffer {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = join(dir, "redaction.key");
  if (existsSync(p)) {
    const key = Buffer.from(readFileSync(p, "utf8").trim(), "base64");
    if (key.length === 32) return key;
  }
  const key = randomBytes(32);
  writeFileSync(p, key.toString("base64"), { mode: 0o600 });
  return key;
}

/** Encrypt a value into a compact base64url blob (iv|tag|ciphertext). */
export function encrypt(value: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return b64url(Buffer.concat([iv, tag, ct]));
}

/** Decrypt a blob back to its value, or null if it is malformed/tampered. */
export function decrypt(blob: string, key: Buffer): string | null {
  try {
    const raw = fromB64url(blob);
    if (raw.length < 29) return null; // 12 iv + 16 tag + >=1 ct
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ct = raw.subarray(28);
    const d = createDecipheriv("aes-256-gcm", key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}
