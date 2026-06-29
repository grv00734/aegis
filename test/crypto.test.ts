import { describe, it, expect } from "vitest";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { encrypt, decrypt, loadOrCreateKey, AEGIS_TOKEN_RE } from "../src/crypto.js";
import { Vault } from "../src/scrub/placeholders.js";

const key = randomBytes(32);

describe("AES-256-GCM encrypt/decrypt", () => {
  it("round-trips a value", () => {
    const blob = encrypt("sk-ant-secret-123", key);
    expect(blob).not.toContain("sk-ant"); // ciphertext, not the value
    expect(decrypt(blob, key)).toBe("sk-ant-secret-123");
  });
  it("produces base64url with no padding or special chars", () => {
    expect(encrypt("hello world", key)).toMatch(/^[A-Za-z0-9_-]+$/);
  });
  it("fails closed on a tampered token", () => {
    const blob = encrypt("secret", key);
    const tampered = blob.slice(0, -2) + (blob.endsWith("A") ? "B" : "A") + "C";
    expect(decrypt(tampered, key)).toBeNull();
  });
  it("fails closed with the wrong key", () => {
    const blob = encrypt("secret", key);
    expect(decrypt(blob, randomBytes(32))).toBeNull();
  });
});

describe("local key persistence", () => {
  it("creates a 32-byte key and reuses it", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-key-"));
    const k1 = loadOrCreateKey(dir);
    expect(k1.length).toBe(32);
    expect(existsSync(join(dir, "redaction.key"))).toBe(true);
    const k2 = loadOrCreateKey(dir);
    expect(k2.equals(k1)).toBe(true); // same key on reload
  });
});

describe("Vault encryption mode", () => {
  it("emits AEGIS tokens and restores by decryption (stateless)", () => {
    const v = new Vault(key);
    const token = v.placeholderFor("dev@acme.com", "EMAIL");
    expect(token).toMatch(/^\[\[AEGIS:[A-Za-z0-9_-]+\]\]$/);
    expect(token).not.toContain("dev@acme.com");

    // A *different* vault with the same key can still restore — proves statelessness.
    const fresh = new Vault(key);
    expect(fresh.active).toBe(true);
    expect(fresh.restore(`set ${token} now`)).toBe("set dev@acme.com now");
  });

  it("reuses the same token for a repeated value within a request", () => {
    const v = new Vault(key);
    const a = v.placeholderFor("a@b.com", "EMAIL");
    const b = v.placeholderFor("a@b.com", "EMAIL");
    expect(a).toBe(b);
  });

  it("default mode (no key) still uses index placeholders", () => {
    const v = new Vault();
    expect(v.placeholderFor("x@y.com", "EMAIL")).toMatch(/^\[\[REDACTED:EMAIL:\d+\]\]$/);
  });
});
