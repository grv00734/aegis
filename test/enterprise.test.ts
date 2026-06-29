import { describe, it, expect } from "vitest";
import { createHmac, generateKeyPairSync, createSign } from "node:crypto";
import { authenticate, can, verifyJwt, type AuthConfig } from "../src/auth.js";
import { FleetAggregator, reportFromBudget } from "../src/fleet.js";
import { isMcp, mcpToolName, mcpDenied } from "../src/mcp.js";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { BudgetSnapshot } from "../src/budget.js";

function b64url(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hs256(payload: object, secret: string): string {
  const head = b64url({ alg: "HS256", typ: "JWT" });
  const body = b64url(payload);
  const sig = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${head}.${body}.${sig}`;
}

describe("RBAC permissions", () => {
  it("orders roles correctly", () => {
    expect(can("viewer", "read")).toBe(true);
    expect(can("viewer", "control")).toBe(false);
    expect(can("operator", "control")).toBe(true);
    expect(can("operator", "configure")).toBe(false);
    expect(can("admin", "configure")).toBe(true);
  });
});

describe("token + JWT authentication", () => {
  const cfg: AuthConfig = { enabled: true, tokens: { "secret-admin": "admin" }, jwt: { algorithm: "HS256", secret: "topsecret", roleClaim: "role" } };

  it("authenticates a static token to its role", () => {
    expect(authenticate({ authorization: "Bearer secret-admin" }, cfg)?.role).toBe("admin");
  });
  it("rejects an unknown token", () => {
    expect(authenticate({ authorization: "Bearer nope" }, cfg)).toBeNull();
  });
  it("verifies a valid HS256 JWT and maps the role claim", () => {
    const tok = hs256({ sub: "alice", role: "operator", exp: Math.floor(Date.now() / 1000) + 60 }, "topsecret");
    const who = authenticate({ authorization: `Bearer ${tok}` }, cfg);
    expect(who?.role).toBe("operator");
    expect(who?.subject).toBe("alice");
  });
  it("rejects a JWT signed with the wrong secret", () => {
    const tok = hs256({ sub: "mallory", role: "admin" }, "wrong");
    expect(authenticate({ authorization: `Bearer ${tok}` }, cfg)).toBeNull();
  });
  it("rejects an expired JWT", () => {
    const tok = hs256({ sub: "x", role: "admin", exp: 1 }, "topsecret");
    expect(verifyJwt(tok, cfg.jwt!)).toBeNull();
  });
  it("verifies an RS256 JWT with the IdP public key (SSO)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const head = b64url({ alg: "RS256", typ: "JWT" });
    const body = b64url({ sub: "bob", role: "viewer" });
    const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(privateKey).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const tok = `${head}.${body}.${sig}`;
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
    expect(verifyJwt(tok, { algorithm: "RS256", publicKeyPem: pem })?.sub).toBe("bob");
  });
});

describe("fleet aggregation", () => {
  it("sums spend across hosts and merges per-employee", () => {
    const agg = new FleetAggregator();
    agg.ingest({ host: "laptop-1", tokens: 100, costUsd: 1, requests: 2, users: [{ user: "alice", tokens: 100, costUsd: 1 }] }, "t");
    agg.ingest({ host: "laptop-2", tokens: 50, costUsd: 0.5, requests: 1, users: [{ user: "alice", tokens: 50, costUsd: 0.5 }, { user: "bob", tokens: 0, costUsd: 0 }] }, "t");
    const s = agg.summary();
    expect(s.totals.hosts).toBe(2);
    expect(s.totals.tokens).toBe(150);
    expect(s.users.find((u) => u.user === "alice")!.tokens).toBe(150);
  });
  it("is idempotent per host (latest snapshot wins)", () => {
    const agg = new FleetAggregator();
    agg.ingest({ host: "h", tokens: 100 }, "t");
    agg.ingest({ host: "h", tokens: 250 }, "t");
    expect(agg.summary().totals.tokens).toBe(250);
  });
  it("builds a report from a budget snapshot", () => {
    const snap = { total: { tokens: 42, costUsd: 0.1, requests: 3 }, users: [{ user: "x", tokens: 42, costUsd: 0.1, requests: 3 }] } as unknown as BudgetSnapshot;
    expect(reportFromBudget("host-a", snap)).toMatchObject({ host: "host-a", tokens: 42, requests: 3 });
  });
});

describe("MCP security", () => {
  const rpc = (method: string, name?: string) => ({ jsonrpc: "2.0", id: 1, method, params: name ? { name, arguments: {} } : {} });
  it("detects MCP JSON-RPC and tool names", () => {
    expect(isMcp(rpc("tools/call", "shell"))).toBe(true);
    expect(isMcp({ messages: [] })).toBe(false);
    expect(mcpToolName(rpc("tools/call", "delete_file"))).toBe("delete_file");
  });
  it("denies tools on the deny-list", () => {
    expect(mcpDenied(rpc("tools/call", "shell"), ["shell", "rm"])).toBe("shell");
    expect(mcpDenied(rpc("tools/call", "read_docs"), ["shell"])).toBeNull();
  });
});

describe("expanded recognizer (orgs + locations)", () => {
  const s = new Scrubber(DEFAULT_CONFIG);
  const types = (t: string) => new Set(s.detect(t).map((m) => m.type));
  it("detects organizations", () => {
    expect(types("invoice from Globex Corp today").has("ORGANIZATION")).toBe(true);
    expect(types("Acme Industries LLC signed").has("ORGANIZATION")).toBe(true);
  });
  it("detects city/state/zip locations", () => {
    expect(types("ship to San Francisco, CA 94105").has("LOCATION")).toBe(true);
  });
});
