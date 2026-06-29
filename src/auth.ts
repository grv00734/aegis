/**
 * Role-based access control for the Aegis control plane (dashboard API, config
 * changes, fleet collector). Two ways to authenticate a caller:
 *
 *   1. Static API tokens mapped to roles (config.auth.tokens).
 *   2. SSO via a bearer JWT — verified locally with HS256 (shared secret) or
 *      RS256 (the IdP's public key). A configurable claim maps to a role. This
 *      is the integration point for Okta/Entra/Auth0/etc. without a heavyweight
 *      SAML stack.
 *
 * Roles are ordered: viewer < operator < admin. Permissions:
 *   - read      (status, scan, audit, report)       -> viewer+
 *   - control   (start/stop proxies)                 -> operator+
 *   - configure (change policy/detectors/budget)     -> admin
 */
import { createHmac, createVerify, timingSafeEqual } from "node:crypto";

export type Role = "viewer" | "operator" | "admin";
export type Action = "read" | "control" | "configure";

export interface JwtConfig {
  algorithm?: "HS256" | "RS256";
  secret?: string; // HS256
  publicKeyPem?: string; // RS256
  issuer?: string;
  audience?: string;
  roleClaim?: string; // default "role"
  roleMap?: Record<string, Role>; // map a claim value -> role
}

export interface AuthConfig {
  enabled: boolean;
  /** token string -> role */
  tokens?: Record<string, Role>;
  jwt?: JwtConfig;
}

export interface Principal {
  role: Role;
  subject: string;
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
const ACTION_NEED: Record<Action, number> = { read: 0, control: 1, configure: 2 };

export function can(role: Role, action: Action): boolean {
  return ROLE_RANK[role] >= ACTION_NEED[action];
}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Verify a JWT locally and return its payload, or null if invalid/expired. */
export function verifyJwt(token: string, cfg: JwtConfig, nowSec = Math.floor(Date.now() / 1000)): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  let header: { alg?: string };
  try {
    header = JSON.parse(b64urlToBuf(h).toString("utf8"));
  } catch {
    return null;
  }
  const alg = header.alg;
  if (cfg.algorithm && cfg.algorithm !== alg) return null;
  const signingInput = `${h}.${p}`;
  const sig = b64urlToBuf(s);

  if (alg === "HS256") {
    if (!cfg.secret) return null;
    const expected = createHmac("sha256", cfg.secret).update(signingInput).digest();
    if (expected.length !== sig.length || !timingSafeEqual(expected, sig)) return null;
  } else if (alg === "RS256") {
    if (!cfg.publicKeyPem) return null;
    const ok = createVerify("RSA-SHA256").update(signingInput).verify(cfg.publicKeyPem, sig);
    if (!ok) return null;
  } else {
    return null;
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(b64urlToBuf(p).toString("utf8"));
  } catch {
    return null;
  }
  if (typeof payload.exp === "number" && nowSec > payload.exp) return null;
  if (typeof payload.nbf === "number" && nowSec < payload.nbf) return null;
  if (cfg.issuer && payload.iss !== cfg.issuer) return null;
  if (cfg.audience && payload.aud !== cfg.audience) return null;
  return payload;
}

function roleFromPayload(payload: Record<string, unknown>, cfg: JwtConfig): Role {
  const claim = cfg.roleClaim ?? "role";
  const raw = payload[claim];
  const value = Array.isArray(raw) ? String(raw[0]) : String(raw ?? "");
  if (cfg.roleMap && cfg.roleMap[value]) return cfg.roleMap[value];
  if (value === "admin" || value === "operator" || value === "viewer") return value;
  return "viewer";
}

/** Resolve the caller's principal from request headers, or null if unauthenticated. */
export function authenticate(headers: Record<string, unknown>, cfg: AuthConfig): Principal | null {
  const raw = headers["authorization"] ?? headers["x-aegis-token"];
  const header = String(Array.isArray(raw) ? raw[0] : (raw ?? ""));
  const token = header.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;

  if (cfg.tokens && cfg.tokens[token]) return { role: cfg.tokens[token], subject: "token" };

  if (cfg.jwt) {
    const payload = verifyJwt(token, cfg.jwt);
    if (payload) return { role: roleFromPayload(payload, cfg.jwt), subject: String(payload.sub ?? "jwt") };
  }
  return null;
}
