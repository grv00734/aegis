/**
 * Shared types for the Aegis DLP guard layer.
 */

export type Category = "secret" | "pii" | "network" | "dictionary" | "code";

export type Severity = "low" | "medium" | "high" | "critical";

/** A raw hit produced by a detector before overlap resolution. */
export interface RawMatch {
  /** Inclusive start offset into the scanned text. */
  start: number;
  /** Exclusive end offset into the scanned text. */
  end: number;
  /** The exact substring to redact. */
  value: string;
  /** Specific detector label, e.g. "AWS_ACCESS_KEY", "EMAIL". */
  type: string;
  category: Category;
  severity: Severity;
}

/** A detector scans text and reports raw matches. Detectors must be pure and offline. */
export interface Detector {
  name: string;
  category: Category;
  run(text: string): RawMatch[];
}

export type Mode = "redact" | "block" | "warn";

export type RouteFormat = "anthropic" | "openai" | "gemini" | "passthrough";

export interface OptimizeConfig {
  enabled: boolean;
  /** Also remove blank lines and collapse internal whitespace (bigger savings). */
  aggressive?: boolean;
  /** Max convergence iterations (default 4). */
  maxPasses?: number;
}

export interface RouteConfig {
  matchPrefix: string;
  upstream: string;
  format: RouteFormat;
  /** Per-route action override; falls back to the global mode. */
  mode?: Mode;
}

export interface AegisConfig {
  port: number;
  host: string;
  mode: Mode;
  /** If a match in any of these categories is found, the request is blocked regardless of mode. */
  blockOn: Category[];
  /** Per-category action overrides, e.g. { secret: "block", pii: "redact" }. */
  categoryActions?: Partial<Record<Category, Mode>>;
  /** Literal values or /regex/ strings to never flag (false-positive suppression). */
  allowlist?: string[];
  detectors: {
    secrets: boolean;
    pii: boolean;
    /** Context-aware PII: names, addresses, DOB, IBAN, passport. */
    identity: boolean;
    network: boolean;
    dictionary: boolean;
    code: boolean;
    /** Entropy-based detection of novel secrets (opt-in; higher false positives). */
    entropy: boolean;
  };
  /** Optional local NER command for context-aware PII (offline). */
  nerCommand?: string;
  /** Also scan AI responses for newly introduced secrets/PII. */
  scanResponses?: boolean;
  /** Shared policy file (a partial config) merged over local settings, so a
   * security team can centrally govern dictionary/mode/detectors across machines. */
  policyFile?: string;
  /** Token / cost spend control across AI services. */
  budget?: BudgetConfig;
  /** Encrypt confidential values (AES-256-GCM, local key) instead of using index
   * placeholders. The ciphertext is sent to the AI and decrypted on the response. */
  encryption?: { enabled: boolean };
  /** Local prompt compression to cut tokens before requests leave (no AI calls). */
  optimize?: OptimizeConfig;
  /** RBAC / SSO for the control plane (dashboard API, config, fleet). */
  auth?: import("./auth.js").AuthConfig;
  /** Report audit/spend to a central fleet collector. */
  fleet?: { url?: string; token?: string };
  /** MCP (Model Context Protocol) tool security. */
  mcp?: { deniedTools?: string[] };
  dictionary: string[];
  code: {
    markers: string[];
    internalNamespaces: string[];
  };
  routes: RouteConfig[];
  defaultUpstream?: string;
  auditLog?: string;
  /** Transparent HTTPS-intercepting proxy ("system proxy") settings. */
  mitm: {
    /** Port the CONNECT proxy listens on. */
    port: number;
    /** Port for OS-redirected (iptables) connections in transparent mode. */
    transparentPort: number;
    /** Hostnames to decrypt + scrub. Everything else is blind-tunnelled untouched. */
    hosts: string[];
  };
}

/** Token / cost spend control. Limits apply over a rolling window. */
export interface BudgetConfig {
  enabled: boolean;
  /** Rolling window length in hours (default 24). */
  windowHours: number;
  /** What to do when a limit would be exceeded. */
  action: "block" | "warn";
  /** Total tokens allowed per window across all services. */
  maxTokens?: number;
  /** Total cost (USD) allowed per window across all services. */
  maxCostUsd?: number;
  /** Hard cap on a single request's estimated tokens. */
  maxRequestTokens?: number;
  /** Per-service overrides, keyed by upstream host (e.g. "api.openai.com"). */
  perService?: Record<string, { maxTokens?: number; maxCostUsd?: number }>;
  /** Override price table: model-name substring -> USD per 1M input/output tokens. */
  pricing?: Record<string, { input: number; output: number }>;
  /** Request header that identifies the employee (e.g. "x-aegis-user"). If
   * absent on a request, Aegis falls back to an API-key fingerprint, then the
   * OS user. */
  identifyHeader?: string;
  /** Default per-employee caps (applied to every user without a perUser entry). */
  maxUserTokens?: number;
  maxUserCostUsd?: number;
  /** Per-employee overrides, keyed by the resolved user id. */
  perUser?: Record<string, { maxTokens?: number; maxCostUsd?: number }>;
}

/** Summary of what was found in a single request — counts only, never values. */
export interface DetectionSummary {
  total: number;
  byCategory: Record<string, number>;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  highestSeverity: Severity | null;
  categoriesPresent: Category[];
}
