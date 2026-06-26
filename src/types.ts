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

export type RouteFormat = "anthropic" | "openai" | "passthrough";

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

/** Summary of what was found in a single request — counts only, never values. */
export interface DetectionSummary {
  total: number;
  byCategory: Record<string, number>;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  highestSeverity: Severity | null;
  categoriesPresent: Category[];
}
