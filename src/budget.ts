/**
 * Token / cost spend control for AI services.
 *
 * The proxy estimates the tokens a request will cost, checks it against a rolling
 * window budget (per service and overall), and — if over — blocks (429) or warns.
 * After the response it records actual usage parsed from the provider's `usage`
 * field (works for Anthropic and OpenAI, streaming or not), falling back to a
 * character-based estimate. Cost is derived from a configurable price table.
 *
 * State is in-memory per running proxy. Nothing about the prompt is stored — only
 * token counts, costs, and the service name.
 */
import { createHash } from "node:crypto";
import { userInfo } from "node:os";
import type { BudgetConfig } from "./types.js";

export interface Usage {
  inputTokens: number;
  outputTokens: number;
}

export interface ServiceSpend {
  service: string;
  tokens: number;
  costUsd: number;
  requests: number;
}

export interface UserSpend {
  user: string;
  tokens: number;
  costUsd: number;
  requests: number;
}

/**
 * Resolve the employee behind a request, without storing any secret:
 *   1. a configured identity header (e.g. "x-aegis-user")
 *   2. else a short fingerprint of the API key (so different keys = different people)
 *   3. else the OS user running the proxy (AEGIS_USER overrides)
 */
export function identifyUser(headers: Record<string, unknown>, cfg: BudgetConfig): string {
  const hdr = cfg.identifyHeader?.toLowerCase();
  if (hdr) {
    const v = headers[hdr];
    if (v) return String(Array.isArray(v) ? v[0] : v);
  }
  const auth = headers["authorization"] ?? headers["x-api-key"] ?? "";
  const authStr = String(Array.isArray(auth) ? auth[0] : auth);
  if (authStr) return "key:" + createHash("sha256").update(authStr).digest("hex").slice(0, 8);
  try {
    return process.env.AEGIS_USER ?? userInfo().username ?? "unknown";
  } catch {
    return process.env.AEGIS_USER ?? "unknown";
  }
}

export interface BudgetSnapshot {
  enabled: true;
  windowHours: number;
  resetAt: string;
  action: "block" | "warn";
  limits: { maxTokens?: number; maxCostUsd?: number; maxRequestTokens?: number; maxUserTokens?: number; maxUserCostUsd?: number };
  total: { tokens: number; costUsd: number; requests: number };
  services: ServiceSpend[];
  users: UserSpend[];
}

/** Rough token estimate: ~4 characters per token (good enough for pre-flight checks). */
export function estimateTokens(text: string): number {
  return Math.ceil((text?.length ?? 0) / 4);
}

/**
 * Pull token usage out of a provider response body (or SSE blob). Matches both
 * Anthropic (input_tokens/output_tokens) and OpenAI (prompt_tokens/completion_tokens),
 * via regex so it works whether the body is one JSON object or a stream of events.
 */
export function extractUsage(raw: string): Usage | null {
  // Covers Anthropic (input/output_tokens), OpenAI + Azure OpenAI
  // (prompt/completion_tokens), AWS Bedrock (input/outputTokenCount),
  // Google Gemini/Vertex (promptTokenCount/candidatesTokenCount), and common
  // Cohere/Mistral variants.
  const inp = raw.match(
    /"(?:input_tokens|prompt_tokens|inputTokenCount|promptTokenCount|prompt_token_count)"\s*:\s*(\d+)/,
  );
  const out = raw.match(
    /"(?:output_tokens|completion_tokens|outputTokenCount|candidatesTokenCount|completion_token_count|generation_tokens)"\s*:\s*(\d+)/,
  );
  if (!inp && !out) return null;
  return {
    inputTokens: inp ? Number(inp[1]) : 0,
    outputTokens: out ? Number(out[1]) : 0,
  };
}

/**
 * Approximate USD per 1M tokens, by model-name substring. These are estimates
 * for budgeting only — override per deployment via config.budget.pricing. Azure
 * OpenAI reuses the OpenAI model names. Match is longest-substring-wins.
 */
const DEFAULT_PRICING: Record<string, { input: number; output: number }> = {
  // Anthropic (direct or via Bedrock/Vertex)
  "claude-3-opus": { input: 15, output: 75 },
  opus: { input: 15, output: 75 },
  sonnet: { input: 3, output: 15 },
  haiku: { input: 0.8, output: 4 },
  // OpenAI + Azure OpenAI
  "gpt-4o-mini": { input: 0.15, output: 0.6 },
  "gpt-4o": { input: 2.5, output: 10 },
  "gpt-4": { input: 10, output: 30 },
  "gpt-3.5": { input: 0.5, output: 1.5 },
  o1: { input: 15, output: 60 },
  "o3-mini": { input: 1.1, output: 4.4 },
  // Google Gemini / Vertex
  "gemini-1.5-pro": { input: 1.25, output: 5 },
  "gemini-1.5-flash": { input: 0.075, output: 0.3 },
  "gemini-2.0-flash": { input: 0.1, output: 0.4 },
  gemini: { input: 0.5, output: 1.5 },
  // Mistral
  "mistral-large": { input: 2, output: 6 },
  "mistral-small": { input: 0.2, output: 0.6 },
  mistral: { input: 1, output: 3 },
  // Cohere
  "command-r-plus": { input: 2.5, output: 10 },
  "command-r": { input: 0.15, output: 0.6 },
  command: { input: 1, output: 2 },
  // Meta Llama / AWS Titan / DeepSeek (Bedrock & others)
  llama: { input: 0.3, output: 0.6 },
  titan: { input: 0.2, output: 0.6 },
  deepseek: { input: 0.14, output: 0.28 },
};

export function priceFor(model: string | undefined, cfg: BudgetConfig): { input: number; output: number } | null {
  if (!model) return null;
  const table = { ...DEFAULT_PRICING, ...(cfg.pricing ?? {}) };
  const m = model.toLowerCase();
  let best: { input: number; output: number } | null = null;
  let bestLen = -1;
  for (const key of Object.keys(table)) {
    if (m.includes(key) && key.length > bestLen) {
      best = table[key]!;
      bestLen = key.length;
    }
  }
  return best;
}

export function costOf(model: string | undefined, usage: Usage, cfg: BudgetConfig): number {
  const p = priceFor(model, cfg);
  if (!p) return 0;
  return (usage.inputTokens * p.input + usage.outputTokens * p.output) / 1_000_000;
}

export interface CheckResult {
  ok: boolean;
  reason?: string;
}

export class BudgetTracker {
  private windowMs: number;
  private start: number;
  private services = new Map<string, ServiceSpend>();
  private users = new Map<string, UserSpend>();

  constructor(
    private cfg: BudgetConfig,
    private now: () => number = () => Date.now(),
  ) {
    this.windowMs = (cfg.windowHours || 24) * 3600 * 1000;
    this.start = this.now();
  }

  private roll(): void {
    if (this.now() - this.start >= this.windowMs) {
      this.services.clear();
      this.users.clear();
      this.start = this.now();
    }
  }

  private svc(service: string): ServiceSpend {
    let e = this.services.get(service);
    if (!e) {
      e = { service, tokens: 0, costUsd: 0, requests: 0 };
      this.services.set(service, e);
    }
    return e;
  }

  private usr(user: string): UserSpend {
    let e = this.users.get(user);
    if (!e) {
      e = { user, tokens: 0, costUsd: 0, requests: 0 };
      this.users.set(user, e);
    }
    return e;
  }

  private totals(): { tokens: number; costUsd: number; requests: number } {
    let tokens = 0;
    let costUsd = 0;
    let requests = 0;
    for (const e of this.services.values()) {
      tokens += e.tokens;
      costUsd += e.costUsd;
      requests += e.requests;
    }
    return { tokens, costUsd, requests };
  }

  /** Pre-flight check using an estimate of this request's tokens/cost. */
  check(service: string, estTokens: number, estCost = 0, user?: string): CheckResult {
    this.roll();
    const { maxRequestTokens, maxTokens, maxCostUsd, perService, perUser, maxUserTokens, maxUserCostUsd } = this.cfg;

    if (maxRequestTokens && estTokens > maxRequestTokens) {
      return { ok: false, reason: `request (~${estTokens} tokens) exceeds per-request cap of ${maxRequestTokens}` };
    }
    const t = this.totals();
    if (maxTokens && t.tokens + estTokens > maxTokens) {
      return { ok: false, reason: `window token budget ${maxTokens} would be exceeded (${t.tokens} used)` };
    }
    if (maxCostUsd && t.costUsd + estCost > maxCostUsd) {
      return { ok: false, reason: `window cost budget $${maxCostUsd} would be exceeded ($${t.costUsd.toFixed(2)} used)` };
    }
    const ps = perService?.[service];
    if (ps) {
      const e = this.svc(service);
      if (ps.maxTokens && e.tokens + estTokens > ps.maxTokens) {
        return { ok: false, reason: `service "${service}" token budget ${ps.maxTokens} would be exceeded` };
      }
      if (ps.maxCostUsd && e.costUsd + estCost > ps.maxCostUsd) {
        return { ok: false, reason: `service "${service}" cost budget $${ps.maxCostUsd} would be exceeded` };
      }
    }
    if (user) {
      const pu = perUser?.[user] ?? { maxTokens: maxUserTokens, maxCostUsd: maxUserCostUsd };
      const e = this.usr(user);
      if (pu.maxTokens && e.tokens + estTokens > pu.maxTokens) {
        return { ok: false, reason: `employee "${user}" token budget ${pu.maxTokens} would be exceeded (${e.tokens} used)` };
      }
      if (pu.maxCostUsd && e.costUsd + estCost > pu.maxCostUsd) {
        return { ok: false, reason: `employee "${user}" cost budget $${pu.maxCostUsd} would be exceeded ($${e.costUsd.toFixed(2)} used)` };
      }
    }
    return { ok: true };
  }

  /** Record actual usage after a response, against both the service and the employee. */
  record(service: string, usage: Usage, model: string | undefined, user?: string): void {
    this.roll();
    const tokens = usage.inputTokens + usage.outputTokens;
    const cost = costOf(model, usage, this.cfg);

    const s = this.svc(service);
    s.tokens += tokens;
    s.costUsd += cost;
    s.requests += 1;

    if (user) {
      const u = this.usr(user);
      u.tokens += tokens;
      u.costUsd += cost;
      u.requests += 1;
    }
  }

  snapshot(): BudgetSnapshot {
    this.roll();
    const t = this.totals();
    return {
      enabled: true,
      windowHours: this.cfg.windowHours || 24,
      resetAt: new Date(this.start + this.windowMs).toISOString(),
      action: this.cfg.action,
      limits: {
        maxTokens: this.cfg.maxTokens,
        maxCostUsd: this.cfg.maxCostUsd,
        maxRequestTokens: this.cfg.maxRequestTokens,
        maxUserTokens: this.cfg.maxUserTokens,
        maxUserCostUsd: this.cfg.maxUserCostUsd,
      },
      total: t,
      services: [...this.services.values()].sort((a, b) => b.tokens - a.tokens),
      users: [...this.users.values()].sort((a, b) => b.tokens - a.tokens),
    };
  }
}
