import { describe, it, expect } from "vitest";
import { estimateTokens, extractUsage, priceFor, costOf, BudgetTracker, identifyUser } from "../src/budget.js";
import type { BudgetConfig } from "../src/types.js";

const base: BudgetConfig = { enabled: true, windowHours: 24, action: "block" };

describe("token estimation & usage extraction", () => {
  it("estimates ~4 chars per token", () => {
    expect(estimateTokens("12345678")).toBe(2);
    expect(estimateTokens("")).toBe(0);
  });

  it("extracts Anthropic usage", () => {
    const u = extractUsage('{"usage":{"input_tokens":10,"output_tokens":25}}');
    expect(u).toEqual({ inputTokens: 10, outputTokens: 25 });
  });

  it("extracts OpenAI usage", () => {
    const u = extractUsage('{"usage":{"prompt_tokens":7,"completion_tokens":13,"total_tokens":20}}');
    expect(u).toEqual({ inputTokens: 7, outputTokens: 13 });
  });

  it("extracts usage from an SSE blob (streaming)", () => {
    const sse = 'event: message_start\ndata: {"message":{"usage":{"input_tokens":100}}}\n\n' +
      'event: message_delta\ndata: {"usage":{"output_tokens":40}}\n\n';
    expect(extractUsage(sse)).toEqual({ inputTokens: 100, outputTokens: 40 });
  });

  it("returns null when there is no usage", () => {
    expect(extractUsage("no tokens here")).toBeNull();
  });
});

describe("pricing", () => {
  it("matches the most specific model key", () => {
    expect(priceFor("claude-opus-4-8", base)?.input).toBe(15);
    expect(priceFor("gpt-4o-mini", base)?.input).toBe(0.15);
    expect(priceFor("gpt-4o", base)?.input).toBe(2.5);
  });
  it("computes cost from usage", () => {
    // opus: $15/1M in, $75/1M out → 1000 in + 1000 out = 0.015 + 0.075
    expect(costOf("claude-opus", { inputTokens: 1000, outputTokens: 1000 }, base)).toBeCloseTo(0.09, 6);
  });
  it("returns 0 for unknown models", () => {
    expect(costOf("mystery-model", { inputTokens: 1000, outputTokens: 1000 }, base)).toBe(0);
  });
  it("honours config price overrides", () => {
    const cfg: BudgetConfig = { ...base, pricing: { "mystery-model": { input: 1, output: 2 } } };
    expect(costOf("mystery-model-v2", { inputTokens: 1_000_000, outputTokens: 0 }, cfg)).toBe(1);
  });
});

describe("BudgetTracker enforcement", () => {
  it("blocks a single request over the per-request cap", () => {
    const t = new BudgetTracker({ ...base, maxRequestTokens: 100 });
    expect(t.check("api.openai.com", 50).ok).toBe(true);
    expect(t.check("api.openai.com", 500).ok).toBe(false);
  });

  it("blocks once the window token budget would be exceeded", () => {
    const t = new BudgetTracker({ ...base, maxTokens: 1000 });
    t.record("api.anthropic.com", { inputTokens: 600, outputTokens: 300 }, "claude-opus"); // 900 used
    expect(t.check("api.anthropic.com", 50).ok).toBe(true);
    expect(t.check("api.anthropic.com", 200).ok).toBe(false); // 900 + 200 > 1000
  });

  it("enforces per-service limits", () => {
    const t = new BudgetTracker({ ...base, perService: { "api.openai.com": { maxTokens: 100 } } });
    t.record("api.openai.com", { inputTokens: 90, outputTokens: 0 }, "gpt-4o");
    expect(t.check("api.openai.com", 50).ok).toBe(false);
    expect(t.check("api.anthropic.com", 50).ok).toBe(true); // other service unaffected
  });

  it("resets after the rolling window elapses", () => {
    let now = 0;
    const t = new BudgetTracker({ ...base, windowHours: 1, maxTokens: 100 }, () => now);
    t.record("svc", { inputTokens: 90, outputTokens: 0 }, undefined);
    expect(t.check("svc", 50).ok).toBe(false);
    now = 2 * 3600 * 1000; // 2h later → window rolled
    expect(t.check("svc", 50).ok).toBe(true);
  });

  it("snapshot reports totals and per-service spend", () => {
    const t = new BudgetTracker({ ...base, maxTokens: 1000 });
    t.record("api.openai.com", { inputTokens: 100, outputTokens: 50 }, "gpt-4o");
    const s = t.snapshot();
    expect(s.total.tokens).toBe(150);
    expect(s.total.requests).toBe(1);
    expect(s.services[0]!.service).toBe("api.openai.com");
    expect(s.limits.maxTokens).toBe(1000);
  });
});

describe("per-employee identification", () => {
  it("prefers the configured identity header", () => {
    const cfg: BudgetConfig = { ...base, identifyHeader: "x-aegis-user" };
    expect(identifyUser({ "x-aegis-user": "alice" }, cfg)).toBe("alice");
  });
  it("falls back to a stable API-key fingerprint (never the key itself)", () => {
    const u1 = identifyUser({ authorization: "Bearer sk-secret-123" }, base);
    const u2 = identifyUser({ authorization: "Bearer sk-secret-123" }, base);
    const u3 = identifyUser({ authorization: "Bearer sk-other-456" }, base);
    expect(u1).toMatch(/^key:[0-9a-f]{8}$/);
    expect(u1).toBe(u2); // stable
    expect(u1).not.toBe(u3); // different key -> different employee
    expect(u1).not.toContain("sk-secret-123"); // key not exposed
  });
});

describe("per-employee budgets", () => {
  it("tracks and caps spend per employee independently", () => {
    const t = new BudgetTracker({ ...base, maxUserTokens: 100 });
    t.record("api.openai.com", { inputTokens: 60, outputTokens: 30 }, "gpt-4o", "alice"); // alice=90
    expect(t.check("api.openai.com", 50, 0, "alice").ok).toBe(false); // 90+50 > 100
    expect(t.check("api.openai.com", 50, 0, "bob").ok).toBe(true); // bob fresh
    const s = t.snapshot();
    expect(s.users.find((u) => u.user === "alice")!.tokens).toBe(90);
  });
  it("honours per-user overrides", () => {
    const t = new BudgetTracker({ ...base, maxUserTokens: 100, perUser: { alice: { maxTokens: 1000 } } });
    t.record("svc", { inputTokens: 200, outputTokens: 0 }, undefined, "alice");
    expect(t.check("svc", 50, 0, "alice").ok).toBe(true); // alice has a higher cap
  });
});
