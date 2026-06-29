import { describe, it, expect } from "vitest";
import { extractUsage, priceFor, costOf } from "../src/budget.js";
import { formatForHost } from "../src/mitm.js";
import { scrubRequestBody } from "../src/messages.js";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { BudgetConfig } from "../src/types.js";

const base: BudgetConfig = { enabled: true, windowHours: 24, action: "block" };

describe("multi-provider usage extraction", () => {
  it("Azure OpenAI (OpenAI shape)", () => {
    expect(extractUsage('{"usage":{"prompt_tokens":12,"completion_tokens":8}}')).toEqual({ inputTokens: 12, outputTokens: 8 });
  });
  it("Google Gemini / Vertex", () => {
    expect(extractUsage('{"usageMetadata":{"promptTokenCount":30,"candidatesTokenCount":15,"totalTokenCount":45}}')).toEqual({
      inputTokens: 30,
      outputTokens: 15,
    });
  });
  it("AWS Bedrock invocation metrics", () => {
    expect(extractUsage('{"amazon-bedrock-invocationMetrics":{"inputTokenCount":50,"outputTokenCount":20}}')).toEqual({
      inputTokens: 50,
      outputTokens: 20,
    });
  });
});

describe("multi-provider pricing", () => {
  it("prices Gemini, Mistral, Cohere, Llama", () => {
    expect(priceFor("gemini-1.5-pro-002", base)?.input).toBe(1.25);
    expect(priceFor("mistral-large-latest", base)?.input).toBe(2);
    expect(priceFor("command-r-plus", base)?.input).toBe(2.5);
    expect(priceFor("meta.llama3-70b", base)?.input).toBe(0.3);
  });
  it("Azure uses OpenAI model names", () => {
    expect(costOf("gpt-4o", { inputTokens: 1_000_000, outputTokens: 0 }, base)).toBe(2.5);
  });
  it("falls back to a per-service budget even when the model is unknown (cost 0)", () => {
    expect(costOf("acme-internal-llm-v3", { inputTokens: 1000, outputTokens: 1000 }, base)).toBe(0);
  });
});

describe("host -> request format mapping", () => {
  it("maps providers correctly, ambiguous -> passthrough", () => {
    expect(formatForHost("api.anthropic.com")).toBe("anthropic");
    expect(formatForHost("api.openai.com")).toBe("openai");
    expect(formatForHost("acme.openai.azure.com")).toBe("openai");
    expect(formatForHost("generativelanguage.googleapis.com")).toBe("gemini");
    expect(formatForHost("bedrock-runtime.us-east-1.amazonaws.com")).toBe("passthrough");
    expect(formatForHost("ai-gateway.acme-internal.com")).toBe("passthrough");
  });
});

describe("Gemini request scrubbing", () => {
  const scrubber = new Scrubber(DEFAULT_CONFIG);
  it("scrubs contents[].parts[].text and systemInstruction", () => {
    const body = {
      systemInstruction: { parts: [{ text: "key sk-ant-abcd1234EFGH5678ijklMNOP" }] },
      contents: [{ role: "user", parts: [{ text: "email dev@acme.com" }] }],
      generationConfig: { temperature: 0.2 },
    };
    const { body: out, matches } = scrubRequestBody(body, "gemini", scrubber, new Vault()) as any;
    expect(matches.length).toBeGreaterThanOrEqual(2);
    const s = JSON.stringify(out);
    expect(s).not.toContain("sk-ant-abcd1234EFGH5678ijklMNOP");
    expect(s).not.toContain("dev@acme.com");
    expect(out.generationConfig.temperature).toBe(0.2); // structural field untouched
  });
});

describe("unknown company agent (deep-scrub fallback)", () => {
  const scrubber = new Scrubber(DEFAULT_CONFIG);
  it("still redacts secrets in an arbitrary body shape", () => {
    const body = { prompt: "use ghp_0123456789abcdefghijklmnopqrstuvwxyz12", meta: { who: "dev@acme.com" } };
    const { body: out } = scrubRequestBody(body, "passthrough", scrubber, new Vault()) as any;
    const s = JSON.stringify(out);
    expect(s).not.toContain("ghp_0123456789abcdefghijklmnopqrstuvwxyz12");
    expect(s).not.toContain("dev@acme.com");
  });
});
