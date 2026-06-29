import { describe, it, expect } from "vitest";
import { optimizeText } from "../src/optimize.js";
import { scrubRequestBody } from "../src/messages.js";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";

describe("prompt optimizer", () => {
  it("is a no-op when disabled", () => {
    const text = "a\n\n\n\nb   ";
    const r = optimizeText(text, { enabled: false });
    expect(r.text).toBe(text);
    expect(r.saved).toBe(0);
  });

  it("conservative: strips trailing whitespace and collapses blank lines", () => {
    const r = optimizeText("line one   \n\n\n\nline two\t\t\n", { enabled: true });
    expect(r.text).toBe("line one\n\nline two");
    expect(r.saved).toBeGreaterThan(0);
  });

  it("converges (idempotent) — optimizing twice changes nothing the second time", () => {
    const once = optimizeText("x   \n\n\n\ny", { enabled: true }).text;
    const twice = optimizeText(once, { enabled: true });
    expect(twice.text).toBe(once);
  });

  it("aggressive: removes blank lines and collapses inline spaces but keeps indentation", () => {
    const src = "  def foo():\n      return     1\n\n\n  done";
    const r = optimizeText(src, { enabled: true, aggressive: true });
    expect(r.text).toContain("      return 1"); // internal indent kept, run collapsed
    expect(r.text).toContain("\n  done"); // internal indent preserved
    expect(r.text).not.toMatch(/\n\s*\n/); // no blank lines
    expect(r.saved).toBeGreaterThan(0);
  });

  it("leaves already-minimal text unchanged", () => {
    const r = optimizeText("hello world", { enabled: true, aggressive: true });
    expect(r.text).toBe("hello world");
    expect(r.saved).toBe(0);
  });

  it("applies through scrubRequestBody as a post-scrub transform on content", () => {
    const scrubber = new Scrubber(DEFAULT_CONFIG);
    const opt = (s: string): string => optimizeText(s, { enabled: true }).text;
    const body = { model: "claude-opus-4-8", messages: [{ role: "user", content: "hi   \n\n\n\nthere" }] };
    const { body: out } = scrubRequestBody(body, "anthropic", scrubber, new Vault(), opt) as any;
    expect(out.messages[0].content).toBe("hi\n\nthere");
    expect(out.model).toBe("claude-opus-4-8"); // structural field untouched
  });
});
