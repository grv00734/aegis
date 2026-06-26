import { describe, it, expect } from "vitest";
import { decide, effectiveAction } from "../src/policy.js";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { AegisConfig, RawMatch } from "../src/types.js";

function cfg(over: Partial<AegisConfig> = {}): AegisConfig {
  return { ...DEFAULT_CONFIG, ...over };
}
function m(category: RawMatch["category"]): RawMatch {
  return { start: 0, end: 1, value: "x", type: "T", category, severity: "high" };
}

describe("policy decision engine", () => {
  it("uses the global mode by default", () => {
    expect(decide([m("pii")], cfg({ mode: "redact", blockOn: [] }), "redact")).toBe("redact");
    expect(decide([m("pii")], cfg({ mode: "warn", blockOn: [] }), "warn")).toBe("warn");
  });

  it("returns clean when there are no matches", () => {
    expect(decide([], cfg(), "redact")).toBe("clean");
  });

  it("escalates blockOn categories to block", () => {
    expect(decide([m("secret")], cfg({ mode: "redact", blockOn: ["secret"] }), "redact")).toBe("block");
  });

  it("applies per-category action overrides", () => {
    const c = cfg({ mode: "warn", blockOn: [], categoryActions: { secret: "block", pii: "redact" } });
    expect(effectiveAction("secret", c, "warn")).toBe("block");
    expect(effectiveAction("pii", c, "warn")).toBe("redact");
    expect(effectiveAction("network", c, "warn")).toBe("warn"); // falls back to route/global mode
  });

  it("picks the strictest action across mixed categories", () => {
    const c = cfg({ mode: "warn", blockOn: [], categoryActions: { secret: "block", pii: "redact" } });
    expect(decide([m("pii"), m("secret"), m("network")], c, "warn")).toBe("block");
    expect(decide([m("pii"), m("network")], c, "warn")).toBe("redact");
  });

  it("honours a per-route mode over the global mode", () => {
    const c = cfg({ mode: "warn", blockOn: [] });
    expect(decide([m("pii")], c, "block")).toBe("block"); // routeMode = block
  });
});

describe("allowlist suppression", () => {
  it("suppresses an exact literal value", () => {
    const s = new Scrubber(cfg({ allowlist: ["AKIAIOSFODNN7EXAMPLE"] }));
    expect(s.detect("key AKIAIOSFODNN7EXAMPLE").length).toBe(0);
  });

  it("suppresses by /regex/", () => {
    const s = new Scrubber(cfg({ allowlist: ["/EXAMPLE$/"] }));
    expect(s.detect("key AKIAIOSFODNN7EXAMPLE").some((x) => x.type === "AWS_ACCESS_KEY")).toBe(false);
  });

  it("still flags real values not on the allowlist", () => {
    const s = new Scrubber(cfg({ allowlist: ["AKIAIOSFODNN7EXAMPLE"] }));
    expect(s.detect("key AKIA1234567890ABCDEF").some((x) => x.type === "AWS_ACCESS_KEY")).toBe(true);
  });
});
