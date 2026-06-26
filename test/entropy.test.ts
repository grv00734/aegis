import { describe, it, expect } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { AegisConfig } from "../src/types.js";

function withEntropy(on: boolean): AegisConfig {
  return { ...DEFAULT_CONFIG, detectors: { ...DEFAULT_CONFIG.detectors, entropy: on } };
}

describe("entropy detector", () => {
  it("is off by default", () => {
    const s = new Scrubber(DEFAULT_CONFIG);
    expect(s.detect("token kF9xQ2mL7pR4tV8wZ1nB6cD3eH5jA0sG2yU").some((m) => m.type === "HIGH_ENTROPY")).toBe(false);
  });

  it("flags a novel high-entropy token when enabled", () => {
    const s = new Scrubber(withEntropy(true));
    expect(s.detect("token kF9xQ2mL7pR4tV8wZ1nB6cD3eH5jA0sG2yU").some((m) => m.type === "HIGH_ENTROPY")).toBe(true);
  });

  it("does not flag ordinary prose", () => {
    const s = new Scrubber(withEntropy(true));
    const prose = "The quick brown fox jumps over the lazy dog every single morning without fail.";
    expect(s.detect(prose).some((m) => m.type === "HIGH_ENTROPY")).toBe(false);
  });

  it("ignores long all-letter words (no digits)", () => {
    const s = new Scrubber(withEntropy(true));
    expect(s.detect("supercalifragilisticexpialidociousss").some((m) => m.type === "HIGH_ENTROPY")).toBe(false);
  });
});
