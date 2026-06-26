import type { Detector, RawMatch } from "../../types.js";

/**
 * Entropy-based detection of novel, un-templated secrets — high-randomness
 * tokens that the pattern detectors don't know about (custom API keys, session
 * tokens, generated credentials). Opt-in (`detectors.entropy`) because, by
 * nature, it is less precise than the specific patterns.
 *
 * Heuristics to keep false positives down: a candidate must be long, mix letters
 * and digits, and clear a Shannon-entropy threshold (random base64/hex easily
 * exceeds it; English prose does not).
 */
const MIN_LEN = 24;
const MIN_ENTROPY = 4.0; // bits/char
const TOKEN = /[A-Za-z0-9+/_=-]{24,}/g;

function shannon(s: string): number {
  const counts: Record<string, number> = {};
  for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
  let e = 0;
  for (const k in counts) {
    const p = counts[k]! / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export const entropyDetector: Detector = {
  name: "entropy",
  category: "secret",
  run(text: string): RawMatch[] {
    const out: RawMatch[] = [];
    for (const m of text.matchAll(TOKEN)) {
      const value = m[0];
      if (value.length < MIN_LEN) continue;
      if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) continue; // mixed classes
      if (shannon(value) < MIN_ENTROPY) continue;
      const start = m.index ?? 0;
      out.push({
        start,
        end: start + value.length,
        value,
        type: "HIGH_ENTROPY",
        category: "secret",
        severity: "medium",
      });
    }
    return out;
  },
};
