/**
 * Local prompt compression — reduces the tokens sent to the AI WITHOUT calling
 * any model (consistent with Aegis staying offline). It applies a set of safe,
 * lossless-for-meaning text passes in a LOOP until the text stops shrinking
 * (convergence) or a pass cap is hit. Opt-in via config.optimize.
 *
 * Conservative passes (default) only touch insignificant whitespace. The
 * aggressive set additionally removes blank lines and collapses internal runs of
 * spaces/tabs — bigger savings, but it can affect intentionally-aligned text
 * (tables/ASCII art), so it is off by default.
 */
import { estimateTokens } from "./budget.js";
import type { OptimizeConfig } from "./types.js";

type Pass = (s: string) => string;

const CONSERVATIVE: Pass[] = [
  (s) => s.replace(/[ \t]+$/gm, ""), // strip trailing whitespace per line
  (s) => s.replace(/\n{3,}/g, "\n\n"), // collapse 3+ blank lines to one paragraph break
  (s) => s.replace(/^\s+|\s+$/g, ""), // trim the whole text
];

const AGGRESSIVE: Pass[] = [
  (s) => s.replace(/\t/g, " "), // tabs -> single space
  (s) => s.replace(/([^\n ]) {2,}/g, "$1 "), // collapse internal space runs (keep indent)
  (s) => s.replace(/\n[ \t]*\n/g, "\n"), // remove blank lines entirely
];

export interface OptimizeResult {
  text: string;
  passes: number;
  beforeTokens: number;
  afterTokens: number;
  saved: number;
}

/** Loop the passes until the text is stable (or maxPasses), then report savings. */
export function optimizeText(text: string, opts: OptimizeConfig): OptimizeResult {
  const before = estimateTokens(text);
  if (!text || !opts.enabled) {
    return { text, passes: 0, beforeTokens: before, afterTokens: before, saved: 0 };
  }

  const fns = opts.aggressive ? [...CONSERVATIVE, ...AGGRESSIVE] : CONSERVATIVE;
  const max = Math.max(1, opts.maxPasses ?? 4);
  let cur = text;
  let passes = 0;
  for (let i = 0; i < max; i++) {
    const next = fns.reduce((t, f) => f(t), cur);
    passes++;
    if (next === cur) break; // converged
    cur = next;
  }

  const after = estimateTokens(cur);
  return { text: cur, passes, beforeTokens: before, afterTokens: after, saved: Math.max(0, before - after) };
}
