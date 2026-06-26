/**
 * Policy-as-code decision engine.
 *
 * Resolves the effective action for a request from layered rules:
 *   1. per-category action overrides (`categoryActions`)
 *   2. per-route mode (a route's own `mode`)
 *   3. the global `mode`
 *   4. `blockOn` categories always escalate to block (backward compatible)
 *
 * When a request contains several categories, the STRICTEST action wins
 * (block > redact > warn).
 */
import type { AegisConfig, Category, Mode, RawMatch } from "./types.js";

export type Decision = "block" | "redact" | "warn" | "clean";

const RANK: Record<Mode, number> = { warn: 0, redact: 1, block: 2 };

/** The action that applies to a single detected category. */
export function effectiveAction(category: Category, cfg: AegisConfig, routeMode: Mode): Mode {
  if (cfg.blockOn?.includes(category)) return "block";
  const override = cfg.categoryActions?.[category];
  return override ?? routeMode;
}

/** The overall decision for a set of matches (strictest category wins). */
export function decide(matches: RawMatch[], cfg: AegisConfig, routeMode: Mode): Decision {
  if (matches.length === 0) return "clean";
  let worst: Mode | null = null;
  for (const m of matches) {
    const a = effectiveAction(m.category, cfg, routeMode);
    if (worst === null || RANK[a] > RANK[worst]) worst = a;
  }
  return worst ?? "warn";
}
