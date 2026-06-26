import type { AegisConfig, Category, DetectionSummary, Detector, RawMatch, Severity } from "../types.js";
import { Vault } from "./placeholders.js";
import { secretsDetector } from "./detectors/secrets.js";
import { piiDetector } from "./detectors/pii.js";
import { identityDetector } from "./detectors/identity.js";
import { makeNerDetector } from "./detectors/ner.js";
import { networkDetector } from "./detectors/network.js";
import { makeDictionaryDetector } from "./detectors/dictionary.js";
import { makeCodeDetector } from "./detectors/code.js";
import { entropyDetector } from "./detectors/entropy.js";

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export interface ScrubResult {
  text: string;
  matches: RawMatch[];
}

/** Drop overlapping matches, preferring earlier start then longer span. */
export function resolveOverlaps(matches: RawMatch[]): RawMatch[] {
  const sorted = [...matches].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: RawMatch[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      kept.push(m);
      lastEnd = m.end;
    }
  }
  return kept;
}

export function summarize(matches: RawMatch[]): DetectionSummary {
  const byCategory: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let highest: Severity | null = null;

  for (const m of matches) {
    byCategory[m.category] = (byCategory[m.category] ?? 0) + 1;
    byType[m.type] = (byType[m.type] ?? 0) + 1;
    bySeverity[m.severity] = (bySeverity[m.severity] ?? 0) + 1;
    if (!highest || SEVERITY_RANK[m.severity] > SEVERITY_RANK[highest]) highest = m.severity;
  }

  return {
    total: matches.length,
    byCategory,
    byType,
    bySeverity,
    highestSeverity: highest,
    categoriesPresent: Object.keys(byCategory) as Category[],
  };
}

/**
 * The Scrubber owns the active set of detectors (built from config) and applies
 * them to text. Each call to `scrub` uses a caller-supplied Vault so that the
 * same placeholders can later be restored in the response.
 */
/** Build allowlist matchers from literal strings or /regex/ entries. */
function buildAllow(entries: string[] = []): Array<(v: string) => boolean> {
  const out: Array<(v: string) => boolean> = [];
  for (const e of entries) {
    if (e.length > 1 && e.startsWith("/") && e.endsWith("/")) {
      try {
        const re = new RegExp(e.slice(1, -1));
        out.push((v) => re.test(v));
        continue;
      } catch {
        /* fall through to literal */
      }
    }
    out.push((v) => v === e);
  }
  return out;
}

export class Scrubber {
  private detectors: Detector[];
  private allow: Array<(v: string) => boolean>;

  constructor(cfg: AegisConfig) {
    this.allow = buildAllow(cfg.allowlist);
    const d: Detector[] = [];
    if (cfg.detectors.secrets) d.push(secretsDetector);
    if (cfg.detectors.pii) d.push(piiDetector);
    if (cfg.detectors.identity) d.push(identityDetector);
    if (cfg.nerCommand) d.push(makeNerDetector(cfg.nerCommand));
    if (cfg.detectors.network) d.push(networkDetector);
    if (cfg.detectors.dictionary) d.push(makeDictionaryDetector(cfg.dictionary));
    if (cfg.detectors.code) d.push(makeCodeDetector(cfg.code.markers, cfg.code.internalNamespaces));
    if (cfg.detectors.entropy) d.push(entropyDetector);
    this.detectors = d;
  }

  /** Detect without mutating — used by `aegis scan` and block-mode decisions. */
  detect(text: string): RawMatch[] {
    if (!text) return [];
    const all: RawMatch[] = [];
    for (const det of this.detectors) all.push(...det.run(text));
    const resolved = resolveOverlaps(all);
    if (this.allow.length === 0) return resolved;
    return resolved.filter((m) => !this.allow.some((fn) => fn(m.value)));
  }

  /** Replace every detected value with a stable placeholder from the vault. */
  scrub(text: string, vault: Vault): ScrubResult {
    const matches = this.detect(text);
    if (matches.length === 0) return { text, matches };

    // Apply replacements right-to-left so earlier offsets stay valid.
    let out = text;
    for (const m of [...matches].sort((a, b) => b.start - a.start)) {
      const token = vault.placeholderFor(m.value, m.type);
      out = out.slice(0, m.start) + token + out.slice(m.end);
    }
    return { text: out, matches };
  }
}

export { Vault };
