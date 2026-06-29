import { appendFile } from "node:fs/promises";
import type { DetectionSummary, Mode } from "./types.js";

export type Action = "redacted" | "blocked" | "warned" | "clean";

export interface AuditEntry {
  ts: string;
  route: string;
  format: string;
  mode: Mode;
  action: Action;
  summary: DetectionSummary;
  /** "request" (outbound, default) or "response" (secrets in AI output). */
  direction?: "request" | "response";
  /** Free-text note for non-DLP events (e.g. a budget block reason). */
  note?: string;
  /** Tokens saved by prompt optimization on this request, if any. */
  savedTokens?: number;
}

/**
 * Append-only audit trail. We deliberately record only counts, types, and
 * severities — never the matched values or their placeholders. The log is safe
 * to ship to a SIEM without leaking the very data we are protecting.
 */
export class AuditLog {
  /**
   * @param path  optional JSONL file to append entries to.
   * @param sink  optional callback that receives each entry. When provided it
   *              replaces the default console output (used by the VS Code
   *              extension to route findings into an Output channel).
   */
  constructor(
    private path?: string,
    private sink?: (entry: AuditEntry) => void,
  ) {}

  async record(entry: AuditEntry): Promise<void> {
    const { summary, action, route } = entry;

    if (this.sink) {
      this.sink(entry);
    } else if (summary.total > 0 || entry.note || entry.savedTokens) {
      // Surface a one-line summary on the console for live visibility.
      const tag =
        action === "blocked" ? "BLOCK" : action === "redacted" ? "REDACT" : action === "warned" ? "WARN" : "OK";
      const saved = entry.savedTokens ? `  (optimized -${entry.savedTokens} tok)` : "";
      if (entry.note) {
        console.log(`[aegis] ${tag} ${route} — ${entry.note}${saved}`);
      } else if (summary.total > 0) {
        const types = Object.entries(summary.byType)
          .map(([t, n]) => `${t}:${n}`)
          .join(", ");
        console.log(`[aegis] ${tag} ${route} — ${summary.total} finding(s) [${types}]${saved}`);
      } else {
        console.log(`[aegis] OPTIMIZE ${route} —${saved}`);
      }
    }

    if (!this.path) return;
    try {
      await appendFile(this.path, JSON.stringify(entry) + "\n", "utf8");
    } catch (err) {
      console.error(`[aegis] failed to write audit log: ${(err as Error).message}`);
    }
  }
}
