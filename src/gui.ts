/**
 * Local control-panel GUI for Aegis.
 *
 * Serves a single self-contained dashboard page plus a small JSON control API on
 * localhost. From the browser you can start/stop the guard, edit the policy and
 * dictionary, interactively test redaction, and watch live activity. No external
 * dependencies, no build step — the page is inlined below.
 */
import * as http from "node:http";
import type { Server } from "node:http";
import type { AegisConfig } from "./types.js";
import { Scrubber, summarize } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";
import { startServer } from "./server.js";
import { startMitmProxy } from "./mitm.js";
import type { AuditEntry } from "./audit.js";
import { buildReport } from "./report.js";
import { BudgetTracker } from "./budget.js";
import { loadOrCreateKey } from "./crypto.js";
import { optimizeText } from "./optimize.js";
import { dashboardHtml } from "./gui-page.js";

interface SystemHandle {
  server: Server;
  transparentServer?: import("node:net").Server;
}

class GuiState {
  cfg: AegisConfig;
  scrubber: Scrubber;
  base: Server | null = null;
  system: SystemHandle | null = null;
  audit: AuditEntry[] = [];
  sse = new Set<http.ServerResponse>();
  budget?: BudgetTracker;
  encKey?: Buffer;

  constructor(cfg: AegisConfig) {
    this.cfg = cfg;
    this.scrubber = new Scrubber(cfg);
    this.budget = cfg.budget?.enabled ? new BudgetTracker(cfg.budget) : undefined;
    this.encKey = cfg.encryption?.enabled ? loadOrCreateKey() : undefined;
  }

  status(): Record<string, unknown> {
    return {
      base: this.base !== null,
      system: this.system !== null,
      baseUrl: `http://${this.cfg.host}:${this.cfg.port}`,
      systemUrl: `http://${this.cfg.host}:${this.cfg.mitm.port}`,
      mode: this.cfg.mode,
      blockOn: this.cfg.blockOn,
      detectors: this.cfg.detectors,
      dictionary: this.cfg.dictionary,
      categoryActions: this.cfg.categoryActions ?? {},
      allowlist: this.cfg.allowlist ?? [],
      optimize: this.cfg.optimize ?? { enabled: false },
      mitmPort: this.cfg.mitm.port,
      transparentPort: this.cfg.mitm.transparentPort,
      budget: this.budget?.snapshot() ?? null,
    };
  }

  private sink = (entry: AuditEntry): void => {
    this.audit.unshift(entry);
    if (this.audit.length > 200) this.audit.pop();
    this.broadcast({ type: "audit", entry });
  };

  startBase(): void {
    if (this.base) return;
    this.base = startServer(this.cfg, { auditSink: this.sink, budget: this.budget });
    this.base.on("error", () => {
      this.base = null;
      this.broadcast({ type: "status", status: this.status() });
    });
    this.broadcast({ type: "status", status: this.status() });
  }

  stopBase(): void {
    if (!this.base) return;
    this.base.close();
    this.base = null;
    this.broadcast({ type: "status", status: this.status() });
  }

  startSystem(): void {
    if (this.system) return;
    const { server, transparentServer } = startMitmProxy(this.cfg, { auditSink: this.sink, budget: this.budget });
    this.system = { server, transparentServer };
    server.on("error", () => {
      this.system = null;
      this.broadcast({ type: "status", status: this.status() });
    });
    this.broadcast({ type: "status", status: this.status() });
  }

  stopSystem(): void {
    if (!this.system) return;
    this.system.server.close();
    this.system.transparentServer?.close();
    this.system = null;
    this.broadcast({ type: "status", status: this.status() });
  }

  applyConfig(partial: Partial<AegisConfig>): void {
    if (partial.mode) this.cfg.mode = partial.mode;
    if (partial.blockOn) this.cfg.blockOn = partial.blockOn;
    if (partial.detectors) this.cfg.detectors = { ...this.cfg.detectors, ...partial.detectors };
    if (partial.dictionary) this.cfg.dictionary = partial.dictionary;
    if (partial.categoryActions !== undefined) this.cfg.categoryActions = partial.categoryActions;
    if (partial.allowlist !== undefined) this.cfg.allowlist = partial.allowlist;
    if (partial.optimize !== undefined) this.cfg.optimize = { ...this.cfg.optimize, ...partial.optimize };
    this.scrubber = new Scrubber(this.cfg);

    // Re-apply to any running proxies.
    const restartBase = this.base !== null;
    const restartSystem = this.system !== null;
    if (restartBase) this.stopBase();
    if (restartSystem) this.stopSystem();
    if (restartBase) this.startBase();
    if (restartSystem) this.startSystem();

    this.broadcast({ type: "status", status: this.status() });
  }

  scan(text: string): Record<string, unknown> {
    const vault = new Vault(this.encKey);
    const scrubbed = this.scrubber.scrub(text, vault);
    const matches = scrubbed.matches;
    // Reflect what actually goes to the AI: scrubbed, then optimized if enabled.
    const opt = this.cfg.optimize?.enabled ? optimizeText(scrubbed.text, this.cfg.optimize) : null;
    const redacted = opt ? opt.text : scrubbed.text;
    const findings = matches
      .slice()
      .sort((a, b) => a.start - b.start)
      .map((m) => ({
        type: m.type,
        category: m.category,
        severity: m.severity,
        start: m.start,
        end: m.end,
        preview: maskPreview(m.value),
      }));
    return { findings, redacted, summary: summarize(matches), savedTokens: opt ? opt.saved : 0 };
  }

  broadcast(event: unknown): void {
    const data = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of this.sse) res.write(data);
  }
}

function maskPreview(value: string): string {
  if (value.length <= 12) return "•".repeat(value.length);
  return value.slice(0, 4) + "…" + value.slice(-2);
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function json(res: http.ServerResponse, code: number, payload: unknown): void {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(payload));
}

export function startGui(cfg: AegisConfig, guiPort: number): Server {
  const state = new GuiState(cfg);

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    try {
      if (path === "/" || path === "/index.html") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(dashboardHtml());
        return;
      }

      if (path === "/api/status") return json(res, 200, state.status());

      if (path === "/api/audit") return json(res, 200, { entries: state.audit });

      if (path === "/api/report") {
        return json(res, 200, buildReport(state.audit, { generatedAt: new Date().toISOString() }));
      }

      if (path === "/api/events") {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        });
        res.write(`data: ${JSON.stringify({ type: "status", status: state.status() })}\n\n`);
        state.sse.add(res);
        req.on("close", () => state.sse.delete(res));
        return;
      }

      if (path === "/api/scan" && method === "POST") {
        const body = (await readJson(req)) as { text?: string };
        return json(res, 200, state.scan(body.text ?? ""));
      }

      if (path === "/api/config" && method === "POST") {
        const body = (await readJson(req)) as Partial<AegisConfig>;
        state.applyConfig(body);
        return json(res, 200, state.status());
      }

      if (path === "/api/proxy/start" && method === "POST") {
        const body = (await readJson(req)) as { kind?: string };
        if (body.kind === "system") state.startSystem();
        else state.startBase();
        return json(res, 200, state.status());
      }

      if (path === "/api/proxy/stop" && method === "POST") {
        const body = (await readJson(req)) as { kind?: string };
        if (body.kind === "system") state.stopSystem();
        else state.stopBase();
        return json(res, 200, state.status());
      }

      json(res, 404, { error: "not found" });
    } catch (err) {
      json(res, 500, { error: String(err) });
    }
  });

  server.listen(guiPort, cfg.host, () => {
    console.log(`\n  Aegis control panel:  http://${cfg.host}:${guiPort}\n`);
  });

  return server;
}
