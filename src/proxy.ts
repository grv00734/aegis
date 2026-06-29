import type { IncomingMessage, ServerResponse } from "node:http";
import type { AegisConfig, RouteConfig } from "./types.js";
import { Scrubber, summarize } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";
import { scrubRequestBody } from "./messages.js";
import { SseRestorer } from "./stream.js";
import { AuditLog, type Action, type AuditEntry } from "./audit.js";
import { decide } from "./policy.js";
import { BudgetTracker, estimateTokens, extractUsage, costOf, identifyUser } from "./budget.js";
import { loadOrCreateKey } from "./crypto.js";
import { optimizeText } from "./optimize.js";
import { mcpDenied } from "./mcp.js";

export interface ContextOptions {
  /** Route audit entries to a custom sink instead of the console. */
  auditSink?: (entry: AuditEntry) => void;
  /** Share a budget tracker (e.g. across the GUI's proxies). */
  budget?: BudgetTracker;
}

/** Headers we must not forward verbatim (hop-by-hop or recomputed). */
const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "content-length",
  "accept-encoding", // force identity so we can rewrite the body safely
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
]);

const STRIP_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

export interface ProxyContext {
  cfg: AegisConfig;
  scrubber: Scrubber;
  audit: AuditLog;
  budget?: BudgetTracker;
  encKey?: Buffer;
}

export function createContext(cfg: AegisConfig, opts: ContextOptions = {}): ProxyContext {
  return {
    cfg,
    scrubber: new Scrubber(cfg),
    audit: new AuditLog(cfg.auditLog, opts.auditSink),
    budget: opts.budget ?? (cfg.budget?.enabled ? new BudgetTracker(cfg.budget) : undefined),
    encKey: cfg.encryption?.enabled ? loadOrCreateKey() : undefined,
  };
}

function matchRoute(cfg: AegisConfig, pathname: string): RouteConfig | null {
  let best: RouteConfig | null = null;
  for (const r of cfg.routes) {
    if (pathname.startsWith(r.matchPrefix)) {
      if (!best || r.matchPrefix.length > best.matchPrefix.length) best = r;
    }
  }
  if (best) return best;
  if (cfg.defaultUpstream) {
    return { matchPrefix: "/", upstream: cfg.defaultUpstream, format: "passthrough" };
  }
  return null;
}

/** Stable per-service key for budgeting: the upstream host. */
function serviceOf(upstream: string): string {
  try {
    return new URL(upstream).host;
  } catch {
    return upstream;
  }
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function forwardHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v == null || STRIP_REQUEST_HEADERS.has(k)) continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

export async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: ProxyContext,
): Promise<void> {
  const { cfg, scrubber, audit } = ctx;
  const url = new URL(req.url ?? "/", "http://localhost");

  if (url.pathname === "/__aegis/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        service: "aegis",
        kind: "base-url-proxy",
        mode: cfg.mode,
        budget: ctx.budget?.snapshot() ?? null,
      }),
    );
    return;
  }

  const route = matchRoute(cfg, url.pathname);

  if (!route) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type: "aegis_no_route", message: `No upstream for ${url.pathname}` } }));
    return;
  }

  const rawBody = req.method && !["GET", "HEAD"].includes(req.method) ? await readBody(req) : Buffer.alloc(0);

  // --- Inspect & scrub the request body (JSON only) ---
  const contentType = String(req.headers["content-type"] ?? "");
  const isJson = contentType.includes("application/json") || contentType.includes("+json");

  let forwardBody: Buffer | string | undefined = rawBody.length ? rawBody : undefined;
  let responseVault = new Vault(ctx.encKey); // carries the key so responses can be decrypted
  let action: Action = "clean";
  let summary = summarize([]);
  let model: string | undefined;
  let savedTokens = 0;
  const service = serviceOf(route.upstream);
  const user =
    ctx.budget && cfg.budget?.enabled
      ? identifyUser(req.headers as Record<string, unknown>, cfg.budget)
      : undefined;
  const optimizeFn = cfg.optimize?.enabled
    ? (s: string): string => {
        const r = optimizeText(s, cfg.optimize!);
        savedTokens += r.saved;
        return r.text;
      }
    : undefined;

  if (rawBody.length && isJson) {
    try {
      const parsed = JSON.parse(rawBody.toString("utf8"));
      if (typeof parsed?.model === "string") model = parsed.model;

      // MCP tool deny-list (block disallowed tool calls outright).
      const deniedTool = mcpDenied(parsed, cfg.mcp?.deniedTools);
      if (deniedTool) {
        await audit.record({
          ts: new Date().toISOString(), route: url.pathname, format: route.format, mode: cfg.mode,
          action: "blocked", note: `MCP tool '${deniedTool}' is denied by policy`, summary: summarize([]),
        });
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { type: "aegis_mcp_denied", message: `MCP tool '${deniedTool}' is blocked by policy.` } }));
        return;
      }

      const scrubVault = new Vault(ctx.encKey);
      const { body: scrubbed, matches } = scrubRequestBody(parsed, route.format, scrubber, scrubVault, optimizeFn);
      summary = summarize(matches);

      const decision = decide(matches, cfg, route.mode ?? cfg.mode);

      if (decision === "block") {
        action = "blocked";
        await audit.record({
          ts: new Date().toISOString(),
          route: url.pathname,
          format: route.format,
          mode: cfg.mode,
          action,
          summary,
        });
        res.writeHead(403, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            error: {
              type: "aegis_blocked",
              message:
                "Aegis blocked this request: confidential data was detected. Remove the flagged content and retry.",
              findings: summary.byType,
              highestSeverity: summary.highestSeverity,
            },
          }),
        );
        return;
      }

      if (decision === "warn") {
        // Forward the original, unmodified body but record what we saw.
        action = "warned";
        forwardBody = rawBody;
      } else {
        // redact (or clean — scrubbed === original when there were no matches)
        action = decision === "redact" ? "redacted" : "clean";
        forwardBody = JSON.stringify(scrubbed);
        if (matches.length > 0) responseVault = scrubVault;
      }
    } catch {
      // Body wasn't valid JSON after all — forward untouched.
      forwardBody = rawBody;
    }
  }

  // --- Token / cost budget check (pre-flight) ---
  if (ctx.budget && cfg.budget?.enabled) {
    const estIn = estimateTokens(rawBody.toString("utf8"));
    const estCost = costOf(model, { inputTokens: estIn, outputTokens: 0 }, cfg.budget);
    const verdict = ctx.budget.check(service, estIn, estCost, user);
    if (!verdict.ok) {
      const note = `budget: ${verdict.reason}`;
      if (cfg.budget.action === "warn") {
        void audit.record({ ts: new Date().toISOString(), route: url.pathname, format: route.format, mode: cfg.mode, action: "warned", note, summary: summarize([]) });
      } else {
        await audit.record({ ts: new Date().toISOString(), route: url.pathname, format: route.format, mode: cfg.mode, action: "blocked", note, summary: summarize([]) });
        res.writeHead(429, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { type: "aegis_budget_exceeded", message: verdict.reason } }));
        return;
      }
    }
  }

  // --- Forward upstream ---
  const upstreamUrl = route.upstream.replace(/\/$/, "") + url.pathname + url.search;
  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: req.method,
      headers: forwardHeaders(req),
      body: forwardBody,
    });
  } catch (err) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(
      JSON.stringify({ error: { type: "aegis_upstream_error", message: (err as Error).message } }),
    );
    return;
  }

  // Audit after we know the request was accepted for forwarding.
  if (summary.total > 0 || action !== "clean" || savedTokens > 0) {
    await audit.record({
      ts: new Date().toISOString(),
      route: url.pathname,
      format: route.format,
      mode: cfg.mode,
      action,
      summary,
      savedTokens: savedTokens > 0 ? savedTokens : undefined,
    });
  }

  // Build a response scanner that flags NEW secrets in the AI output. It scans
  // the model's raw text (before placeholder restore) so the employee's own
  // restored values don't re-trigger.
  const wantBudget = !!(ctx.budget && cfg.budget?.enabled);
  const onResponse =
    cfg.scanResponses || wantBudget
      ? (rawText: string): void => {
          if (cfg.scanResponses) {
            const matches = scrubber.detect(rawText);
            if (matches.length > 0) {
              void audit.record({
                ts: new Date().toISOString(),
                route: url.pathname,
                format: route.format,
                mode: cfg.mode,
                action: "warned",
                direction: "response",
                summary: summarize(matches),
              });
            }
          }
          if (wantBudget && ctx.budget) {
            const usage =
              extractUsage(rawText) ?? {
                inputTokens: estimateTokens(rawBody.toString("utf8")),
                outputTokens: estimateTokens(rawText),
              };
            ctx.budget.record(service, usage, model, user);
          }
        }
      : undefined;

  await sendResponse(res, upstream, responseVault, onResponse);
}

async function sendResponse(
  res: ServerResponse,
  upstream: Response,
  vault: Vault,
  scanResponse?: (rawText: string) => void,
): Promise<void> {
  const respHeaders: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) respHeaders[key] = value;
  });

  const ctype = upstream.headers.get("content-type") ?? "";
  const status = upstream.status;
  const textish =
    ctype.includes("json") || ctype.includes("event-stream") || ctype.startsWith("text/");

  // Binary / unknown bodies: stream raw, no transform, no scan.
  if (!upstream.body || !textish) {
    res.writeHead(status, respHeaders);
    if (upstream.body) {
      for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) res.write(chunk);
    }
    res.end();
    return;
  }

  const decoder = new TextDecoder();

  if (ctype.includes("text/event-stream")) {
    respHeaders["content-type"] = "text/event-stream";
    respHeaders["cache-control"] = "no-cache";
    res.writeHead(status, respHeaders);
    const restorer = vault.active ? new SseRestorer(vault) : null;
    let raw = "";
    for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) {
      const txt = decoder.decode(chunk, { stream: true });
      raw += txt; // pre-restore text, for response scanning
      res.write(restorer ? restorer.feed(txt) : txt);
    }
    const tail = decoder.decode();
    raw += tail;
    if (restorer) {
      res.write(restorer.feed(tail));
      res.write(restorer.end());
    } else if (tail) {
      res.write(tail);
    }
    res.end();
    if (scanResponse) scanResponse(raw);
    return;
  }

  // JSON / text: buffer, (optionally) restore, scan the raw text, send.
  const text = await upstream.text();
  let out = text;
  if (vault.active) {
    try {
      out = JSON.stringify(vault.restoreDeep(JSON.parse(text)));
    } catch {
      out = vault.restore(text);
    }
  }
  if (scanResponse) scanResponse(text);
  respHeaders["content-type"] = ctype || "application/json";
  respHeaders["content-length"] = String(Buffer.byteLength(out));
  res.writeHead(status, respHeaders);
  res.end(out);
}
