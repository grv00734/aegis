/**
 * Transparent HTTPS-intercepting proxy ("system proxy" mode).
 *
 * Flow:
 *   client --CONNECT host:443--> Aegis
 *      • host NOT on the allowlist -> blind TCP tunnel, never decrypted
 *      • host on the allowlist      -> TLS-terminate with a cert we mint for it,
 *        read the plaintext HTTP request, scrub it, forward to the real provider
 *        over verified TLS, then restore placeholders in the response.
 *
 * Only allowlisted AI-provider hosts are ever decrypted. Everything else (your
 * bank, email, etc.) is passed through as opaque bytes.
 */
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";
import type { AegisConfig, RouteFormat } from "./types.js";
import { Scrubber, summarize } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";
import { scrubRequestBody } from "./messages.js";
import { SseRestorer } from "./stream.js";
import { AuditLog, type Action, type AuditEntry } from "./audit.js";
import { CertAuthority, aegisHome } from "./ca.js";
import { peekSni } from "./sni.js";
import { decide } from "./policy.js";
import { BudgetTracker, estimateTokens, extractUsage, costOf, identifyUser } from "./budget.js";
import { loadOrCreateKey } from "./crypto.js";
import { optimizeText } from "./optimize.js";

export interface Upstream {
  host: string;
  port: number;
  secure: boolean;
  servername?: string;
  ca?: string | string[];
  rejectUnauthorized?: boolean;
}

export interface MitmOptions {
  caDir?: string;
  auditSink?: (entry: AuditEntry) => void;
  /** Share a budget tracker (e.g. across the GUI's proxies). */
  budget?: BudgetTracker;
  /** Test seam: redirect a host to a different upstream / trust settings. */
  resolveUpstream?: (host: string, secure: boolean) => Upstream;
  /** Also listen for OS-redirected (iptables) connections on this port. */
  transparentPort?: number;
  /** Test seam: where to blind-tunnel a transparent connection (default host:443). */
  resolveTunnel?: (host: string) => { host: string; port: number };
}

export interface MitmHandle {
  server: http.Server;
  /** Present when transparentPort was set: the iptables-redirect listener. */
  transparentServer?: net.Server;
  ca: CertAuthority;
}

const STRIP_REQUEST_HEADERS = new Set([
  "proxy-connection",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "accept-encoding",
  "content-length",
]);
const STRIP_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

export function startMitmProxy(cfg: AegisConfig, opts: MitmOptions = {}): MitmHandle {
  const ca = new CertAuthority(opts.caDir ?? aegisHome());
  const scrubber = new Scrubber(cfg);
  const audit = new AuditLog(undefined, opts.auditSink);
  const budget = opts.budget ?? (cfg.budget?.enabled ? new BudgetTracker(cfg.budget) : undefined);
  const encKey = cfg.encryption?.enabled ? loadOrCreateKey(opts.caDir ?? aegisHome()) : undefined;
  const allow = new Set(cfg.mitm.hosts.map((h) => h.toLowerCase()));
  const resolveUpstream =
    opts.resolveUpstream ??
    ((host: string, secure: boolean): Upstream => ({
      host,
      port: secure ? 443 : 80,
      secure,
      servername: host,
    }));

  const shouldMitm = (host: string): boolean => {
    const h = host.toLowerCase();
    if (allow.has(h)) return true;
    // allow suffix entries like ".openai.com"
    for (const entry of allow) {
      if (entry.startsWith(".") && h.endsWith(entry)) return true;
    }
    return false;
  };

  // Internal HTTP server parses the decrypted stream for us.
  const internalServer = http.createServer((req, res) => {
    void handleDecrypted(req, res, true);
  });

  // TLS terminator: picks the right minted cert via SNI, then feeds the
  // decrypted socket into the internal HTTP server.
  const tlsServer = tls.createServer(
    {
      key: ca.leafKeyPem,
      cert: `${ca.mintLeaf("localhost")}\n${ca.caCertPem}`,
      SNICallback: (servername, cb) => cb(null, ca.contextFor(servername)),
    },
    (socket) => internalServer.emit("connection", socket),
  );

  const resolveTunnel = opts.resolveTunnel ?? ((h: string) => ({ host: h, port: 443 }));

  // Feed a client socket into TLS termination (optionally replaying peeked bytes).
  function mitmTls(clientSocket: net.Socket, prepend?: Buffer): void {
    if (prepend && prepend.length) clientSocket.unshift(prepend);
    tlsServer.emit("connection", clientSocket);
  }

  // Opaque pass-through — bytes are never decrypted.
  function blindTunnel(clientSocket: net.Socket, destHost: string, destPort: number, prepend?: Buffer): void {
    const upstream = net.connect(destPort, destHost, () => {
      if (prepend && prepend.length) upstream.write(prepend);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on("error", () => clientSocket.destroy());
    clientSocket.on("error", () => upstream.destroy());
  }

  const proxy = http.createServer((req, res) => {
    // Plain-HTTP proxying: req.url is absolute (http://host/path).
    void handlePlain(req, res);
  });

  // Explicit-proxy CONNECT tunnels (client opted in via HTTPS_PROXY).
  proxy.on("connect", (req, clientSocket: net.Socket, head: Buffer) => {
    const [rawHost, rawPort] = (req.url ?? "").split(":");
    const host = rawHost ?? "";
    const port = Number(rawPort) || 443;
    clientSocket.on("error", () => clientSocket.destroy());
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (shouldMitm(host)) mitmTls(clientSocket, head?.length ? head : undefined);
    else blindTunnel(clientSocket, host, port, head?.length ? head : undefined);
  });

  proxy.listen(cfg.mitm.port, cfg.host);

  // Transparent listener: OS (iptables REDIRECT) hands us already-connected
  // sockets with no CONNECT line. Route by the SNI in the TLS ClientHello.
  let transparentServer: net.Server | undefined;
  if (opts.transparentPort != null) {
    transparentServer = net.createServer((socket: net.Socket) => {
      socket.on("error", () => socket.destroy());
      peekSni(socket)
        .then(({ host, buffered }) => {
          if (!host) {
            socket.destroy(); // no SNI -> cannot determine destination
            return;
          }
          if (shouldMitm(host)) {
            mitmTls(socket, buffered);
          } else {
            const t = resolveTunnel(host);
            blindTunnel(socket, t.host, t.port, buffered);
          }
        })
        .catch(() => socket.destroy());
    });
    transparentServer.listen(opts.transparentPort, cfg.host);
  }

  // --- request handling ---

  async function handlePlain(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if ((req.url ?? "").startsWith("/__aegis/health")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok", service: "aegis", kind: "system-proxy", mode: cfg.mode, budget: budget?.snapshot() ?? null }));
      return;
    }
    try {
      const url = new URL(req.url ?? "/");
      if (!shouldMitm(url.hostname)) {
        // Opaque pass-through for non-AI plain HTTP.
        const up = http.request(
          { host: url.hostname, port: Number(url.port) || 80, method: req.method, path: url.pathname + url.search, headers: req.headers },
          (upRes) => {
            res.writeHead(upRes.statusCode ?? 502, upRes.headers);
            upRes.pipe(res);
          },
        );
        up.on("error", () => endError(res));
        req.pipe(up);
        return;
      }
      await handleDecrypted(req, res, false);
    } catch {
      endError(res);
    }
  }

  async function handleDecrypted(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    secure: boolean,
  ): Promise<void> {
    const host = (req.headers.host ?? "").split(":")[0] ?? "";
    const path = req.url ?? "/";
    const format = formatForHost(host);

    const rawBody = await readBody(req);
    const isJson = String(req.headers["content-type"] ?? "").includes("json");

    let forwardBody: Buffer | string = rawBody;
    let responseVault = new Vault(encKey);
    let action: Action = "clean";
    let summary = summarize([]);
    let model: string | undefined;
    let savedTokens = 0;
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
        const vault = new Vault(encKey);
        const { body: scrubbed, matches } = scrubRequestBody(parsed, format, scrubber, vault, optimizeFn);
        summary = summarize(matches);
        const decision = decide(matches, cfg, cfg.mode);

        if (decision === "block") {
          action = "blocked";
          await audit.record({ ts: new Date().toISOString(), route: `${host}${path}`, format, mode: cfg.mode, action, summary });
          res.writeHead(403, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              error: {
                type: "aegis_blocked",
                message: "Aegis blocked this request: confidential data was detected.",
                findings: summary.byType,
              },
            }),
          );
          return;
        }

        if (decision === "warn") {
          action = "warned";
        } else {
          action = decision === "redact" ? "redacted" : "clean";
          forwardBody = JSON.stringify(scrubbed);
          if (matches.length > 0) responseVault = vault;
        }
      } catch {
        /* not JSON after all */
      }
    }

    if (summary.total > 0 || action !== "clean" || savedTokens > 0) {
      await audit.record({ ts: new Date().toISOString(), route: `${host}${path}`, format, mode: cfg.mode, action, summary, savedTokens: savedTokens > 0 ? savedTokens : undefined });
    }

    // --- Token / cost budget check (pre-flight) ---
    const user = budget && cfg.budget?.enabled ? identifyUser(req.headers as Record<string, unknown>, cfg.budget) : undefined;
    if (budget && cfg.budget?.enabled) {
      const estIn = estimateTokens(rawBody.toString("utf8"));
      const estCost = costOf(model, { inputTokens: estIn, outputTokens: 0 }, cfg.budget);
      const verdict = budget.check(host, estIn, estCost, user);
      if (!verdict.ok) {
        const note = `budget: ${verdict.reason}`;
        if (cfg.budget.action === "warn") {
          void audit.record({ ts: new Date().toISOString(), route: `${host}${path}`, format, mode: cfg.mode, action: "warned", note, summary: summarize([]) });
        } else {
          await audit.record({ ts: new Date().toISOString(), route: `${host}${path}`, format, mode: cfg.mode, action: "blocked", note, summary: summarize([]) });
          res.writeHead(429, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { type: "aegis_budget_exceeded", message: verdict.reason } }));
          return;
        }
      }
    }

    const onRaw =
      budget && cfg.budget?.enabled
        ? (rawText: string): void => {
            const usage =
              extractUsage(rawText) ?? {
                inputTokens: estimateTokens(rawBody.toString("utf8")),
                outputTokens: estimateTokens(rawText),
              };
            budget.record(host, usage, model, user);
          }
        : undefined;

    forwardUpstream(req, res, { host, path, secure, body: forwardBody, vault: responseVault, onRaw });
  }

  function forwardUpstream(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    o: { host: string; path: string; secure: boolean; body: Buffer | string; vault: Vault; onRaw?: (raw: string) => void },
  ): void {
    const up = resolveUpstream(o.host, o.secure);
    const headers = filterHeaders(req.headers);
    headers["host"] = o.host;
    const bodyBuf = typeof o.body === "string" ? Buffer.from(o.body, "utf8") : o.body;
    if (req.method && !["GET", "HEAD"].includes(req.method)) headers["content-length"] = String(bodyBuf.length);

    const requestFn = up.secure ? https.request : http.request;
    const options: https.RequestOptions = {
      host: up.host,
      port: up.port,
      method: req.method,
      path: o.path,
      headers,
      servername: up.servername ?? o.host,
      ca: up.ca,
      rejectUnauthorized: up.rejectUnauthorized,
    };

    const upReq = requestFn(options, (upRes) => sendResponse(res, upRes, o.vault, o.onRaw));
    upReq.on("error", () => endError(res));
    if (bodyBuf.length) upReq.write(bodyBuf);
    upReq.end();
  }

  return { server: proxy, transparentServer, ca };
}

function sendResponse(
  res: http.ServerResponse,
  upRes: http.IncomingMessage,
  vault: Vault,
  onRaw?: (raw: string) => void,
): void {
  const headers: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(upRes.headers)) {
    if (v != null && !STRIP_RESPONSE_HEADERS.has(k.toLowerCase())) headers[k] = v;
  }
  const status = upRes.statusCode ?? 502;
  const ctype = String(upRes.headers["content-type"] ?? "");

  // Nothing to restore (no redactions, no key) -> stream raw. Tee for budget if needed.
  if (!vault.active) {
    res.writeHead(status, headers);
    if (!onRaw) {
      upRes.pipe(res);
      return;
    }
    const seen: Buffer[] = [];
    upRes.on("data", (c: Buffer) => {
      seen.push(c);
      res.write(c);
    });
    upRes.on("end", () => {
      res.end();
      onRaw(Buffer.concat(seen).toString("utf8"));
    });
    upRes.on("error", () => res.end());
    return;
  }

  if (ctype.includes("text/event-stream")) {
    headers["content-type"] = "text/event-stream";
    headers["cache-control"] = "no-cache";
    res.writeHead(status, headers);
    const restorer = new SseRestorer(vault);
    const decoder = new TextDecoder();
    let raw = "";
    upRes.on("data", (chunk: Buffer) => {
      const txt = decoder.decode(chunk, { stream: true });
      raw += txt;
      res.write(restorer.feed(txt));
    });
    upRes.on("end", () => {
      const tail = decoder.decode();
      raw += tail;
      res.write(restorer.feed(tail));
      res.write(restorer.end());
      res.end();
      onRaw?.(raw);
    });
    upRes.on("error", () => res.end());
    return;
  }

  // Buffer text-ish responses, restore, resend.
  const chunks: Buffer[] = [];
  upRes.on("data", (c: Buffer) => chunks.push(c));
  upRes.on("end", () => {
    const text = Buffer.concat(chunks).toString("utf8");
    let out = text;
    if (ctype.includes("json")) {
      try {
        out = JSON.stringify(vault.restoreDeep(JSON.parse(text)));
      } catch {
        out = vault.restore(text);
      }
    } else {
      out = vault.restore(text);
    }
    headers["content-length"] = String(Buffer.byteLength(out));
    res.writeHead(status, headers);
    res.end(out);
    onRaw?.(text);
  });
  upRes.on("error", () => res.end());
}

/**
 * Map an upstream host to its request body shape. We only return a specific
 * format when we're confident of the shape; anything ambiguous (Bedrock,
 * Cohere, Mistral, internal company agents) falls back to "passthrough", which
 * deep-scrubs every string — safe by default.
 */
export function formatForHost(host: string): RouteFormat {
  const h = host.toLowerCase();
  if (h.includes("anthropic")) return "anthropic";
  if (h.includes("openai") || h.includes(".openai.azure.com")) return "openai"; // incl. Azure OpenAI
  if (h.includes("generativelanguage.googleapis.com") || h.includes("gemini")) return "gemini";
  return "passthrough";
}

function filterHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v == null || STRIP_REQUEST_HEADERS.has(k.toLowerCase())) continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function endError(res: http.ServerResponse): void {
  if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
  if (!res.writableEnded) {
    res.end(JSON.stringify({ error: { type: "aegis_upstream_error", message: "upstream request failed" } }));
  }
}
