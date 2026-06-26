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
      res.end(JSON.stringify({ status: "ok", service: "aegis", kind: "system-proxy", mode: cfg.mode }));
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
    let responseVault = new Vault();
    let action: Action = "clean";
    let summary = summarize([]);

    if (rawBody.length && isJson) {
      try {
        const parsed = JSON.parse(rawBody.toString("utf8"));
        const vault = new Vault();
        const { body: scrubbed, matches } = scrubRequestBody(parsed, format, scrubber, vault);
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

    if (summary.total > 0 || action !== "clean") {
      await audit.record({ ts: new Date().toISOString(), route: `${host}${path}`, format, mode: cfg.mode, action, summary });
    }

    forwardUpstream(req, res, { host, path, secure, body: forwardBody, vault: responseVault });
  }

  function forwardUpstream(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    o: { host: string; path: string; secure: boolean; body: Buffer | string; vault: Vault },
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

    const upReq = requestFn(options, (upRes) => sendResponse(res, upRes, o.vault));
    upReq.on("error", () => endError(res));
    if (bodyBuf.length) upReq.write(bodyBuf);
    upReq.end();
  }

  return { server: proxy, transparentServer, ca };
}

function sendResponse(res: http.ServerResponse, upRes: http.IncomingMessage, vault: Vault): void {
  const headers: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(upRes.headers)) {
    if (v != null && !STRIP_RESPONSE_HEADERS.has(k.toLowerCase())) headers[k] = v;
  }
  const status = upRes.statusCode ?? 502;
  const ctype = String(upRes.headers["content-type"] ?? "");

  // Nothing was redacted -> stream raw, no rewriting.
  if (vault.size === 0) {
    res.writeHead(status, headers);
    upRes.pipe(res);
    return;
  }

  if (ctype.includes("text/event-stream")) {
    headers["content-type"] = "text/event-stream";
    headers["cache-control"] = "no-cache";
    res.writeHead(status, headers);
    const restorer = new SseRestorer(vault);
    const decoder = new TextDecoder();
    upRes.on("data", (chunk: Buffer) => res.write(restorer.feed(decoder.decode(chunk, { stream: true }))));
    upRes.on("end", () => {
      res.write(restorer.feed(decoder.decode()));
      res.write(restorer.end());
      res.end();
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
  });
  upRes.on("error", () => res.end());
}

function formatForHost(host: string): RouteFormat {
  const h = host.toLowerCase();
  if (h.includes("anthropic")) return "anthropic";
  if (h.includes("openai")) return "openai";
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
