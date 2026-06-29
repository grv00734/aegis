/**
 * Fleet management: aggregate token/cost spend (and per-employee usage) across
 * many machines into one view — the "team plane".
 *
 *   agents  --POST /fleet/report-->  collector (aggregates)  --GET /fleet/summary-->
 *
 * Each agent periodically reports its rolling budget snapshot. The collector
 * keeps the latest snapshot per host (idempotent) and sums across the fleet.
 * Reports are authenticated with a shared bearer token.
 */
import * as http from "node:http";
import type { BudgetSnapshot } from "./budget.js";

export interface FleetUser {
  user: string;
  tokens: number;
  costUsd: number;
}

export interface FleetReport {
  host: string;
  ts?: string;
  tokens?: number;
  costUsd?: number;
  requests?: number;
  users?: FleetUser[];
}

export interface FleetSummary {
  hosts: Required<Omit<FleetReport, "users">>[];
  users: FleetUser[];
  totals: { tokens: number; costUsd: number; requests: number; hosts: number };
}

export class FleetAggregator {
  private hosts = new Map<string, FleetReport>();

  ingest(r: FleetReport, ts: string): void {
    if (!r || !r.host) return;
    this.hosts.set(r.host, { ...r, ts: r.ts ?? ts });
  }

  summary(): FleetSummary {
    const hosts: Required<Omit<FleetReport, "users">>[] = [];
    const users = new Map<string, FleetUser>();
    const totals = { tokens: 0, costUsd: 0, requests: 0, hosts: 0 };

    for (const h of this.hosts.values()) {
      hosts.push({
        host: h.host,
        ts: h.ts ?? "",
        tokens: h.tokens ?? 0,
        costUsd: h.costUsd ?? 0,
        requests: h.requests ?? 0,
      });
      totals.tokens += h.tokens ?? 0;
      totals.costUsd += h.costUsd ?? 0;
      totals.requests += h.requests ?? 0;
      for (const u of h.users ?? []) {
        const e = users.get(u.user) ?? { user: u.user, tokens: 0, costUsd: 0 };
        e.tokens += u.tokens;
        e.costUsd += u.costUsd;
        users.set(u.user, e);
      }
    }
    totals.hosts = hosts.length;
    return {
      hosts: hosts.sort((a, b) => b.tokens - a.tokens),
      users: [...users.values()].sort((a, b) => b.tokens - a.tokens),
      totals,
    };
  }
}

/** Build a fleet report from a local budget snapshot. */
export function reportFromBudget(host: string, snap: BudgetSnapshot | null): FleetReport {
  if (!snap) return { host };
  return {
    host,
    tokens: snap.total.tokens,
    costUsd: snap.total.costUsd,
    requests: snap.total.requests,
    users: snap.users.map((u) => ({ user: u.user, tokens: u.tokens, costUsd: u.costUsd })),
  };
}

/** Fire-and-forget POST of a report to the fleet collector. */
export async function reportToFleet(url: string, token: string | undefined, report: FleetReport): Promise<boolean> {
  try {
    const r = await fetch(url.replace(/\/$/, "") + "/fleet/report", {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(report),
    });
    return r.ok;
  } catch {
    return false;
  }
}

export interface FleetCollectorOptions {
  port: number;
  host?: string;
  token?: string;
}

export function startFleetCollector(opts: FleetCollectorOptions): http.Server {
  const agg = new FleetAggregator();
  const authorized = (req: http.IncomingMessage): boolean => {
    if (!opts.token) return true;
    const h = String(req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
    return h === opts.token;
  };

  const server = http.createServer((req, res) => {
    if (!authorized(req)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end('{"error":"unauthorized"}');
      return;
    }
    if (req.method === "POST" && req.url === "/fleet/report") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        try {
          agg.ingest(JSON.parse(b), new Date().toISOString());
        } catch {
          /* ignore malformed */
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"ok":true}');
      });
      return;
    }
    if (req.url === "/fleet/summary" || req.url === "/") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(agg.summary()));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"not found"}');
  });

  server.listen(opts.port, opts.host ?? "0.0.0.0", () => {
    console.log(`\n  Aegis fleet collector on http://${opts.host ?? "0.0.0.0"}:${opts.port}`);
    console.log(`  agents report to:  ${"POST"} /fleet/report   view:  GET /fleet/summary\n`);
  });
  return server;
}
