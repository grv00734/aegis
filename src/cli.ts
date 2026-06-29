#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { copyFileSync } from "node:fs";
import { loadConfig } from "./config.js";
import { startServer } from "./server.js";
import { Scrubber, summarize } from "./scrub/index.js";
import { installShellProfile, uninstallShellProfile } from "./setup.js";
import { startMitmProxy } from "./mitm.js";
import { CertAuthority, trustInstructions } from "./ca.js";
import { plan as transparentPlan, apply as transparentApply, isRoot } from "./transparent.js";
import { probeHealth, probeTcp } from "./status.js";
import type { BudgetTracker } from "./budget.js";
import { startGui } from "./gui.js";
import { launchApp } from "./app.js";
import { scanHistory } from "./history.js";
import { buildReport, formatReportText, parseAuditFile } from "./report.js";
import { optimizeText } from "./optimize.js";
import { spawn } from "node:child_process";

function parseFlags(args: string[]): { positionals: string[]; flags: Record<string, string> } {
  const positionals: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = "true";
      }
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

function cmdStart(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  if (flags.port) cfg.port = Number(flags.port);
  if (flags.mode) cfg.mode = flags.mode as typeof cfg.mode;
  startServer(cfg);
}

function cmdInit(): void {
  const target = resolve(process.cwd(), "aegis.config.json");
  if (existsSync(target)) {
    console.error("aegis.config.json already exists — not overwriting.");
    process.exit(1);
  }
  const here = dirname(fileURLToPath(import.meta.url));
  // Example ships alongside the package root (one level up from dist/).
  const example = resolve(here, "..", "aegis.config.example.json");
  const contents = existsSync(example)
    ? readFileSync(example, "utf8")
    : JSON.stringify({ port: 8787, mode: "redact" }, null, 2);
  writeFileSync(target, contents, "utf8");
  console.log(`Wrote ${target}. Edit the dictionary / code sections for your org, then run: aegis start`);
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    const child = spawn(cmd, [url], { stdio: "ignore", detached: true, shell: process.platform === "win32" });
    child.on("error", () => undefined);
    child.unref();
  } catch {
    /* best effort */
  }
}

async function cmdBudget(flags: Record<string, string>): Promise<void> {
  const cfg = loadConfig(flags.config);
  if (!cfg.budget?.enabled) {
    console.log('Token budget is disabled. Set "budget": { "enabled": true, ... } in aegis.config.json.');
    return;
  }

  const [base, sys] = await Promise.all([
    probeHealth(cfg.host, cfg.port),
    probeHealth(cfg.host, cfg.mitm.port),
  ]);
  const snap =
    ((base.info as { budget?: unknown } | undefined)?.budget as ReturnType<BudgetTracker["snapshot"]> | undefined) ??
    ((sys.info as { budget?: unknown } | undefined)?.budget as ReturnType<BudgetTracker["snapshot"]> | undefined) ??
    null;

  if (!snap) {
    console.log("Budget is configured, but no running guard was found to read live spend from.");
    console.log(`  window ${cfg.budget.windowHours}h   action=${cfg.budget.action}`);
    console.log(
      `  limits: tokens=${cfg.budget.maxTokens ?? "-"}  cost=$${cfg.budget.maxCostUsd ?? "-"}  perRequest=${cfg.budget.maxRequestTokens ?? "-"}`,
    );
    console.log("  Start `aegis start` or `aegis proxy` to begin tracking.");
    return;
  }

  console.log(`\nToken spend  (window ${snap.windowHours}h, resets ${snap.resetAt})   action=${snap.action}`);
  console.log(`  total: ${snap.total.tokens} tokens   $${snap.total.costUsd.toFixed(4)}   ${snap.total.requests} request(s)`);
  console.log(
    `  limits: tokens=${snap.limits.maxTokens ?? "-"}  cost=$${snap.limits.maxCostUsd ?? "-"}  perRequest=${snap.limits.maxRequestTokens ?? "-"}`,
  );
  if (snap.services.length) {
    console.log("  by service:");
    for (const s of snap.services) {
      console.log(`    ${s.service.padEnd(28)} ${String(s.tokens).padStart(8)} tok   $${s.costUsd.toFixed(4)}   ${s.requests} req`);
    }
  }
  if (snap.users.length) {
    console.log("  by employee:");
    for (const u of snap.users) {
      console.log(`    ${u.user.padEnd(28)} ${String(u.tokens).padStart(8)} tok   $${u.costUsd.toFixed(4)}   ${u.requests} req`);
    }
  }
}

function cmdGui(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const guiPort = flags.port ? Number(flags.port) : 8799;
  startGui(cfg, guiPort);
  if (flags.open === "true") openBrowser(`http://${cfg.host}:${guiPort}`);
}

function cmdPitch(flags: Record<string, string>): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const deck = resolve(here, "..", "pitch", "index.html");
  if (!existsSync(deck)) {
    console.error(`Pitch deck not found at ${deck}`);
    process.exitCode = 1;
    return;
  }
  const url = `file://${deck}`;
  const r = launchApp(url, "1280,820", "aegis-pitch-profile");
  if (r.launched) {
    console.log(`  Opened the Aegis pitch deck (${r.browser}). Arrow keys to navigate, F for fullscreen.`);
  } else {
    console.log(`  Open the deck in your browser:\n    ${deck}`);
    if (flags.open === "true") openBrowser(url);
  }
}

function cmdApp(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const guiPort = flags.port ? Number(flags.port) : 8799;
  startGui(cfg, guiPort);
  const url = `http://${cfg.host}:${guiPort}`;
  const r = launchApp(url);
  if (r.launched) {
    console.log(`  Opened Aegis as a desktop app window (${r.browser}).`);
    console.log(`  Close the window to keep it running, or Ctrl-C here to stop the guard.`);
  } else {
    console.log(`  No Chromium-family browser found for app mode. Opening in your default browser:`);
    console.log(`    ${url}`);
    openBrowser(url);
  }
}

async function cmdStatus(flags: Record<string, string>): Promise<void> {
  const cfg = loadConfig(flags.config);
  const host = cfg.host;

  const [base, sys, trans] = await Promise.all([
    probeHealth(host, cfg.port),
    probeHealth(host, cfg.mitm.port),
    probeTcp(host, cfg.mitm.transparentPort),
  ]);

  const row = (name: string, port: number, up: boolean, extra = ""): void => {
    const dot = up ? "●  up  " : "○  down";
    console.log(`  ${dot}  ${name.padEnd(22)} ${host}:${port}${extra}`);
  };

  console.log("\nAegis status\n");
  row("base-URL proxy", cfg.port, base.up, base.info?.mode ? `   (mode=${base.info.mode})` : "");
  row("system proxy", cfg.mitm.port, sys.up, sys.info?.mode ? `   (mode=${sys.info.mode})` : "");
  row("transparent listener", cfg.mitm.transparentPort, trans);

  const anyUp = base.up || sys.up || trans;
  console.log(
    anyUp
      ? "\nAegis is running."
      : "\nAegis is not running. Start it with:  aegis start   (or: aegis proxy)",
  );
  process.exitCode = anyUp ? 0 : 1;
}

function cmdProxy(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  if (flags.port) cfg.mitm.port = Number(flags.port);
  const transparent = flags.transparent === "true";

  const { ca } = startMitmProxy(cfg, {
    transparentPort: transparent ? cfg.mitm.transparentPort : undefined,
    auditSink: (e) => {
      if (e.summary.total === 0) return;
      const types = Object.entries(e.summary.byType).map(([t, n]) => `${t}×${n}`).join(", ");
      console.log(`[aegis] ${e.action.toUpperCase()} ${e.route} — ${types}`);
    },
  });

  console.log(`\n  Aegis system proxy (HTTPS-intercepting) on http://${cfg.host}:${cfg.mitm.port}`);
  if (transparent) {
    console.log(`  Transparent listener (iptables REDIRECT target) on ${cfg.host}:${cfg.mitm.transparentPort}`);
  }
  console.log(`  Decrypting only: ${cfg.mitm.hosts.join(", ")}`);
  console.log(`  Everything else is blind-tunnelled (never decrypted).\n`);
  if (transparent) {
    console.log(`  Now install the redirect rules:  sudo aegis transparent --apply --uid <proxy-user-uid>\n`);
  } else {
    console.log(`  Point your system / apps at this proxy:`);
    console.log(`    export HTTPS_PROXY=http://${cfg.host}:${cfg.mitm.port}`);
    console.log(`    export HTTP_PROXY=http://${cfg.host}:${cfg.mitm.port}\n`);
  }
  console.log(trustInstructions(ca.caCertPath));
  console.log("");
}

function cmdTransparent(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const port = flags.port ? Number(flags.port) : cfg.mitm.transparentPort;
  const uid = flags.uid;
  const platform = flags.platform as "linux" | "darwin" | undefined;
  const action: "install" | "undo" = flags.undo ? "undo" : "install";
  const p = transparentPlan({ port, uid, platform });

  if (flags.apply === "true") {
    if (p.platform !== "linux") {
      console.error("--apply is Linux-only. On macOS, run the printed pf commands manually.");
      process.exitCode = 1;
      return;
    }
    if (!isRoot()) {
      console.error("Applying iptables rules requires root. Re-run with sudo.");
      process.exitCode = 1;
      return;
    }
    transparentApply({ port, uid }, action);
    console.log(`iptables rules ${action === "install" ? "installed" : "removed"}.`);
    return;
  }

  const cmds = action === "install" ? p.install : p.undo;
  // Linux commands are bare; prefix sudo for copy/paste. macOS already includes it.
  const printed = p.platform === "linux" ? cmds.map((c) => `sudo ${c}`) : cmds;

  console.log(`# Platform: ${p.platform}`);
  console.log(`# ${p.note}\n`);
  console.log(action === "install" ? "# Install (run as root):" : "# Undo (run as root):");
  console.log(printed.join("\n"));
  if (p.platform === "linux") {
    console.log(`\n# Or apply directly:  sudo aegis transparent ${flags.undo ? "--undo " : ""}--apply --uid <uid>`);
  }
}

function cmdCa(flags: Record<string, string>): void {
  const ca = new CertAuthority();
  if (flags.export) {
    copyFileSync(ca.caCertPath, flags.export);
    console.log(`Exported root CA to ${flags.export}`);
    return;
  }
  console.log(`Aegis root CA: ${ca.caCertPath}\n`);
  console.log(trustInstructions(ca.caCertPath));
}

function cmdSetup(flags: Record<string, string>): void {
  if (flags.undo) {
    const { files } = uninstallShellProfile();
    if (files.length === 0) {
      console.log("Aegis was not installed in any shell profile.");
    } else {
      console.log(`Removed Aegis auto-routing from:\n  ${files.join("\n  ")}`);
      console.log("Open a new terminal (or 'source' the file) for it to take effect.");
    }
    return;
  }

  const cfg = loadConfig(flags.config);
  const baseUrl = `http://${cfg.host}:${cfg.port}`;
  const { files } = installShellProfile(baseUrl);
  console.log(`Auto-routing enabled. Every new terminal now sends AI-agent traffic through ${baseUrl}.`);
  console.log(`Updated:\n  ${files.join("\n  ")}`);
  console.log(`\nNext: run 'aegis start' to launch the guard, then open a new terminal.`);
  console.log(`Undo any time with: aegis setup --undo`);
}

function cmdOptimize(positionals: string[], flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const file = positionals[0];
  const text = file ? readFileSync(resolve(process.cwd(), file), "utf8") : readFileSync(0, "utf8");
  const r = optimizeText(text, {
    enabled: true,
    aggressive: flags.aggressive === "true" || cfg.optimize?.aggressive,
    maxPasses: cfg.optimize?.maxPasses,
  });
  const pct = r.beforeTokens > 0 ? Math.round((r.saved / r.beforeTokens) * 100) : 0;
  console.log(
    `Before: ${r.beforeTokens} tokens   After: ${r.afterTokens} tokens   Saved: ${r.saved} (${pct}%)   passes: ${r.passes}`,
  );
  if (flags.print === "true") process.stdout.write("\n" + r.text + "\n");
}

function cmdScanHistory(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const scrubber = new Scrubber(cfg);
  const cwd = flags.path ? resolve(process.cwd(), flags.path) : process.cwd();

  let res;
  try {
    res = scanHistory(scrubber, cwd);
  } catch (err) {
    console.error((err as Error).message);
    process.exitCode = 1;
    return;
  }

  if (res.findings.length === 0) {
    console.log(`Scanned ${res.scannedBlobs} blob(s) across git history. No confidential data found.`);
    return;
  }
  console.log(`Scanned ${res.scannedBlobs} blob(s). Found ${res.findings.length} item(s):\n`);
  for (const f of res.findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.type}  ${f.path}@${f.blob}  (${f.preview})`);
  }
  console.log("\nBy type:", JSON.stringify(res.summary.byType));
  process.exitCode = 2;
}

function cmdReport(flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const input = flags.input ?? cfg.auditLog ?? "./aegis-audit.log";
  const p = resolve(process.cwd(), input);
  if (!existsSync(p)) {
    console.error(`Audit log not found: ${p}. Run the guard so it can record activity first.`);
    process.exitCode = 1;
    return;
  }
  const entries = parseAuditFile(readFileSync(p, "utf8"));
  const report = buildReport(entries, { since: flags.since, generatedAt: new Date().toISOString() });
  if (flags.format === "json") console.log(JSON.stringify(report, null, 2));
  else console.log(formatReportText(report));
}

function cmdScan(positionals: string[], flags: Record<string, string>): void {
  const cfg = loadConfig(flags.config);
  const scrubber = new Scrubber(cfg);

  const file = positionals[0];
  let text: string;
  if (file) {
    text = readFileSync(resolve(process.cwd(), file), "utf8");
  } else {
    text = readFileSync(0, "utf8"); // stdin
  }

  const matches = scrubber.detect(text);
  const summary = summarize(matches);

  if (matches.length === 0) {
    console.log("No confidential data detected.");
    return;
  }

  console.log(`Found ${summary.total} item(s). Highest severity: ${summary.highestSeverity}\n`);
  for (const m of matches) {
    const preview = m.value.length > 12 ? m.value.slice(0, 4) + "…" + m.value.slice(-2) : "•".repeat(m.value.length);
    console.log(`  [${m.severity.toUpperCase()}] ${m.category}/${m.type}  @${m.start}  (${preview})`);
  }
  console.log("\nBy type:", JSON.stringify(summary.byType));
  process.exitCode = 2; // non-zero so it can gate CI / pre-commit
}

function main(): void {
  const [command, ...rest] = process.argv.slice(2);
  const { positionals, flags } = parseFlags(rest);

  switch (command) {
    case "start":
      cmdStart(flags);
      break;
    case "init":
      cmdInit();
      break;
    case "scan":
      cmdScan(positionals, flags);
      break;
    case "scan-history":
      cmdScanHistory(flags);
      break;
    case "optimize":
      cmdOptimize(positionals, flags);
      break;
    case "report":
      cmdReport(flags);
      break;
    case "setup":
      cmdSetup(flags);
      break;
    case "proxy":
      cmdProxy(flags);
      break;
    case "status":
      void cmdStatus(flags);
      break;
    case "budget":
      void cmdBudget(flags);
      break;
    case "gui":
      cmdGui(flags);
      break;
    case "app":
      cmdApp(flags);
      break;
    case "pitch":
      cmdPitch(flags);
      break;
    case "transparent":
      cmdTransparent(flags);
      break;
    case "ca":
      cmdCa(flags);
      break;
    default:
      console.log(`aegis — local DLP guard for AI coding agents

Usage:
  aegis start  [--config <path>] [--port <n>] [--mode redact|block|warn]
      Base-URL proxy. Agents set ANTHROPIC_BASE_URL/OPENAI_BASE_URL to it.

  aegis proxy  [--config <path>] [--port <n>] [--transparent]
      System proxy (HTTPS interception). Catches any app that honours
      HTTPS_PROXY and trusts the Aegis CA. Add --transparent for OS-level
      capture of apps that ignore proxy settings (pair with 'aegis transparent').

  aegis transparent [--undo] [--apply] [--uid <uid>] [--port <n>]
      Print (or --apply as root) the iptables REDIRECT rules that force traffic
      through the transparent proxy — works even for apps that ignore HTTPS_PROXY.

  aegis ca     [--export <path>]
      Show / export the root CA and OS trust instructions.

  aegis setup  [--undo]
      Auto-route ALL terminals through the base-URL guard.

  aegis app    [--config <path>] [--port <n>]
      Open the control panel as a standalone desktop app window.

  aegis pitch
      Open the Aegis pitch deck as a presentation window.

  aegis gui    [--config <path>] [--port <n>] [--open]
      Launch the local web control panel (default http://127.0.0.1:8799).

  aegis budget [--config <path>]              Show token / cost spend against the budget
  aegis status [--config <path>]              Check whether the guard is running
  aegis scan        [file] [--config <path>]  Scan a file (or stdin) for findings
  aegis scan-history [--path <dir>]           Scan the entire git history for secrets
  aegis report      [--since <iso>] [--format text|json] [--input <log>]
      Compliance report (PCI/HIPAA/GDPR) from the audit log.
  aegis optimize    [file] [--aggressive] [--print]
      Preview prompt-compression token savings on a file (or stdin).
  aegis init                                  Write a starter aegis.config.json

Examples:
  aegis proxy            # transparent system-wide interception
  aegis ca --export ./aegis-ca.crt
  aegis start --mode redact
  cat notes.txt | aegis scan
`);
      if (command && command !== "help" && command !== "--help") process.exitCode = 1;
  }
}

main();
