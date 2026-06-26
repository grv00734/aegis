import * as vscode from "vscode";
import { DEFAULT_CONFIG } from "../../dist/config.js";
import type { AegisConfig, Category, Mode } from "../../dist/types.js";

/** Build a core AegisConfig from the user's VS Code settings. */
export function getConfig(): AegisConfig {
  const c = vscode.workspace.getConfiguration("aegis");
  return {
    ...DEFAULT_CONFIG,
    port: c.get<number>("proxy.port", DEFAULT_CONFIG.port),
    host: c.get<string>("proxy.host", DEFAULT_CONFIG.host),
    mode: c.get<Mode>("mode", DEFAULT_CONFIG.mode),
    blockOn: c.get<Category[]>("blockOn", DEFAULT_CONFIG.blockOn),
    detectors: {
      secrets: c.get<boolean>("detectors.secrets", true),
      pii: c.get<boolean>("detectors.pii", true),
      identity: c.get<boolean>("detectors.identity", true),
      network: c.get<boolean>("detectors.network", true),
      dictionary: c.get<boolean>("detectors.dictionary", true),
      code: c.get<boolean>("detectors.code", true),
      entropy: c.get<boolean>("detectors.entropy", false),
    },
    dictionary: c.get<string[]>("dictionary", []),
    code: {
      markers: c.get<string[]>("code.markers", DEFAULT_CONFIG.code.markers),
      internalNamespaces: c.get<string[]>("code.internalNamespaces", []),
    },
    routes: DEFAULT_CONFIG.routes,
    defaultUpstream: DEFAULT_CONFIG.defaultUpstream,
    // The extension routes audit events to an Output channel, not a file.
    auditLog: undefined,
  };
}

export function diagnosticsEnabled(): boolean {
  return vscode.workspace.getConfiguration("aegis").get<boolean>("diagnostics.enabled", true);
}

export function setTerminalEnvEnabled(): boolean {
  return vscode.workspace.getConfiguration("aegis").get<boolean>("proxy.setTerminalEnv", true);
}

export function autoStartEnabled(): boolean {
  return vscode.workspace.getConfiguration("aegis").get<boolean>("proxy.autoStart", false);
}
