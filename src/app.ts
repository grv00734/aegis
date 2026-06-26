/**
 * Launches the Aegis dashboard as a standalone desktop window using a
 * Chromium-family browser in "app mode" (--app=URL). This gives a chromeless,
 * single-purpose window that appears in the taskbar like a native application —
 * without bundling Electron. Falls back to the default browser if no Chromium
 * binary is found.
 */
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";

const LINUX_BINS = [
  "google-chrome",
  "google-chrome-stable",
  "chromium",
  "chromium-browser",
  "brave-browser",
  "microsoft-edge",
  "microsoft-edge-stable",
  "vivaldi",
];

const MAC_PATHS = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
];

const WIN_PATHS = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
];

/** Find a binary on PATH (Linux) without spawning a shell. */
function onPath(bin: string): string | null {
  const dirs = (process.env.PATH ?? "").split(delimiter);
  for (const d of dirs) {
    if (d && existsSync(join(d, bin))) return join(d, bin);
  }
  return null;
}

export function findBrowser(): string | null {
  if (process.platform === "darwin") {
    return MAC_PATHS.find((p) => existsSync(p)) ?? null;
  }
  if (process.platform === "win32") {
    return WIN_PATHS.find((p) => existsSync(p)) ?? null;
  }
  for (const bin of LINUX_BINS) {
    const found = onPath(bin);
    if (found) return found;
  }
  return null;
}

export interface AppLaunch {
  launched: boolean;
  browser?: string;
}

/** Open `url` in a dedicated app window. Returns whether a browser was launched. */
export function launchApp(url: string, size = "560,820", profileName = "aegis-app-profile"): AppLaunch {
  const bin = findBrowser();
  if (!bin) return { launched: false };

  // A separate profile dir keeps the app window isolated from the user's
  // normal browsing session and guarantees a fresh, frameless window.
  const profile = join(tmpdir(), profileName);
  const args = [
    `--app=${url}`,
    `--user-data-dir=${profile}`,
    `--window-size=${size}`,
    "--no-first-run",
    "--no-default-browser-check",
  ];

  try {
    const child = spawn(bin, args, { detached: true, stdio: "ignore" });
    child.on("error", () => undefined);
    child.unref();
    return { launched: true, browser: bin };
  } catch {
    return { launched: false };
  }
}
