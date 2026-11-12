// runner.mjs — THE ONLY production module allowed to import child_process.
//
// Enforced by ci/check-keywords.mjs (SCOPE-EXEC-001): any other production
// file referencing child_process fails the build. The runner executes a
// fixed, read-only probe allowlist - nothing else. There is no plumbing to
// run arbitrary commands: argv arrays are constructed from the PROBES table
// below, never from user input.
//
// Write verbs are forbidden by the same gate (SCOPE-EXEC-002). Keep comments
// in this file free of mutating command names.

import { spawnSync } from "node:child_process";
import process from "node:process";

/**
 * The read-only probe allowlist. Each probe is a fixed argv for a read-only
 * query. PowerShell probes run -NoProfile -NonInteractive and force UTF-8
 * console output; schtasks speaks the system console encoding (ASCII catalog
 * task names are unaffected - documented limitation in the README).
 */
export const PROBES = {
  "process-list": {
    windows: true,
    argv: [
      "powershell.exe",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance Win32_Process | Select-Object Name,ExecutablePath | ConvertTo-Csv -NoTypeInformation",
    ],
    encoding: "utf8",
    timeoutMs: 120000,
  },
  "service-list": {
    windows: true,
    argv: [
      "powershell.exe",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,State,StartMode | ConvertTo-Csv -NoTypeInformation",
    ],
    encoding: "utf8",
    timeoutMs: 120000,
  },
  "uninstall-list": {
    windows: true,
    argv: [
      "powershell.exe",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-ItemProperty -ErrorAction SilentlyContinue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Select-Object DisplayName,InstallLocation | ConvertTo-Csv -NoTypeInformation",
    ],
    encoding: "utf8",
    timeoutMs: 120000,
  },
  "task-list": {
    windows: true,
    argv: ["schtasks.exe", "/query", "/fo", "csv", "/nh"],
    encoding: "utf8",
    timeoutMs: 120000,
  },
};

/**
 * Execute one probe by id. Returns { ok, stdout, stderr, status, error }.
 * Never throws for exec failures - the scan records probe errors as
 * warnings and keeps going (fail-closed at the report level: an inventory
 * built from partial probes says so).
 */
export function runProbe(probeId, exec = spawnSync, platform = process.platform) {
  const probe = PROBES[probeId];
  if (!probe) {
    return { ok: false, stdout: "", stderr: "", status: null, error: `unknown probe: ${probeId}` };
  }
  if (probe.windows && platform !== "win32") {
    return {
      ok: false,
      stdout: "",
      stderr: "",
      status: null,
      error: `probe '${probeId}' requires Windows (this is ${platform})`,
    };
  }
  let res;
  try {
    res = exec(probe.argv[0], probe.argv.slice(1), {
      encoding: probe.encoding,
      timeout: probe.timeoutMs,
      windowsHide: true,
    });
  } catch (err) {
    return { ok: false, stdout: "", stderr: "", status: null, error: err.message };
  }
  if (res.error) {
    return { ok: false, stdout: res.stdout ?? "", stderr: res.stderr ?? "", status: res.status, error: res.error.message };
  }
  if (res.status !== 0) {
    return {
      ok: false,
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
      status: res.status,
      error: `probe exited ${res.status}`,
    };
  }
  return { ok: true, stdout: res.stdout ?? "", stderr: res.stderr ?? "", status: res.status, error: null };
}

/** True when running on Windows - scan refuses to start anywhere else. */
export function isWindows(platform = process.platform) {
  return platform === "win32";
}
