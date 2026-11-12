// scan.mjs — run the read-only probes and build the RMM tool inventory.
//
// The scan never mutates the system: it only parses output of the probe
// allowlist (src/runner.mjs). Probe failures are recorded as warnings and
// the inventory states which probes were used - partial data is labelled,
// never silently presented as complete.

import { toolCount } from "./catalog.mjs";
import {
  clip,
  ikey,
  parseCsv,
  parsePowerShellCsv,
  wildcardMatch,
  windowsBasename,
} from "./parse.mjs";

export const PROBE_IDS = ["process-list", "service-list", "uninstall-list", "task-list"];

/**
 * Run all probes through `runProbe` and collect raw probe results.
 * Returns { probes: { <probeId>: {ok, stdout, error} } , warnings: [...] }.
 */
export function collectProbes(runProbe) {
  const probes = {};
  const warnings = [];
  for (const id of PROBE_IDS) {
    const res = runProbe(id);
    probes[id] = { ok: res.ok, stdout: res.stdout, error: res.error };
    if (!res.ok) {
      warnings.push(`probe ${id} failed: ${res.error}`);
    }
  }
  return { probes, warnings };
}

/** Match a catalog value list against one observed value. */
function anyMatch(values, observed) {
  return values.some((v) => wildcardMatch(v, observed));
}

/**
 * Evaluate one catalog tool against the parsed probe data.
 * Returns an inventory entry {tool_id, tool_name, evidence[]} or null.
 * evidence items: {kind, detail} where kind in
 *   process | service | uninstall | scheduled-task
 */
export function matchTool(tool, data) {
  const artifacts = tool.artifacts ?? {};
  const evidence = [];

  for (const rec of data.processes) {
    const base = windowsBasename(rec.name);
    if (base && anyMatch(artifacts.processes ?? [], base)) {
      evidence.push({
        kind: "process",
        detail: `process ${clip(rec.name)}${rec.path ? ` at ${clip(rec.path)}` : " (path unavailable)"}`,
        path: rec.path || null,
      });
    }
  }

  for (const rec of data.services) {
    if (anyMatch(artifacts.services ?? [], rec.name)) {
      evidence.push({
        kind: "service",
        detail: `service ${clip(rec.name)}${rec.pathname ? ` via ${clip(rec.pathname)}` : ""} (${clip(rec.state)})`,
        path: rec.pathname || null,
      });
    } else if (rec.pathname && windowsBasename(rec.pathname) && anyMatch(artifacts.processes ?? [], windowsBasename(rec.pathname))) {
      evidence.push({
        kind: "service",
        detail: `service ${clip(rec.name)} runs ${clip(windowsBasename(rec.pathname))} (${clip(rec.state)})`,
        path: rec.pathname || null,
      });
    }
  }

  for (const rec of data.uninstalls) {
    const display = ikey(rec.display);
    if (
      display &&
      (display === ikey(tool.name) || anyMatch(artifacts.uninstall_key_names ?? [], rec.display))
    ) {
      evidence.push({
        kind: "uninstall",
        detail: `uninstall entry ${clip(rec.display)}${rec.location ? ` at ${clip(rec.location)}` : ""}`,
        path: rec.location || null,
      });
    }
  }

  for (const rec of data.tasks) {
    // schtasks TaskName is a task path like \\Microsoft\\Windows\\X\\Y;
    // catalog names may be patterns - compare the full path and the leaf.
    const leaf = rec.task.replace(/^\\+/, "").split("\\").pop() ?? "";
    if (anyMatch(artifacts.scheduled_tasks ?? [], leaf) || anyMatch(artifacts.scheduled_tasks ?? [], rec.task)) {
      evidence.push({
        kind: "scheduled-task",
        detail: `scheduled task ${clip(rec.task)} (${clip(rec.status)})`,
        path: null,
      });
    }
  }

  if (evidence.length === 0) return null;
  return { tool_id: tool.id, tool_name: tool.name, evidence };
}

/**
 * Build the inventory from probe output + catalog.
 * `catalog` is a validated catalog document.
 */
export function buildInventory(catalog, probeOut) {
  const data = {
    processes: [],
    services: [],
    uninstalls: [],
    tasks: [],
  };
  let skippedRows = 0;

  const pRes = parsePowerShellCsv(probeOut["process-list"]?.stdout ?? "", ["name", "path"]);
  for (const rec of pRes.records) {
    if (rec.name) data.processes.push({ name: rec.name, path: rec.path });
  }
  skippedRows += pRes.skipped;

  const sRes = parsePowerShellCsv(probeOut["service-list"]?.stdout ?? "", [
    "name",
    "display",
    "pathname",
    "state",
    "startmode",
  ]);
  for (const rec of sRes.records) {
    if (rec.name) data.services.push(rec);
  }
  skippedRows += sRes.skipped;

  const uRes = parsePowerShellCsv(probeOut["uninstall-list"]?.stdout ?? "", ["display", "location"]);
  for (const rec of uRes.records) {
    if (rec.display) data.uninstalls.push(rec);
  }
  skippedRows += uRes.skipped;

  const tRes = parseCsv(probeOut["task-list"]?.stdout ?? "", { header: false });
  for (const row of tRes.rows) {
    // schtasks /nh CSV: TaskName, Next Run Time, Status (+possibly more)
    if (row.length >= 3) {
      data.tasks.push({ task: row[0], next: row[1], status: row[2] });
    } else {
      skippedRows++;
    }
  }
  skippedRows += tRes.skipped;

  const inventory = [];
  for (const tool of catalog.tools) {
    const entry = matchTool(tool, data);
    if (entry) inventory.push(entry);
  }
  inventory.sort((a, b) => (a.tool_id < b.tool_id ? -1 : a.tool_id > b.tool_id ? 1 : 0));

  return {
    inventory,
    probes_run: PROBE_IDS.filter((id) => probeOut[id]?.ok),
    probes_failed: PROBE_IDS.filter((id) => !probeOut[id]?.ok),
    warnings: probeOut.warnings ?? [],
    skipped_rows: skippedRows,
    catalog_tools: toolCount(catalog),
  };
}
