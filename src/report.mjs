// report.mjs — text/JSON renderers and the only opt-in filesystem writer.
//
// ci/check-keywords.mjs (SCOPE-WRITE-001) pins all write APIs to this file.
// Without --out nothing is ever written: `writeIfOut` is called only when
// the CLI parsed an --out path, and its writer is injectable so tests can
// prove the no-write default.

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** Text renderer for an inventory document. */
export function renderInventoryText(doc) {
  const lines = [];
  lines.push(`RMM-Sentinel ${doc.version} - read-only RMM inventory (no system changes)`);
  lines.push(`catalog: ${doc.catalog_version} (${doc.catalog_tools} tools), probes ok: ${doc.probes_run.join(", ") || "none"}`);
  if (doc.probes_failed.length) {
    lines.push(`probes failed (partial inventory!): ${doc.probes_failed.join(", ")}`);
  }
  if (doc.skipped_rows > 0) lines.push(`skipped malformed rows: ${doc.skipped_rows}`);
  lines.push("");
  if (doc.inventory.length === 0) {
    lines.push("No catalogued RMM tools detected on this host.");
    lines.push("");
    lines.push("A clean run means \"no known RMM artifacts found\" - it is not a guarantee.");
    return lines.join("\n");
  }
  lines.push(`Detected ${doc.inventory.length} catalogued RMM tool(s):`);
  for (const entry of doc.inventory) {
    lines.push("");
    lines.push(`- ${entry.tool_name} (${entry.tool_id})`);
    for (const ev of entry.evidence) lines.push(`  [${ev.kind}] ${ev.detail}`);
  }
  lines.push("");
  lines.push("Presence of a tool is context, not evidence of misuse.");
  return lines.join("\n");
}

/** Text renderer for signals. */
export function renderSignalsText(doc) {
  const lines = [];
  lines.push(`RMM-Sentinel ${doc.version} - abuse-signal review (heuristic, for human review)`);
  lines.push(`signals: ${doc.signals.length}, fail-on: ${doc.fail_on}`);
  if (doc.signals.length === 0) {
    lines.push("");
    lines.push("No abuse signals above 'info' were raised. This is not a guarantee.");
    return lines.join("\n");
  }
  lines.push("");
  for (const s of doc.signals) {
    lines.push(`${s.severity.toUpperCase().padEnd(6)} ${s.rule_id}${s.tool_id ? ` (${s.tool_id})` : ""}: ${s.detail}`);
    lines.push(`       ${s.why}`);
    for (const fp of s.falsepositives) lines.push(`       falsepositive: ${fp}`);
  }
  if (doc.signals.length > 0 && doc.failing_count === 0) {
    lines.push("");
    lines.push(`WARNING: signals exist but none at or above --fail-on ${doc.fail_on}`);
  }
  return lines.join("\n");
}

/** Text renderer for the IOC catalog. */
export function renderIocText(doc) {
  const lines = [];
  lines.push(`RMM-Sentinel ${doc.version} - IOC catalog (offline, derived from the shipped catalog)`);
  lines.push(`iocs: ${doc.count}, catalog: ${doc.catalog_version}`);
  lines.push("");
  lines.push("Use --format json|csv|sigma for machine-readable output.");
  return lines.join("\n");
}

/**
 * Write `content` to `outPath` via the injectable writer - but only when
 * `outPath` is a non-empty string. Returns outPath or null (nothing written).
 */
export function writeIfOut(content, outPath, writer = writeFileSync, mkDir = mkdirSync) {
  if (typeof outPath !== "string" || outPath.trim() === "") return null;
  const dir = dirname(outPath);
  if (dir && dir !== "." && dir !== "/") mkDir(dir, { recursive: true });
  writer(outPath, content, "utf8");
  return outPath;
}
