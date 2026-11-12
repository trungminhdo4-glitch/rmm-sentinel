// signals.mjs — abuse-signal evaluation over a built inventory (pure).
//
// Signal rules are heuristics for *human review*, never verdicts. Each rule
// documents its own false positives; a clean scan means "no known risky
// patterns", not "safe". Rule IDs RS-SIG-<NNN> are part of the public
// contract (see RELEASING.md) and may only change with a MAJOR bump.

import { isTypicalInstallPath, isUserWritablePath, windowsBasename, wildcardMatch } from "./parse.mjs";

export const SIGNAL_SEVERITIES = ["info", "low", "medium", "high"];

/**
 * The signal rule catalogue. Every rule: { id, title, severity, why,
 * falsepositives }. Rules are data-driven over the inventory + catalog.
 */
export const SIGNAL_RULES = [
  {
    id: "RS-SIG-001",
    title: "RMM service binary outside its documented install locations",
    severity: "medium",
    why: "A catalogued RMM service runs from a directory that matches none of the tool's documented install locations. Attackers renaming or relocating agents leave exactly this shape; legitimate custom-directory installs do too.",
    falsepositives: ["Intentional custom install directories approved by your organisation"],
  },
  {
    id: "RS-SIG-002",
    title: "RMM process running from a user-writable location",
    severity: "high",
    why: "A catalogued RMM process runs from Temp, Downloads, Public, Desktop or Recycle. Attackers drop agents in exactly these locations to avoid detection; quick-support sessions may legitimately do the same.",
    falsepositives: ["Vendor quick-support ('run from Temp') sessions used by your service desk"],
  },
  {
    id: "RS-SIG-003",
    title: "RMM service whose binary name is not catalogued for the tool",
    severity: "medium",
    why: "A service matching a catalogued RMM tool name runs a binary whose name is not in the tool's catalogued process list. Renamed agents and sideloaded builds show this shape; vendor service helpers may as well.",
    falsepositives: ["Vendor helper binaries that changed names between releases"],
  },
  {
    id: "RS-SIG-004",
    title: "RMM uninstall entry pointing outside documented install locations",
    severity: "low",
    why: "The uninstall entry of a catalogued RMM tool records an InstallLocation outside the tool's documented locations. Partial transfers or repackaged agents leave this shape.",
    falsepositives: ["Administrators choosing custom install roots"],
  },
  {
    id: "RS-SIG-005",
    title: "Many distinct RMM tool families present",
    severity: "info",
    why: "More RMM tool families than the configured threshold are installed on this host. Sprawl itself is not malicious, but every additional family widens the remote-access surface.",
    falsepositives: ["MSP-managed hosts that legitimately run several client agent families"],
  },
];

export const DEFAULT_MANY_FAMILIES_THRESHOLD = 4;

/**
 * Evaluate all signal rules. Returns a list of findings
 * { rule_id, title, severity, tool_id?, detail, why, falsepositives }.
 * Sorted by severity (high first) then rule id.
 */
export function evaluateSignals(catalog, inventory, opts = {}) {
  const threshold = Number.isInteger(opts.manyFamiliesThreshold)
    ? opts.manyFamiliesThreshold
    : DEFAULT_MANY_FAMILIES_THRESHOLD;
  const byId = new Map(catalog.tools.map((t) => [t.id, t]));
  const findings = [];
  const foundToolIds = new Set(inventory.map((e) => e.tool_id));

  for (const entry of inventory) {
    const tool = byId.get(entry.tool_id);
    if (!tool) continue;
    for (const ev of entry.evidence) {
      if (ev.kind === "service") {
        const pathname = ev.path;
        if (pathname && tool.artifacts?.install_paths?.length) {
          if (!isTypicalInstallPath(pathname, tool)) {
            findings.push(makeFinding("RS-SIG-001", tool, `service binary at ${pathname}`));
          }
          const base = windowsBasename(pathname);
          if (base && !anyMatchProcesses(tool, base)) {
            findings.push(
              makeFinding("RS-SIG-003", tool, `service binary '${base}' is not in the catalogued process list`),
            );
          }
        }
      }
      if (ev.kind === "process") {
        const path = ev.path;
        if (path && isUserWritablePath(path)) {
          findings.push(makeFinding("RS-SIG-002", tool, `process running from ${path}`));
        }
      }
      if (ev.kind === "uninstall") {
        const loc = ev.path;
        if (loc && tool.artifacts?.install_paths?.length && !isTypicalInstallPath(loc, tool)) {
          findings.push(makeFinding("RS-SIG-004", tool, `uninstall location ${loc}`));
        }
      }
    }
  }

  if (foundToolIds.size >= threshold) {
    findings.push({
      rule_id: "RS-SIG-005",
      title: ruleById("RS-SIG-005").title,
      severity: "info",
      tool_id: null,
      detail: `${foundToolIds.size} distinct RMM tool families present (threshold ${threshold})`,
      why: ruleById("RS-SIG-005").why,
      falsepositives: ruleById("RS-SIG-005").falsepositives,
    });
  }

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) =>
    order[a.severity] - order[b.severity] || (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0),
  );
  return findings;
}

function anyMatchProcesses(tool, base) {
  return (tool.artifacts?.processes ?? []).some((p) => wildcardMatch(p, base));
}

function ruleById(id) {
  return SIGNAL_RULES.find((r) => r.id === id);
}

function makeFinding(ruleId, tool, detail) {
  const rule = ruleById(ruleId);
  return {
    rule_id: ruleId,
    title: rule.title,
    severity: rule.severity,
    tool_id: tool.id,
    detail,
    why: rule.why,
    falsepositives: rule.falsepositives,
  };
}

/**
 * Signals at or above the fail-on severity. Returns [high, medium, low, info]
 * -> a signal of severity `sev` fails when its order <= the fail-on order.
 */
export function failsOn(findings, failOn) {
  const order = { info: 0, low: 1, medium: 2, high: 3 };
  const min = order[failOn] ?? 3;
  return findings.filter((f) => (order[f.severity] ?? 0) >= min);
}
