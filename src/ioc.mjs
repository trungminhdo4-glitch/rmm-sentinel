// ioc.mjs — offline IOC and Sigma-rule generator over the catalog (pure).
//
// Generates exactly what the local scan can verify: process names, service
// names, scheduled-task names, uninstall-key names and install-path prefixes.
// No hashes, no domains, no invented values: every emitted IOC is a direct
// transcription of a catalog entry. Output is deterministic - the same
// catalog always produces byte-identical output (pinned by tests).

import { createHash } from "node:crypto";

/** Deterministic RFC 4122 v5 UUID (SHA-1 based) - no deps, stable. */
export function uuid5(name, namespaceHex = "d3b07384-d9a1-4b7c-9b2d-8f6c5a4e3d21") {
  const nsBuf = Buffer.from(String(namespaceHex).replace(/-/g, ""), "hex");
  const nameBuf = Buffer.from(String(name), "utf8");
  const hash = createHash("sha1").update(nsBuf).update(nameBuf).digest();
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const h = hash.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** One IOC object per catalog artifact value. */
export function buildIocs(catalog) {
  const iocs = [];
  const kinds = [
    ["processes", "process-name"],
    ["services", "service-name"],
    ["scheduled_tasks", "scheduled-task"],
    ["uninstall_key_names", "uninstall-key"],
    ["install_paths", "install-path"],
  ];
  for (const tool of catalog.tools) {
    const artifacts = tool.artifacts ?? {};
    for (const [kind, type] of kinds) {
      for (const value of artifacts[kind] ?? []) {
        iocs.push({
          id: `RS-IOC-${tool.id}-${kind}`,
          type,
          value,
          tool_id: tool.id,
          tool_name: tool.name,
          confidence: "catalog-derived",
        });
      }
    }
  }
  return iocs;
}

/** JSON output shape (schema pinned: may only change with a MAJOR bump). */
export function iocJson(catalog, meta = {}) {
  const iocs = buildIocs(catalog);
  return {
    schema_version: "1.0",
    generator: "rmm-sentinel",
    generator_version: meta.version ?? "dev",
    catalog_version: catalog.version,
    catalog_generated_at: catalog.generated_at,
    license_note: catalog.license_note,
    count: iocs.length,
    iocs,
  };
}

/** CSV output: type,value,tool_id - one row per IOC. */
export function iocCsv(catalog) {
  const rows = [["type", "value", "tool_id"].join(",")];
  for (const ioc of buildIocs(catalog)) {
    rows.push([ioc.type, csvField(ioc.value), ioc.tool_id].join(","));
  }
  return `${rows.join("\n")}\n`;
}

function csvField(value) {
  const s = String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Minimal YAML emitter for the small, flat Sigma shapes below. */
function yamlString(value) {
  const s = String(value);
  if (/^[A-Za-z0-9_][A-Za-z0-9_. -]*$/.test(s) && !/^(true|false|null|on|off|yes|no)$/i.test(s)) return s;
  return JSON.stringify(s);
}

/**
 * Emit Sigma rules for one tool: a process-creation rule and a service-
 * installation rule (EventID 7045). IDs are deterministic uuid5s.
 */
export function sigmaRulesForTool(tool, catalog) {
  const rules = [];
  const artifacts = tool.artifacts ?? {};
  const catalogs = `RMM-Sentinel catalog ${catalog.version} (derived from LOLRMM ${catalog.source?.snapshot_date ?? "snapshot"}; see NOTICE)`;
  const falsepositives = ["Approved remote-support deployments", "Managed environments where this tool is standard"];

  if ((artifacts.processes ?? []).length > 0) {
    rules.push({
      title: `RMM-Sentinel: ${tool.name} process activity`,
      id: uuid5(`rmm-sentinel:${catalog.version}:process:${tool.id}`),
      status: "test",
      description: `Detects process names catalogued for ${tool.name}. Source: ${catalogs}. Presence is not evidence of misuse.`,
      logsource: { product: "windows", category: "process_creation" },
      detection: {
        selection_process_name: {
          "Image|endswith": artifacts.processes.map((p) => `\\${p}`),
        },
        condition: "selection_process_name",
      },
      falsepositives,
      level: "medium",
      tags: ["rmm_sentinel"],
    });
  }

  if ((artifacts.services ?? []).length > 0) {
    rules.push({
      title: `RMM-Sentinel: ${tool.name} service installation`,
      id: uuid5(`rmm-sentinel:${catalog.version}:service:${tool.id}`),
      status: "test",
      description: `Detects service-control-manager installation events (EventID 7045) whose service name matches the ${tool.name} catalogue. Source: ${catalogs}. Presence is not evidence of misuse.`,
      logsource: { product: "windows", service: "system" },
      detection: {
        selection_event: { EventID: 7045 },
        selection_service_name: {
          ServiceName: artifacts.services,
        },
        condition: "selection_event and selection_service_name",
      },
      falsepositives,
      level: "medium",
      tags: ["rmm_sentinel"],
    });
  }

  return rules;
}

/** All Sigma rules for the catalog, as a YAML document (--- separated). */
export function sigmaYaml(catalog) {
  const docs = [];
  for (const tool of catalog.tools) {
    for (const rule of sigmaRulesForTool(tool, catalog)) {
      docs.push(sigmaToYaml(rule));
    }
  }
  return docs.length ? `${docs.join("\n---\n")}\n` : "";
}

function sigmaToYaml(rule) {
  const lines = [];
  lines.push(`title: ${yamlString(rule.title)}`);
  lines.push(`id: ${rule.id}`);
  lines.push(`status: ${rule.status}`);
  lines.push(`description: ${yamlString(rule.description)}`);
  lines.push("logsource:");
  for (const [k, v] of Object.entries(rule.logsource)) {
    lines.push(`  ${k}: ${v}`);
  }
  lines.push("detection:");
  for (const [key, value] of Object.entries(rule.detection)) {
    if (key === "condition") continue;
    lines.push(`  ${key}:`);
    emitDetectionValue(lines, value, 4);
  }
  lines.push(`  condition: ${rule.detection.condition}`);
  lines.push("falsepositives:");
  for (const fp of rule.falsepositives) lines.push(`  - ${yamlString(fp)}`);
  lines.push(`level: ${rule.level}`);
  lines.push("tags:");
  for (const tag of rule.tags) lines.push(`  - ${tag}`);
  return lines.join("\n");
}

function emitDetectionValue(lines, value, indent) {
  const pad = " ".repeat(indent);
  if (Array.isArray(value)) {
    for (const item of value) lines.push(`${pad}- ${yamlString(item)}`);
    return;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (Array.isArray(v)) {
        lines.push(`${pad}${k}:`);
        emitDetectionValue(lines, v, indent + 2);
      } else {
        lines.push(`${pad}${k}: ${yamlString(v)}`);
      }
    }
    return;
  }
  lines.push(`${pad}${yamlString(value)}`);
}
