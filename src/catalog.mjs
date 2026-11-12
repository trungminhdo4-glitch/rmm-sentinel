// catalog.mjs — load and validate the RMM tool catalog (data/rmm-catalog.json).
//
// The catalog is inert data (CC-BY-4.0 metadata, derived from LOLRMM under
// Apache-2.0 attribution - see NOTICE). Nothing here talks to the network.
// A malformed catalog fails closed: loadCatalog throws CatalogError, which the
// CLI maps to exit 2. Every value is matched case-insensitively at scan time;
// '*' inside a value is a wildcard segment, never a path traversal primitive.

import { readFileSync } from "node:fs";

export const ARTIFACT_KINDS = [
  "processes",
  "services",
  "scheduled_tasks",
  "uninstall_key_names",
  "install_paths",
  "typical_dirs",
];

export class CatalogError extends Error {}

/** Check one artifact value: non-empty string, no control characters. */
function checkArtifactValue(toolId, kind, value, problems) {
  if (typeof value !== "string" || value.trim() === "") {
    problems.push(`${toolId}.${kind}: artifact value must be a non-empty string`);
    return;
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f]/.test(value)) {
    problems.push(`${toolId}.${kind}: artifact value contains control characters`);
  }
}

/**
 * Validate one catalog entry. Returns a list of problem strings (empty = ok).
 * Structural contract of schema rmm-sentinel-catalog/1:
 *   id: [a-z0-9-]+ slug, unique, <= 64 chars
 *   name: non-empty string
 *   artifacts: optional object; every present kind is an array of non-empty
 *              strings; unknown kinds are rejected (typo-proof data)
 *   references: optional array of non-empty strings
 */
export function validateTool(tool) {
  const problems = [];
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    return ["tool entry must be an object"];
  }
  if (typeof tool.id !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(tool.id)) {
    problems.push(`tool id invalid: ${JSON.stringify(tool.id)}`);
  }
  if (typeof tool.name !== "string" || tool.name.trim() === "") {
    problems.push(`${tool.id}: name must be a non-empty string`);
  }
  const artifacts = tool.artifacts;
  if (artifacts !== undefined) {
    if (!artifacts || typeof artifacts !== "object" || Array.isArray(artifacts)) {
      problems.push(`${tool.id}: artifacts must be an object when present`);
    } else {
      for (const kind of Object.keys(artifacts)) {
        if (!ARTIFACT_KINDS.includes(kind)) {
          problems.push(`${tool.id}: unknown artifact kind '${kind}'`);
          continue;
        }
        const list = artifacts[kind];
        if (!Array.isArray(list)) {
          problems.push(`${tool.id}.${kind}: must be an array`);
          continue;
        }
        for (const value of list) checkArtifactValue(tool.id, kind, value, problems);
      }
      if (artifacts.install_paths && !Array.isArray(artifacts.install_paths)) {
        problems.push(`${tool.id}.install_paths: must be an array`);
      }
      if (
        artifacts.install_paths &&
        artifacts.typical_dirs &&
        !Array.isArray(artifacts.typical_dirs)
      ) {
        problems.push(`${tool.id}.typical_dirs: must be an array`);
      }
    }
  }
  if (tool.references !== undefined) {
    if (!Array.isArray(tool.references)) {
      problems.push(`${tool.id}: references must be an array when present`);
    } else if (tool.references.some((r) => typeof r !== "string" || r.trim() === "")) {
      problems.push(`${tool.id}: references must be non-empty strings`);
    }
  }
  return problems;
}

/**
 * Validate the whole catalog document. Returns { problems, duplicateIds }.
 */
export function validateCatalog(doc) {
  const problems = [];
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { problems: ["catalog must be an object"], duplicateIds: [] };
  }
  if (doc.schema !== "rmm-sentinel-catalog/1") {
    problems.push(`unsupported schema: ${JSON.stringify(doc.schema)}`);
  }
  if (typeof doc.version !== "string" || doc.version.trim() === "") {
    problems.push("catalog.version must be a non-empty string");
  }
  if (!Array.isArray(doc.tools)) {
    problems.push("catalog.tools must be an array");
    return { problems, duplicateIds: [] };
  }
  const seen = new Map();
  const duplicateIds = [];
  for (const tool of doc.tools) {
    problems.push(...validateTool(tool));
    if (tool && typeof tool.id === "string") {
      if (seen.has(tool.id)) duplicateIds.push(tool.id);
      seen.set(tool.id, true);
    }
  }
  return { problems, duplicateIds };
}

/**
 * Load and validate the catalog from disk. Throws CatalogError on any
 * structural problem - the CLI maps that to exit 2 (fail closed).
 */
export function loadCatalog(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new CatalogError(`cannot read catalog '${path}': ${err.message}`);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new CatalogError(`catalog '${path}' is not valid JSON: ${err.message}`);
  }
  const { problems, duplicateIds } = validateCatalog(doc);
  if (problems.length > 0 || duplicateIds.length > 0) {
    const dup = duplicateIds.length ? ` duplicate ids: ${duplicateIds.join(", ")}.` : "";
    throw new CatalogError(
      `catalog '${path}' failed validation:${dup} ${problems.slice(0, 10).join("; ")}`,
    );
  }
  return doc;
}

/** Number of tools in a catalog document. */
export function toolCount(doc) {
  return Array.isArray(doc.tools) ? doc.tools.length : 0;
}
