// test-catalog.mjs — catalog schema validation tests (node:test, offline).
import { test } from "node:test";
import assert from "node:assert/strict";

import { loadCatalog, toolCount, validateCatalog, validateTool, CatalogError } from "../src/catalog.mjs";

test("the shipped catalog validates and has a healthy size", () => {
  const doc = loadCatalog("data/rmm-catalog.json");
  assert.equal(doc.schema, "rmm-sentinel-catalog/1");
  assert.equal(doc.version, "0.1.0");
  assert.ok(toolCount(doc) >= 200, `expected >= 200 tools, got ${toolCount(doc)}`);
  assert.ok(toolCount(doc) <= 400);
  // provenance must be present
  assert.equal(doc.source.name, "LOLRMM (Living Off The Land - Remote Monitoring & Management)");
  assert.equal(doc.source.license, "Apache-2.0");
  assert.ok(doc.source.snapshot_date);
});

test("known catalogued RMM families are present", () => {
  const doc = loadCatalog("data/rmm-catalog.json");
  const ids = new Set(doc.tools.map((t) => t.id));
  for (const id of ["anydesk", "teamviewer", "screenconnect", "splashtop", "rustdesk", "meshcentral", "atera"]) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
});

test("every tool carries at least one artifact kind", () => {
  const doc = loadCatalog("data/rmm-catalog.json");
  for (const tool of doc.tools) {
    const kinds = Object.keys(tool.artifacts);
    assert.ok(kinds.length > 0, `${tool.id} has no artifacts`);
  }
});

test("validateTool accepts a well-formed entry", () => {
  assert.deepEqual(
    validateTool({ id: "x", name: "X", artifacts: { processes: ["x.exe"] }, references: ["https://x"] }),
    [],
  );
});

test("validateTool rejects unknown artifact kinds", () => {
  const problems = validateTool({ id: "x", name: "X", artifacts: { procs: ["x.exe"] } });
  assert.ok(problems.some((p) => /unknown artifact kind 'procs'/.test(p)));
});

test("validateTool rejects bad ids and empty values", () => {
  assert.ok(validateTool({ id: "Bad Id", name: "X" }).length > 0);
  assert.ok(validateTool({ id: "x", name: "", artifacts: { processes: [""] } }).length >= 2);
  assert.ok(validateTool({ id: "x", name: "X", artifacts: { processes: ["a\u0000b"] } }).length === 1);
});

test("validateCatalog rejects wrong schema and duplicate ids", () => {
  const res = validateCatalog({ schema: "other", tools: [{ id: "x", name: "X" }, { id: "x", name: "X" }] });
  assert.ok(res.problems.some((p) => /unsupported schema/.test(p)));
  assert.deepEqual(res.duplicateIds, ["x"]);
});

test("loadCatalog throws CatalogError on missing file", () => {
  assert.throws(() => loadCatalog("test/fixtures/does-not-exist.json"), CatalogError);
});

test("loadCatalog throws CatalogError on invalid JSON", () => {
  assert.throws(() => loadCatalog("test/fixtures/catalog-invalid-json.json"), CatalogError);
});

test("loadCatalog throws CatalogError on duplicate ids", () => {
  assert.throws(() => loadCatalog("test/fixtures/catalog-duplicate.json"), /duplicate ids: dup/);
});
