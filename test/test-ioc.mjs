// test-ioc.mjs — IOC/Sigma generator tests: determinism is pinned.
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildIocs, iocCsv, iocJson, sigmaRulesForTool, sigmaYaml, uuid5 } from "../src/ioc.mjs";
import { loadCatalog } from "../src/catalog.mjs";

const catalog = loadCatalog("test/fixtures/catalog-mini.json");
const real = loadCatalog("data/rmm-catalog.json");

test("uuid5 is deterministic and RFC 4122 v5-shaped", () => {
  const a = uuid5("x");
  const b = uuid5("x");
  const c = uuid5("y");
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("buildIocs transcribes catalog values only", () => {
  const iocs = buildIocs(catalog);
  const synth = iocs.filter((i) => i.tool_id === "synthrmm");
  const types = new Set(synth.map((i) => i.type));
  assert.ok(types.has("process-name"));
  assert.ok(types.has("service-name"));
  assert.ok(types.has("scheduled-task"));
  assert.ok(types.has("uninstall-key"));
  assert.ok(types.has("install-path"));
  const processIoc = synth.find((i) => i.type === "process-name");
  assert.equal(processIoc.value, "synthrmm.exe");
  assert.equal(processIoc.confidence, "catalog-derived");
  assert.match(processIoc.id, /^RS-IOC-synthrmm-processes$/);
});

test("the shipped catalog produces a plausible IOC count", () => {
  const iocs = buildIocs(real);
  assert.ok(iocs.length >= 500, `too few IOCs: ${iocs.length}`);
  assert.ok(iocs.length <= 10000, `too many IOCs: ${iocs.length}`);
  for (const ioc of iocs) {
    assert.ok(ioc.value && ioc.value.length > 0);
    assert.ok(real.tools.some((t) => t.id === ioc.tool_id));
  }
});

test("iocJson output is stable for the same catalog", () => {
  const a = JSON.stringify(iocJson(catalog, { version: "0.1.0" }));
  const b = JSON.stringify(iocJson(catalog, { version: "0.1.0" }));
  assert.equal(a, b);
  const doc = JSON.parse(a);
  assert.equal(doc.schema_version, "1.0");
  assert.equal(doc.count, doc.iocs.length);
});

test("iocCsv escapes commas and quotes", () => {
  const text = iocCsv(catalog);
  const lines = text.trimEnd().split("\n");
  assert.equal(lines[0], "type,value,tool_id");
  assert.ok(lines.some((l) => l.startsWith("process-name,synthrmm.exe,synthrmm")));
  const weirdCatalog = {
    ...catalog,
    tools: [{ id: "w", name: "W", artifacts: { processes: ['has,comma"x"'] } }],
  };
  const csv = iocCsv(weirdCatalog);
  assert.match(csv, /"has,comma""x"""/);
});

test("sigma rules for a tool: process rule", () => {
  const tool = catalog.tools.find((t) => t.id === "synthrmm");
  const rules = sigmaRulesForTool(tool, catalog);
  const proc = rules.find((r) => r.detection.selection_process_name);
  assert.ok(proc, JSON.stringify(rules.map((r) => r.title)));
  assert.equal(proc.logsource.product, "windows");
  assert.equal(proc.logsource.category, "process_creation");
  assert.deepEqual(proc.detection.selection_process_name["Image|endswith"], ["\\synthrmm.exe"]);
  assert.equal(proc.level, "medium");
  assert.match(proc.description, /Presence is not evidence of misuse/);
});

test("sigma rules for a tool: service rule with EventID 7045", () => {
  const tool = catalog.tools.find((t) => t.id === "synthrmm");
  const rules = sigmaRulesForTool(tool, catalog);
  const svc = rules.find((r) => r.detection.selection_service_name);
  assert.ok(svc);
  assert.deepEqual(svc.detection.selection_event, { EventID: 7045 });
  assert.deepEqual(svc.detection.selection_service_name.ServiceName, ["SynthRMM"]);
  assert.equal(svc.detection.condition, "selection_event and selection_service_name");
});

test("sigmaYaml is byte-stable and well-formed for the shipped catalog", () => {
  const a = sigmaYaml(real);
  const b = sigmaYaml(real);
  assert.equal(a, b);
  assert.ok(a.startsWith("---\n") || a.startsWith("title:"));
  const docs = a.split(/\n---\n/);
  assert.ok(docs.length >= 200, `expected many rules, got ${docs.length}`);
  for (const doc of docs) {
    assert.match(doc, /^title: /);
    assert.match(doc, /\nid: [0-9a-f-]{36}\n/);
    assert.match(doc, /\nlevel: medium\n/);
  }
});

test("sigmaYaml has no invented values: every Image endswith exists in the catalog", () => {
  const text = sigmaYaml(real);
  const ends = [...text.matchAll(/\\([\w.*()-]+\.exe)/g)].map((m) => m[1]);
  const known = new Set(real.tools.flatMap((t) => t.artifacts?.processes ?? []));
  for (const e of ends) assert.ok(known.has(e), `invented process name: ${e}`);
});
