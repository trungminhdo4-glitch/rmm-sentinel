// test-scan.mjs — inventory building with a fake runner (node:test, offline).
// Tests never execute real probes: the runner is injectable and the fixtures
// simulate the exact probe output shapes.
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildInventory, collectProbes, matchTool, PROBE_IDS } from "../src/scan.mjs";
import { loadCatalog } from "../src/catalog.mjs";

/** Fake probe runner: fixture outputs keyed by probe id. */
function fakeRunner(outputs, { ok = true } = {}) {
  return (probeId) => {
    if (!PROBE_IDS.includes(probeId)) {
      return { ok: false, stdout: "", stderr: "", status: null, error: `unknown probe: ${probeId}` };
    }
    const stdout = outputs[probeId] ?? "";
    if (!ok) return { ok: false, stdout: "", stderr: "boom", status: 1, error: "probe exited 1" };
    return { ok: true, stdout, stderr: "", status: 0, error: null };
  };
}

const FIXTURES = {
  "process-list": '"Name","ExecutablePath"\n"SynthRMM.exe","C:\\Program Files\\SynthRMM\\SynthRMM.exe"\n"explorer.exe","C:\\Windows\\explorer.exe"\n"agent.exe","C:\\Temp\\agent.exe"\n',
  "service-list": '"Name","DisplayName","PathName","State","StartMode"\n"SynthRMM","SynthRMM Service","C:\\Program Files\\SynthRMM\\SynthRMM.exe","Running","Auto"\n"WinDefend","Defender","C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe","Running","Auto"\n',
  "uninstall-list": '"DisplayName","InstallLocation"\n"SynthRMM","C:\\Program Files\\SynthRMM\\"\n"SomeOther","C:\\Elsewhere\\"\n',
  "task-list": '"\\SynthRMMUpdateTask1","2026-11-13 03:00","Bereit"\n"\\Microsoft\\Windows\\Defrag","2026-11-13 01:00","Ready"\n',
};

test("collectProbes runs exactly the four allowlisted probes and records failures", () => {
  const seen = [];
  const out = collectProbes((id) => {
    seen.push(id);
    if (id === "uninstall-list") return { ok: false, stdout: "", stderr: "", status: 1, error: "probe exited 1" };
    return { ok: true, stdout: "", stderr: "", status: 0, error: null };
  });
  assert.deepEqual(seen.sort(), [...PROBE_IDS].sort());
  assert.equal(out.warnings.length, 1);
  assert.match(out.warnings[0], /uninstall-list failed/);
  assert.equal(out.probes["uninstall-list"].ok, false);
});

test("buildInventory finds the synthetic tool from fixture output", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const runProbe = fakeRunner(FIXTURES);
  const { probes, warnings } = collectProbes(runProbe);
  const doc = buildInventory(catalog, probes);
  assert.equal(warnings.length, 0);
  assert.equal(doc.probes_failed.length, 0);
  assert.deepEqual(doc.probes_run, PROBE_IDS);
  assert.equal(doc.inventory.length, 1);
  const entry = doc.inventory[0];
  assert.equal(entry.tool_id, "synthrmm");
  const kinds = entry.evidence.map((e) => e.kind).sort();
  assert.deepEqual(kinds, ["process", "scheduled-task", "service", "uninstall"]);
  assert.match(entry.evidence.find((e) => e.kind === "process").detail, /SynthRMM\.exe/);
  assert.match(entry.evidence.find((e) => e.kind === "uninstall").detail, /SynthRMM/);
});

test("buildInventory reports failed probes as warnings and partial inventory", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const { probes, warnings } = collectProbes(fakeRunner(FIXTURES, { ok: false }));
  const doc = buildInventory(catalog, probes);
  assert.equal(doc.probes_run.length, 0);
  assert.equal(doc.probes_failed.length, PROBE_IDS.length);
  assert.equal(warnings.length, PROBE_IDS.length);
  assert.equal(doc.inventory.length, 0);
});

test("buildInventory is robust against empty probe output", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const { probes, warnings } = collectProbes(fakeRunner({}));
  const doc = buildInventory(catalog, probes);
  assert.equal(warnings.length, 0);
  assert.equal(doc.inventory.length, 0);
});

test("matchTool matches catalog service binary names even when the service name differs", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const tool = catalog.tools.find((t) => t.id === "quickrmm");
  const data = {
    processes: [],
    services: [{ name: "SomeSvc", display: "QuickRMM Agent", pathname: "C:\\ProgramData\\QuickRMM\\quickrmm_agent.exe", state: "Running", startmode: "Auto" }],
    uninstalls: [],
    tasks: [],
  };
  const entry = matchTool(tool, data);
  assert.ok(entry);
  assert.equal(entry.evidence[0].kind, "service");
  assert.match(entry.evidence[0].detail, /quickrmm_agent\.exe/);
});

test("matchTool does not attribute unrelated artifacts", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const tool = catalog.tools.find((t) => t.id === "synthrmm");
  const data = {
    processes: [{ name: "quickrmm_agent.exe", path: "C:\\ProgramData\\QuickRMM\\quickrmm_agent.exe" }],
    services: [],
    uninstalls: [{ display: "QuickRMM", location: "" }],
    tasks: [],
  };
  assert.equal(matchTool(tool, data), null);
});

test("buildInventory counts skipped malformed rows", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const outputs = {
    ...FIXTURES,
    "task-list": '"\\Good","x","Ready"\n"malformed-row"\n',
  };
  const { probes } = collectProbes(fakeRunner(outputs));
  const doc = buildInventory(catalog, probes);
  assert.equal(doc.skipped_rows, 1);
});
