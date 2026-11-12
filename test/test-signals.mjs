// test-signals.mjs — signal-rule tests: every rule gets a matching AND a
// non-matching sample (PR rule: no signal rule without both).
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_MANY_FAMILIES_THRESHOLD,
  evaluateSignals,
  failsOn,
  SIGNAL_RULES,
} from "../src/signals.mjs";
import { loadCatalog } from "../src/catalog.mjs";

const catalog = loadCatalog("test/fixtures/catalog-mini.json");

function inv(toolId, evidence) {
  const tool = catalog.tools.find((t) => t.id === toolId);
  return [{ tool_id: toolId, tool_name: tool.name, evidence }];
}

test("every rule is documented with why and falsepositives", () => {
  for (const rule of SIGNAL_RULES) {
    assert.ok(rule.id.startsWith("RS-SIG-"));
    assert.ok(["info", "low", "medium", "high"].includes(rule.severity));
    assert.ok(rule.title.length > 10);
    assert.ok(rule.why.length > 20);
    assert.ok(rule.falsepositives.length > 0);
  }
});

test("RS-SIG-001: service binary outside typical locations is flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "service", detail: "service SynthRMM (Running)", path: "C:\\Custom\\SynthRMM\\SynthRMM.exe" }]),
  );
  const hit = findings.find((f) => f.rule_id === "RS-SIG-001");
  assert.ok(hit, JSON.stringify(findings));
  assert.equal(hit.severity, "medium");
  assert.equal(hit.tool_id, "synthrmm");
});

test("RS-SIG-001: service binary in typical location is not flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "service", detail: "service SynthRMM (Running)", path: "C:\\Program Files\\SynthRMM\\SynthRMM.exe" }]),
  );
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-001"));
});

test("RS-SIG-002: process in a user-writable path is flagged high", () => {
  const findings = evaluateSignals(
    catalog,
    inv("quickrmm", [{ kind: "process", detail: "process quickrmm_agent.exe", path: "C:\\Users\\a\\Downloads\\quickrmm_agent.exe" }]),
  );
  const hit = findings.find((f) => f.rule_id === "RS-SIG-002");
  assert.ok(hit);
  assert.equal(hit.severity, "high");
});

test("RS-SIG-002: process in ProgramData tool dir is not flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("quickrmm", [{ kind: "process", detail: "process quickrmm_agent.exe", path: "C:\\ProgramData\\QuickRMM\\quickrmm_agent.exe" }]),
  );
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-002"));
});

test("RS-SIG-003: service whose binary is not catalogued is flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "service", detail: "service SynthRMM (Running)", path: "C:\\Program Files\\SynthRMM\\renamed_helper.exe" }]),
  );
  const hit = findings.find((f) => f.rule_id === "RS-SIG-003");
  assert.ok(hit);
  assert.equal(hit.severity, "medium");
});

test("RS-SIG-003: catalogued service binary is not flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "service", detail: "service SynthRMM (Running)", path: "C:\\Program Files\\SynthRMM\\SynthRMM.exe" }]),
  );
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-003"));
});

test("RS-SIG-004: uninstall location outside documented dirs is flagged low", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "uninstall", detail: "uninstall entry SynthRMM", path: "C:\\Custom\\Roaming\\" }]),
  );
  const hit = findings.find((f) => f.rule_id === "RS-SIG-004");
  assert.ok(hit);
  assert.equal(hit.severity, "low");
});

test("RS-SIG-004: uninstall inside documented dirs is not flagged", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "uninstall", detail: "uninstall entry SynthRMM", path: "C:\\Program Files\\SynthRMM\\" }]),
  );
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-004"));
});

test("RS-SIG-004: uninstall without a location raises nothing", () => {
  const findings = evaluateSignals(
    catalog,
    inv("synthrmm", [{ kind: "uninstall", detail: "uninstall entry SynthRMM", path: null }]),
  );
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-004"));
});

test("RS-SIG-005: many families are flagged info at the default threshold", () => {
  assert.equal(DEFAULT_MANY_FAMILIES_THRESHOLD, 4);
  const catalog2 = { ...catalog, tools: [] };
  for (let i = 0; i < 4; i++) {
    catalog2.tools.push({ id: `tool${i}`, name: `Tool${i}`, artifacts: {} });
  }
  const inventory = catalog2.tools.map((t) => ({ tool_id: t.id, tool_name: t.name, evidence: [{ kind: "process", detail: "process x.exe" }] }));
  const findings = evaluateSignals(catalog2, inventory);
  const hit = findings.find((f) => f.rule_id === "RS-SIG-005");
  assert.ok(hit);
  assert.equal(hit.severity, "info");
});

test("RS-SIG-005: below threshold raises nothing", () => {
  const catalog2 = { ...catalog, tools: [{ id: "a", name: "A", artifacts: {} }] };
  const inventory = [{ tool_id: "a", tool_name: "A", evidence: [{ kind: "process", detail: "process x.exe" }] }];
  const findings = evaluateSignals(catalog2, inventory);
  assert.ok(!findings.some((f) => f.rule_id === "RS-SIG-005"));
});

test("RS-SIG-005 threshold is configurable", () => {
  const catalog2 = { ...catalog, tools: [{ id: "a", name: "A", artifacts: {} }, { id: "b", name: "B", artifacts: {} }] };
  const inventory = catalog2.tools.map((t) => ({ tool_id: t.id, tool_name: t.name, evidence: [] }));
  const findings = evaluateSignals(catalog2, inventory, { manyFamiliesThreshold: 2 });
  assert.ok(findings.some((f) => f.rule_id === "RS-SIG-005"));
});

test("findings are sorted high before info", () => {
  const catalog2 = { ...catalog, tools: [] };
  for (let i = 0; i < 5; i++) catalog2.tools.push({ id: `t${i}`, name: `T${i}`, artifacts: {} });
  const inventory = catalog2.tools.map((t) => ({
    tool_id: t.id,
    tool_name: t.name,
    evidence: [{ kind: "process", detail: "process x.exe at C:\\Users\\a\\Downloads\\x.exe" }],
  }));
  const findings = evaluateSignals(catalog2, inventory);
  const severities = findings.map((f) => f.severity);
  const firstInfo = severities.indexOf("info");
  assert.ok(severities.slice(0, firstInfo).every((s) => s === "high" || s === "medium" || s === "low"));
});

test("failsOn filters by severity order", () => {
  const findings = [
    { rule_id: "RS-SIG-002", severity: "high" },
    { rule_id: "RS-SIG-001", severity: "medium" },
    { rule_id: "RS-SIG-004", severity: "low" },
  ];
  assert.equal(failsOn(findings, "high").length, 1);
  assert.equal(failsOn(findings, "medium").length, 2);
  assert.equal(failsOn(findings, "low").length, 3);
  assert.equal(failsOn(findings, "info").length, 3);
});
