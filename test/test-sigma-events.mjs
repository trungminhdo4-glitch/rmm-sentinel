// Offline event conformance checks for the subset emitted by our generator.
// This test helper is not a Sigma backend or a claim about SIEM field mappings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadCatalog } from "../src/catalog.mjs";
import { sigmaRulesForTool, sigmaYaml } from "../src/ioc.mjs";

const catalog = loadCatalog("test/fixtures/catalog-mini.json");
const tool = catalog.tools.find((entry) => entry.id === "synthrmm");
const fixtures = JSON.parse(readFileSync(new URL("fixtures/sigma-events.json", import.meta.url), "utf8"));

function sigmaRegex(pattern, endswith) {
  let expression = endswith ? "" : "^";
  for (let index = 0; index < pattern.length; index++) {
    let ch = pattern[index];
    if (ch === "\\" && /[\\*?]/.test(pattern[index + 1] ?? "")) {
      ch = pattern[++index];
    } else if (ch === "*") {
      expression += "[\\s\\S]*";
      continue;
    } else if (ch === "?") {
      expression += "[\\s\\S]";
      continue;
    }
    expression += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${expression}$`, "i");
}

function matchesSelection(selection, event) {
  return Object.entries(selection).every(([key, patterns]) => {
    const [field, modifier] = key.split("|");
    if (!Object.hasOwn(event, field)) return false;
    return (Array.isArray(patterns) ? patterns : [patterns]).some((pattern) =>
      typeof pattern === "number"
        ? event[field] === pattern
        : sigmaRegex(pattern, modifier === "endswith").test(event[field]),
    );
  });
}

function matchesRule(rule, event) {
  const detection = rule.detection;
  if (detection.selection_process_name) return matchesSelection(detection.selection_process_name, event);
  if (!matchesSelection(detection.selection_event, event)) return false;
  if (detection.selection_service_name) return matchesSelection(detection.selection_service_name, event);
  return Object.entries(detection).some(([name, selection]) =>
    name.startsWith("selection_task_") && matchesSelection(selection, event),
  );
}

test("generated process, service and task selections match synthetic positive and negative events", () => {
  const rules = sigmaRulesForTool(tool, catalog);
  const byKind = {
    process: rules.find((rule) => rule.logsource.category === "process_creation"),
    service: rules.find((rule) => rule.logsource.service === "system"),
    task: rules.find((rule) => rule.logsource.service === "security"),
  };
  assert.ok(byKind.task, "a catalogued task needs an event rule");
  assert.equal(byKind.task.detection.condition, "selection_event and 1 of selection_task_*");
  for (const fixture of fixtures) {
    assert.equal(matchesRule(byKind[fixture.kind], fixture.event), fixture.match, JSON.stringify(fixture));
  }
});

test("task rules keep full paths exact and catalog question marks literal", () => {
  const taskTool = { ...tool, artifacts: { scheduled_tasks: ["\\Known\\FixedTask", "Literal?Task", "*Agent"] } };
  const [rule] = sigmaRulesForTool(taskTool, catalog);
  for (const name of ["\\Known\\FixedTask", "\\Folder\\Literal?Task", "\\Folder\\SupportAgent"]) {
    assert.equal(matchesRule(rule, { EventID: 4698, TaskName: name }), true, name);
  }
  for (const name of ["\\Other\\Known\\FixedTask", "\\Folder\\LiteralXTask", "\\Folder\\SupportAgentBackup"]) {
    assert.equal(matchesRule(rule, { EventID: 4698, TaskName: name }), false, name);
  }
  assert.match(sigmaYaml({ ...catalog, tools: [taskTool] }), /TaskName\|endswith:/);
  assert.equal(rule.logsource.service, "security");
  assert.match(rule.description, /auditing/);
  assert.match(rule.description, /Presence is not evidence of misuse/);
});

test("tools without task artifacts emit no task rule", () => {
  const rules = sigmaRulesForTool(catalog.tools.find((entry) => entry.id === "quickrmm"), catalog);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].logsource.category, "process_creation");
});

test("shipped task rule count follows catalog entries and IDs are stable and unique", () => {
  const real = loadCatalog("data/rmm-catalog.json");
  const rules = real.tools.flatMap((entry) => sigmaRulesForTool(entry, real));
  const tasks = rules.filter((rule) => rule.logsource.service === "security");
  assert.equal(tasks.length, real.tools.filter((entry) => entry.artifacts.scheduled_tasks?.length).length);
  assert.equal(new Set(rules.map((rule) => rule.id)).size, rules.length);
  for (const rule of rules) assert.deepEqual(rule.tags, ["rmm_sentinel.catalog"]);
});
