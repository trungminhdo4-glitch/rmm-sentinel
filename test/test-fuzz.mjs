// test-fuzz.mjs — deterministic robustness fuzzing for every parser (node:test).
//
// ModelGate pins every parser behind `go test -fuzz`. This project has no Go
// fuzzing, so the same goal is reached with a seeded pseudo-random mutation
// loop: each parser must never throw and must always return a structured
// result on hostile input. The seed is fixed; CI output is reproducible.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  expandWinVars,
  isTypicalInstallPath,
  isUserWritablePath,
  parseCsv,
  parseCsvRow,
  parsePowerShellCsv,
  typicalDirPrefix,
  wildcardMatch,
  windowsBasename,
  windowsDirname,
} from "../src/parse.mjs";
import { buildInventory } from "../src/scan.mjs";
import { evaluateSignals } from "../src/signals.mjs";
import { buildIocs, iocCsv, iocJson, sigmaYaml } from "../src/ioc.mjs";
import { validateCatalog } from "../src/catalog.mjs";
import { loadCatalog } from "../src/catalog.mjs";

/** mulberry32: tiny deterministic PRNG. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEED = 0x5eed;
const ROUNDS = 3000;

const SEEDS = [
  "Name,Path\n\"tool.exe\",\"C:\\x\\tool.exe\"",
  "\"SynthRMM\",\"C:\\Program Files\\SynthRMM\\\"",
  '"a,b","c""d",,',
  "a\r\nb\n",
  '"unclosed,"row"',
  ",,,",
  "%programdata%\\x\\*",
  "C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe",
  "\\TeamViewer","\\TeamViewer\\service",
  '"Task","Next","Status"',
  "\u0000\u001f\u007f",
  "\u00e4\u00f6\u00fc\u4e2d\u6587",
  "a".repeat(5000),
];

function mutate(text, rnd) {
  const ops = ["insert", "delete", "swap", "dup", "trunc"];
  const op = ops[Math.floor(rnd() * ops.length)];
  const i = Math.floor(rnd() * text.length);
  const junk = ['"', ",", "\n", "\\", "*", "%", "\u0000", "a", "-", "\\u202e"][Math.floor(rnd() * 10)];
  switch (op) {
    case "insert": return text.slice(0, i) + junk + text.slice(i);
    case "delete": return text.slice(0, i) + text.slice(i + 1);
    case "swap": return text.slice(0, i) + text.slice(i + 1, i + 2) + (text[i] ?? "") + text.slice(i + 2);
    case "dup": return text.slice(0, i) + text.slice(i, i + 40) + text.slice(i);
    case "trunc": return text.slice(0, i);
    default: return text;
  }
}

test("parseCsvRow and parseCsv never throw on mutated input", () => {
  const rnd = prng(SEED);
  for (let i = 0; i < ROUNDS; i++) {
    const text = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    const row = parseCsvRow(text.slice(0, 200));
    assert.ok(row === null || Array.isArray(row));
    const doc = parseCsv(text, { header: rnd() > 0.5 });
    assert.ok(Array.isArray(doc.rows));
    assert.ok(Number.isInteger(doc.skipped));
  }
});

test("parsePowerShellCsv never throws on mutated input", () => {
  const rnd = prng(SEED + 1);
  const cols = ["name", "path"];
  for (let i = 0; i < ROUNDS; i++) {
    const text = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    const out = parsePowerShellCsv(text, cols);
    assert.ok(Array.isArray(out.records));
    for (const rec of out.records) assert.equal(typeof rec.name, "string");
  }
});

test("path helpers never throw on mutated input", () => {
  const rnd = prng(SEED + 2);
  for (let i = 0; i < ROUNDS; i++) {
    const text = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    assert.equal(typeof windowsBasename(text), "string");
    assert.equal(typeof windowsDirname(text), "string");
    assert.equal(typeof wildcardMatch(text, "tool.exe"), "boolean");
    assert.equal(typeof expandWinVars(text), "string");
    assert.ok(isUserWritablePath(text) === true || isUserWritablePath(text) === false);
    const prefix = typicalDirPrefix(text);
    assert.ok(prefix === null || typeof prefix === "string");
  }
});

test("isTypicalInstallPath never throws with mutated paths and real catalog tools", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const rnd = prng(SEED + 3);
  for (let i = 0; i < ROUNDS; i++) {
    const text = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    for (const tool of catalog.tools) {
      const res = isTypicalInstallPath(text, tool);
      assert.ok(res === true || res === false);
    }
  }
});

test("buildInventory survives mutated probe output (fake runner)", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const rnd = prng(SEED + 4);
  const probeIds = ["process-list", "service-list", "uninstall-list", "task-list"];
  for (let i = 0; i < 800; i++) {
    const outputs = {};
    for (const id of probeIds) {
      outputs[id] = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    }
    const runProbe = (probeId) => ({
      ok: true, stdout: outputs[probeId] ?? "", stderr: "", status: 0, error: null,
    });
    const doc = buildInventory(catalog, collectFrom(runProbe, probeIds));
    assert.ok(Array.isArray(doc.inventory));
    for (const entry of doc.inventory) {
      assert.ok(entry.tool_id);
      assert.ok(Array.isArray(entry.evidence));
    }
  }
});

test("evaluateSignals survives mutated inventory", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const rnd = prng(SEED + 5);
  for (let i = 0; i < 800; i++) {
    const tool = catalog.tools[Math.floor(rnd() * catalog.tools.length)];
    const detail = mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd);
    const kinds = ["process", "service", "uninstall", "scheduled-task"];
    const inventory = [
      {
        tool_id: tool.id,
        tool_name: tool.name,
        evidence: [{ kind: kinds[Math.floor(rnd() * 4)], detail, path: rnd() > 0.5 ? detail : null }],
      },
    ];
    const findings = evaluateSignals(catalog, inventory);
    assert.ok(Array.isArray(findings));
    for (const f of findings) {
      assert.ok(f.rule_id.startsWith("RS-SIG-"));
      assert.ok(["info", "low", "medium", "high"].includes(f.severity));
    }
  }
});

test("ioc generators never throw on mutated catalogs", () => {
  const real = loadCatalog("data/rmm-catalog.json");
  const rnd = prng(SEED + 6);
  for (let i = 0; i < 300; i++) {
    const mutated = JSON.parse(JSON.stringify(real));
    const tool = mutated.tools[Math.floor(rnd() * mutated.tools.length)];
    const kinds = Object.keys(tool.artifacts);
    const kind = kinds[Math.floor(rnd() * kinds.length)];
    tool.artifacts[kind] = [mutate(SEEDS[Math.floor(rnd() * SEEDS.length)] ?? "", rnd)];
    const { problems } = validateCatalog(mutated);
    if (problems.length > 0) continue; // invalid catalogs are allowed to be rejected
    assert.ok(Array.isArray(buildIocs(mutated)));
    assert.equal(typeof iocJson(mutated, { version: "x" }), "object");
    assert.equal(typeof iocCsv(mutated), "string");
    assert.equal(typeof sigmaYaml(mutated), "string");
  }
});

function collectFrom(runProbe, probeIds) {
  const probes = {};
  for (const id of probeIds) {
    const res = runProbe(id);
    probes[id] = { ok: res.ok, stdout: res.stdout, error: res.error };
  }
  return { probes, warnings: [] };
}
