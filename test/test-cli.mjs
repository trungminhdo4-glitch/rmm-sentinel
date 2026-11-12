// test-cli.mjs — CLI wiring tests. scan/signals would execute real read-only
// probes on this machine, so the automated CLI tests cover everything that is
// deterministic offline: usage, bad flags, catalog failures, tools/ioc output
// against the synthetic fixture, --out writes and exit codes. The probe
// plumbing itself is unit-tested with a fake runner in test-scan.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { main } from "../rmm-sentinel.mjs";
import { VERSION } from "../src/version.mjs";

const repoRoot = join(fileURLToPath(new URL("..", import.meta.url)), "");
const CLI = join(repoRoot, "rmm-sentinel.mjs");
const MINI = "test/fixtures/catalog-mini.json";

function runCli(args, { cwd = repoRoot } = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
}

test("version command prints the pinned version", () => {
  const res = runCli(["version"]);
  assert.equal(res.status, 0);
  assert.equal(res.stdout.trim(), `rmm-sentinel ${VERSION}`);
});

test("package.json version matches src/version.mjs (single source of truth)", () => {
  const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
  assert.equal(pkg.version, VERSION);
});

test("--help exits 0 and documents the commands", () => {
  const res = runCli(["--help"]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /scan/);
  assert.match(res.stdout, /signals/);
  assert.match(res.stdout, /ioc/);
  assert.match(res.stdout, /Exit codes: 0 = clean/, "exit codes are part of the contract");
});

test("no command prints usage and exits 2", () => {
  const res = runCli([]);
  assert.equal(res.status, 2);
  assert.match(res.stdout, /usage:/);
});

test("unknown command exits 2", () => {
  const res = runCli(["pwn"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /unknown command: 'pwn'/);
});

test("missing flag value exits 2", () => {
  const res = runCli(["ioc", "--format"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /requires a value/);
});

test("unexpected positional argument exits 2", () => {
  const res = runCli(["tools", "extra"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /unexpected argument/);
});

test("unreadable catalog exits 2 with a fail-closed message", () => {
  const res = runCli(["ioc", "--catalog", "test/fixtures/does-not-exist.json"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /cannot read catalog/);
});

test("invalid catalog JSON exits 2", () => {
  const res = runCli(["ioc", "--catalog", "test/fixtures/catalog-invalid-json.json"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /not valid JSON/);
});

test("tools command lists the synthetic fixture catalog", () => {
  const res = runCli(["tools", "--catalog", MINI]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /synthrmm/);
  assert.match(res.stdout, /quickrmm/);
  assert.match(res.stdout, /synthetic test fixture/);
});

test("tools --format json is parseable", () => {
  const res = runCli(["tools", "--format", "json", "--catalog", MINI]);
  assert.equal(res.status, 0);
  const doc = JSON.parse(res.stdout);
  assert.equal(doc.tools.length, 2);
  assert.equal(doc.catalog_tools, 2);
});

test("ioc command generates JSON, CSV and Sigma deterministically", () => {
  const j1 = runCli(["ioc", "--catalog", MINI]);
  const j2 = runCli(["ioc", "--catalog", MINI]);
  assert.equal(j1.status, 0);
  assert.equal(j1.stdout, j2.stdout);
  const doc = JSON.parse(j1.stdout);
  assert.equal(doc.schema_version, "1.0");
  assert.ok(doc.count > 0);
  assert.equal(doc.iocs.length, doc.count);

  const csv = runCli(["ioc", "--catalog", MINI, "--format", "csv"]);
  assert.equal(csv.status, 0);
  assert.match(csv.stdout, /^type,value,tool_id\n/);

  const sigma = runCli(["ioc", "--catalog", MINI, "--format", "sigma"]);
  assert.equal(sigma.status, 0);
  assert.match(sigma.stdout, /title: "?RMM-Sentinel: SynthRMM process activity"?/);
  assert.match(sigma.stdout, /\nid: [0-9a-f-]{36}/);

  const bad = runCli(["ioc", "--catalog", MINI, "--format", "yaml"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /json\|csv\|sigma/);
});

test("--out writes the report (the only opt-in write)", () => {
  const dir = mkdtempSync(join(tmpdir(), "rmm-out-"));
  const outPath = join(dir, "iocs.json");
  try {
    const res = runCli(["ioc", "--catalog", MINI, "--out", outPath]);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /wrote .*iocs\.json/);
    const doc = JSON.parse(readFileSync(outPath, "utf8"));
    assert.ok(doc.count > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("main is importable and does not auto-execute on import", () => {
  assert.equal(typeof main, "function");
});
