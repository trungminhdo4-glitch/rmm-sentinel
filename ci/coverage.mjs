#!/usr/bin/env node
// coverage.mjs — line-coverage gate over the node test runner (node builtins
// only). Runs `node --experimental-test-coverage --test`, parses the report
// table (verified format: "all files | line % | branch % | funcs %") and
// fails closed:
//   exit 0 = line coverage >= threshold AND every production file has a row
//   exit 1 = line coverage below the threshold
//   exit 2 = report unparseable, production file missing from the table, or
//            the test suite itself did not pass (never claim green without
//            evidence)
//
// Threshold default: 80. Override locally with --threshold (CI uses default).

import { readdirSync } from "node:fs";
import path, { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import process from "node:process";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..");

/** Files the coverage table must account for (production code only). */
export function coverageTargets(root = REPO_ROOT) {
  const files = ["rmm-sentinel.mjs"];
  for (const name of readdirSync(join(root, "src"))) {
    if (name.endsWith(".mjs")) files.push(join("src", name).split(/[\\/]/).join("/"));
  }
  return files.sort();
}

/**
 * Parse a coverage report table. Returns { linePct, presentFiles, missingFiles }
 * or null when the "all files" row is absent / its number unparseable.
 */
export function parseCoverageReport(report, expectedFiles = []) {
  const lines = report.split(/\r?\n/);
  const allFiles = lines.find((l) => /all files\s*\|/.test(l));
  if (!allFiles) return null;
  const m = /all files\s*\|\s*([\d.]+)/.exec(allFiles);
  if (!m) return null;
  const linePct = Number.parseFloat(m[1]);
  if (!Number.isFinite(linePct)) return null;
  const tableRows = lines.filter((l) => /\|\s*[\d.]+\s*\|/.test(l));
  const presentFiles = expectedFiles.filter((f) => {
    const base = f.split("/").pop();
    return tableRows.some((row) => row.includes(base));
  });
  const missingFiles = expectedFiles.filter((f) => !presentFiles.includes(f));
  return { linePct, presentFiles, missingFiles };
}

function main(argv) {
  const thrIdx = argv.indexOf("--threshold");
  const threshold = thrIdx >= 0 ? Number.parseFloat(argv[thrIdx + 1]) : 80;
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
    process.stderr.write(`coverage: invalid --threshold: ${argv[thrIdx + 1]}\n`);
    return 2;
  }
  if (argv.includes("--help")) {
    process.stdout.write(
      "usage: node ci/coverage.mjs [--threshold 80]\n" +
        "exit 0 = green, 1 = below threshold, 2 = unparseable/suite red\n",
    );
    return 0;
  }

  const res = spawnSync(process.execPath, ["--experimental-test-coverage", "--test"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 15 * 60 * 1000,
  });
  const output = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
  if (res.status !== 0) {
    process.stderr.write("coverage: test suite did not pass - refusing to evaluate coverage\n");
    process.stderr.write(output.slice(-4000) + "\n");
    return 2;
  }
  const parsed = parseCoverageReport(output, coverageTargets());
  if (parsed === null) {
    process.stderr.write("coverage: cannot parse the coverage report (no 'all files' row)\n");
    process.stderr.write(output.slice(-2000) + "\n");
    return 2;
  }
  if (parsed.missingFiles.length > 0) {
    process.stderr.write(`coverage: production files missing from the coverage table: ${parsed.missingFiles.join(", ")}\n`);
    return 2;
  }
  process.stdout.write(`coverage: line coverage ${parsed.linePct}% (gate ${threshold}%), all production files covered by the report\n`);
  if (parsed.linePct + 0 < threshold) {
    process.stdout.write(`coverage: BELOW the ${threshold}% gate\n`);
    return 1;
  }
  process.stdout.write("coverage: green\n");
  return 0;
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]).toLowerCase() : "";
if (invoked !== "" && path.resolve(fileURLToPath(import.meta.url)).toLowerCase() === invoked) {
  process.exit(main(process.argv.slice(2)));
}
