#!/usr/bin/env node
// bootstrap.mjs — reproducible fresh-clone bootstrap (node builtins only).
//
// Deterministic, ordered step plan:
//   tool-preflight -> node-check -> node-test -> gate-tests -> keyword-gate
//
// Fail-closed: a missing required tool exits 2 in every mode (the preflight
// runs first, so no step can fail with a raw ENOENT before the check); a
// failing step exits 1. No step is skipped silently and no step contains
// placeholders. All steps run against this repository's root, no matter
// which directory the script was invoked from.
//
// There is no --offline flag: unlike the Go toolchain this project has no
// dependency-download step at all (0 runtime dependencies), so the plan is
// identical on- and offline. See RELEASING.md.
//
// Exit codes: 0 = bootstrap green, 1 = step failed, 2 = missing tool/usage.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

/** Every external binary the full gate run depends on (plus node itself). */
export const REQUIRED_TOOLS = ["node", "gitleaks", "actionlint", "yamllint"];

/** Probe arguments per tool that print a version and exit 0. */
const PROBE_ARGS = {
  node: ["--version"],
  gitleaks: ["version"],
  actionlint: ["-version"],
  yamllint: ["--version"],
};

const REGISTRY = path.join("Dev", "school", "tool-registry", "registry.mjs");

/** Repository root, derived from this file - independent of the caller's cwd. */
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Absolute path of the machine tool registry if it exists on this machine,
 * null otherwise (fresh clones of this public repo on foreign machines).
 */
export function discoverRegistry(
  root = process.env.USERPROFILE || process.env.HOME || os.homedir(),
) {
  const candidate = path.join(root, REGISTRY);
  return existsSync(candidate) ? candidate : null;
}

/**
 * One install-hint line for the machine tool registry. Fails closed instead
 * of rendering "node undefined recipe ..." when no registry is known - callers
 * (describeMissing) only reach this inside their own `registryPath` guard.
 */
export function recipeHint(tool, registryPath = discoverRegistry()) {
  if (!registryPath) {
    throw new Error(`recipeHint(${tool}): no tool registry on this machine`);
  }
  return `node ${registryPath} recipe ${tool}`;
}

export function describeMissing(missing, { registryPath = discoverRegistry() } = {}) {
  const header = [
    `missing required tools: ${missing.join(", ")}`,
  ];
  if (registryPath) {
    return [
      ...header,
      "install them via the machine tool registry (school/tool-registry):",
      ...missing.map((t) => `  ${recipeHint(t, registryPath)}`),
    ].join("\n");
  }
  return [
    ...header,
    "install them with your platform package manager, then re-run; the exact",
    "bootstrap steps are documented in RELEASING.md (section 'Repository bootstrap'):",
    ...missing.map((t) => `  - ${t}`),
  ].join("\n");
}

/** All .mjs files shipped in this repository (checked one by one). */
export function collectMjsFiles(root = REPO_ROOT) {
  const files = [];
  for (const dir of [".", "src", "ci", "test"]) {
    const abs = path.join(root, dir);
    if (!statSync(abs).isDirectory()) continue;
    for (const name of readdirSync(abs)) {
      if (name.endsWith(".mjs")) {
        files.push(dir === "." ? name : path.join(dir, name).split(/[\\/]/).join("/"));
      }
    }
  }
  return files.sort();
}

/** All .mjs test files under test/ (run explicitly - Windows-safe). */
export function collectTestFiles(root = REPO_ROOT) {
  const dir = path.join(root, "test");
  const files = statSync(dir).isDirectory()
    ? readdirSync(dir).filter((n) => n.endsWith(".mjs")).map((n) => `test/${n}`)
    : [];
  return files.sort();
}

/**
 * The bootstrap step plan - identical in every mode (there is no module
 * download step; the tool preflight is always first so a missing tool fails
 * with exit 2 before any step executes).
 */
export function planSteps(root = REPO_ROOT) {
  return [
    {
      id: "tool-preflight",
      kind: "preflight",
      cmd: "preflight",
      argv: [...REQUIRED_TOOLS],
    },
    {
      id: "node-check",
      kind: "node-check",
      cmd: process.execPath,
      argv: ["--check", ...collectMjsFiles(root)],
    },
    {
      id: "node-test",
      kind: "exec",
      cmd: process.execPath,
      argv: ["--test", ...collectTestFiles(root)],
    },
    {
      id: "gate-tests",
      kind: "exec",
      cmd: process.execPath,
      argv: ["--test", "ci/test-gates.mjs", "ci/test-bootstrap.mjs"],
    },
    { id: "keyword-gate", kind: "exec", cmd: process.execPath, argv: ["ci/check-keywords.mjs"] },
  ];
}

/** Probe one tool; returns true only if it exists and its probe exits 0. */
export function probeTool(tool, exec = spawnSync) {
  const res = exec(tool, PROBE_ARGS[tool] || ["--version"], { encoding: "utf8" });
  if (res.error) return false;
  return res.status === 0;
}

export function preflight(tools, probe = probeTool) {
  return tools.filter((t) => !probe(t));
}

function runStep(step) {
  if (step.kind === "node-check") {
    // node --check ignores files after the first, so every file is checked
    // in its own invocation - a failing file fails the step with its name.
    for (let i = 1; i < step.argv.length; i++) {
      const file = step.argv[i];
      const res = spawnSync(step.cmd, ["--check", file], { encoding: "utf8" });
      if (res.error) {
        process.stderr.write(`bootstrap: ${step.id}: ${res.error.message}\n`);
        return false;
      }
      if (res.status !== 0) {
        process.stderr.write(`bootstrap: ${step.id} failed for ${file}\n`);
        if (res.stderr) process.stderr.write(res.stderr + "\n");
        return false;
      }
    }
    process.stdout.write(`bootstrap: ${step.id} ok (${step.argv.length - 1} file(s))\n`);
    return true;
  }
  const res = spawnSync(step.cmd, step.argv, { encoding: "utf8" });
  if (res.error) {
    process.stderr.write(`bootstrap: ${step.id}: ${res.error.message}\n`);
    return false;
  }
  const out = (res.stdout || "").trim();
  if (res.status !== 0) {
    process.stderr.write(`bootstrap: ${step.id} failed (exit ${res.status})\n`);
    if (out) process.stderr.write(out + "\n");
    if (res.stderr) process.stderr.write(res.stderr + "\n");
    return false;
  }
  process.stdout.write(`bootstrap: ${step.id} ok\n`);
  return true;
}

export function main(argv) {
  process.chdir(REPO_ROOT);
  if (argv.includes("--help")) {
    process.stdout.write(
      "usage: node ci/bootstrap.mjs\n" +
        "  (no flags: the plan is deterministic and has no download step)\n" +
        "exit 0 = green, 1 = step failed, 2 = missing tool/usage\n",
    );
    return 0;
  }
  if (argv.length > 0) {
    process.stderr.write(`bootstrap: unknown argument: ${argv[0]}\n`);
    return 2;
  }
  for (const step of planSteps()) {
    if (step.kind === "preflight") {
      const missing = preflight(step.argv);
      if (missing.length > 0) {
        process.stderr.write(describeMissing(missing) + "\n");
        return 2;
      }
      process.stdout.write("bootstrap: tool-preflight ok\n");
      continue;
    }
    if (!runStep(step)) return 1;
  }
  process.stdout.write("bootstrap: green\n");
  return 0;
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked !== "" && fileURLToPath(import.meta.url) === invoked) {
  process.exit(main(process.argv.slice(2)));
}
