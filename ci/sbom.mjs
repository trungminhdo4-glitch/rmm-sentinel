#!/usr/bin/env node
// sbom.mjs — CycloneDX 1.6 SBOM for this node module (node builtins only).
//
// The module is dependency-free, so the bill of materials is fully
// deterministic: one application component for the CLI plus one file
// component (with a SHA-256 digest) for every shipped production file.
// Output is byte-stable for a given timestamp/tool-version pair.
//
// Exit codes: 0 = sbom written, 1 = invalid input, 2 = usage/tool error.

import { readFileSync, writeFileSync } from "node:fs";
import { readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import path, { join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { VERSION } from "../src/version.mjs";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..");

/**
 * The shipped production files, discovered deterministically: the CLI
 * entry point, every src/*.mjs, and the catalog data file. Sorted so the
 * SBOM is byte-stable. Fails closed (exit 2) when a listed file is missing.
 */
export function productionFiles(root = REPO_ROOT) {
  const files = ["rmm-sentinel.mjs", "data/rmm-catalog.json"];
  const srcDir = join(root, "src");
  if (!statSync(srcDir).isDirectory()) {
    throw new Error(`sbom: src/ directory missing under ${root}`);
  }
  for (const name of readdirSync(srcDir)) {
    if (name.endsWith(".mjs")) files.push(join("src", name));
  }
  return files
    .map((f) => f.split(/[\\/]/).join("/"))
    .sort()
    .map((f) => {
      const abs = join(root, f);
      try {
        const content = readFileSync(abs);
        return { path: f, sha256: createHash("sha256").update(content).digest("hex") };
      } catch (err) {
        throw new Error(`sbom: cannot read production file '${f}': ${err.message}`);
      }
    });
}

/** One CycloneDX file component per production file, with its SHA-256. */
function fileComponents(files) {
  return files.map((f) => ({
    type: "file",
    "bom-ref": `file:${f.path}`,
    name: f.path,
    hashes: [{ alg: "SHA-256", content: f.sha256 }],
  }));
}

export function buildBom(files, opts) {
  const components = fileComponents(files);
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    serialNumber: `urn:uuid:${opts.serial}`,
    metadata: {
      timestamp: opts.timestamp,
      tools: [
        {
          vendor: "trung-dev",
          name: "rmm-sentinel-sbom",
          version: opts.toolVersion,
        },
      ],
      component: {
        type: "application",
        "bom-ref": `pkg:generic/rmm-sentinel@${opts.toolVersion}`,
        name: "rmm-sentinel",
        version: opts.toolVersion,
        description: "Read-only Windows RMM inventory, abuse-signal scanner and IOC/rule generator (defensive)",
      },
    },
    components,
  };
}

export function validateBom(bom) {
  const problems = [];
  if (bom.bomFormat !== "CycloneDX") problems.push("bomFormat must be CycloneDX");
  if (bom.specVersion !== "1.6") problems.push("specVersion must be 1.6");
  if (!Array.isArray(bom.components) || bom.components.length === 0) {
    problems.push("components must be a non-empty array");
  }
  for (const c of bom.components ?? []) {
    if (!c.name || !c["bom-ref"]) problems.push(`component missing name/bom-ref: ${JSON.stringify(c)}`);
    if (!["library", "application", "framework", "container", "operating-system", "device", "firmware", "file"].includes(c.type)) {
      problems.push(`invalid component type: ${c.type}`);
    }
    if (c.type === "file") {
      const hashes = Array.isArray(c.hashes) ? c.hashes : [];
      if (!hashes.some((h) => h?.alg === "SHA-256" && /^[0-9a-f]{64}$/.test(h?.content ?? ""))) {
        problems.push(`file component without SHA-256 digest: ${c.name}`);
      }
    }
  }
  const app = bom.metadata?.component;
  if (app?.type !== "application") problems.push("metadata.component must be the application");
  return problems;
}

function deterministicSerial(input) {
  const hash = createHash("sha256").update(input).digest("hex");
  const h = hash.slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function main(argv) {
  const outIdx = argv.indexOf("--out");
  const outPath = outIdx >= 0 ? argv[outIdx + 1] : "sbom.cdx.json";
  const tsIdx = argv.indexOf("--timestamp");
  const timestamp = tsIdx >= 0 ? argv[tsIdx + 1] : new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const verIdx = argv.indexOf("--tool-version");
  const toolVersion = verIdx >= 0 ? argv[verIdx + 1] : VERSION;
  if (!outPath || argv.includes("--help")) {
    process.stderr.write(
      "usage: node ci/sbom.mjs [--out sbom.cdx.json] [--timestamp ISO] [--tool-version V]\n" +
        "exit 0 = written, 1 = invalid, 2 = tool error\n",
    );
    return argv.includes("--help") ? 0 : 2;
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(timestamp)) {
    process.stderr.write(`sbom: --timestamp must be ISO 8601 UTC (got '${timestamp}')\n`);
    return 2;
  }

  let files;
  try {
    files = productionFiles();
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    return 2;
  }

  const serial = deterministicSerial(
    files.map((f) => `${f.path}:${f.sha256}`).join("|") + timestamp + toolVersion,
  );
  const bom = buildBom(files, { serial, timestamp, toolVersion });
  const problems = validateBom(bom);
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`sbom: ${p}\n`);
    return 1;
  }
  writeFileSync(outPath, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
  process.stdout.write(`sbom: wrote ${outPath} (${bom.components.length} component(s))\n`);
  return 0;
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]).toLowerCase() : "";
if (invoked !== "" && path.resolve(fileURLToPath(import.meta.url)).toLowerCase() === invoked) {
  process.exit(main(process.argv.slice(2)));
}
