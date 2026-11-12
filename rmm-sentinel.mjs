#!/usr/bin/env node
// rmm-sentinel.mjs — CLI entry point (wiring only, no logic of its own).
//
// Commands:
//   scan      read-only inventory of catalogued RMM tools on this Windows host
//   signals   evaluate abuse-signal heuristics over the inventory
//   ioc       generate IOC/detection-rule output from the catalog (offline)
//   tools     list the shipped catalog
//   version   print the version
//
// Exit codes: 0 = clean / below fail-on, 1 = signals at or above fail-on,
// 2 = usage or runtime error (bad flags, unreadable catalog, non-Windows
// host for scan/signals, probe misconfiguration).

import process from "node:process";

import { CatalogError, loadCatalog, toolCount } from "./src/catalog.mjs";
import { iocCsv, iocJson, sigmaYaml } from "./src/ioc.mjs";
import { renderInventoryText, renderIocText, renderSignalsText, writeIfOut } from "./src/report.mjs";
import { isWindows, runProbe } from "./src/runner.mjs";
import { VERSION } from "./src/version.mjs";
import { buildInventory, collectProbes } from "./src/scan.mjs";
import { evaluateSignals, failsOn, SIGNAL_RULES } from "./src/signals.mjs";

const USAGE = `RMM-Sentinel ${VERSION} - defensive, read-only RMM scanner

usage: node rmm-sentinel.mjs <command> [flags]

commands:
  scan       read-only RMM inventory (services, processes, uninstall entries, tasks)
  signals    abuse-signal heuristics over the inventory
  ioc        IOC / detection-rule generator (offline, catalog only)
  tools      list the shipped catalog
  version    print the version

flags:
  --format <text|json>     output format (scan/signals); ioc also accepts csv|sigma
  --out <file>             opt-in: the ONLY filesystem write this tool ever does
  --fail-on <info|low|medium|high>   exit 1 when a signal at/above this severity
                                     exists (default: high)
  --catalog <file>         alternative catalog JSON (default: data/rmm-catalog.json)
  --many-families-threshold <n>      RS-SIG-005 threshold (default: 4)
  --help                   this text

Windows only for scan/signals. ioc/tools work on every platform.
Scan changes nothing: probes are read-only queries (see src/runner.mjs).

Exit codes: 0 = clean / below fail-on, 1 = signals at or above fail-on,
2 = usage or runtime error (bad flags, unreadable catalog, non-Windows host,
probe misconfiguration).
`;

function fail(message) {
  process.stderr.write(`rmm-sentinel: ${message}\n`);
  return 2;
}

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") flags.help = true;
    else if (arg === "--version") flags.version = true;
    else if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      let name;
      let value;
      if (eq >= 0) {
        name = arg.slice(2, eq);
        value = arg.slice(eq + 1);
      } else {
        name = arg.slice(2);
        value = argv[i + 1];
        i++;
      }
      if (value === undefined || value === "") return { error: `flag --${name} requires a value` };
      flags[name] = value;
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

function catalogPath(flags) {
  return flags.catalog ?? "data/rmm-catalog.json";
}

function loadValidatedCatalog(flags) {
  return loadCatalog(catalogPath(flags));
}

function emit(flags, content) {
  if (flags.out) {
    const written = writeIfOut(content, flags.out);
    process.stdout.write(`rmm-sentinel: wrote ${written}\n`);
  } else {
    process.stdout.write(`${content}\n`);
  }
}

function cmdScan(flags) {
  if (!isWindows()) {
    return fail("scan requires Windows (read-only local probes); 'ioc' and 'tools' work everywhere");
  }
  const catalog = loadValidatedCatalog(flags);
  const { probes, warnings } = collectProbes(runProbe);
  const doc = buildInventory(catalog, probes);
  const out = {
    schema_version: "1.0",
    generator: "rmm-sentinel",
    generator_version: VERSION,
    version: VERSION,
    catalog_version: catalog.version,
    catalog_tools: toolCount(catalog),
    probes_run: doc.probes_run,
    probes_failed: doc.probes_failed,
    warnings,
    skipped_rows: doc.skipped_rows,
    inventory: doc.inventory,
  };
  if (flags.format === "json") {
    emit(flags, JSON.stringify(out, null, 2));
  } else {
    emit(flags, renderInventoryText(out));
  }
  return 0;
}

function cmdSignals(flags) {
  if (!isWindows()) {
    return fail("signals requires Windows (read-only local probes); 'ioc' and 'tools' work everywhere");
  }
  const catalog = loadValidatedCatalog(flags);
  const failOn = flags["fail-on"] ?? "high";
  if (!(["info", "low", "medium", "high"].includes(failOn))) {
    return fail(`--fail-on must be one of info|low|medium|high (got '${failOn}')`);
  }
  const { probes, warnings } = collectProbes(runProbe);
  const doc = buildInventory(catalog, probes);
  const threshold = flags["many-families-threshold"]
    ? Number.parseInt(flags["many-families-threshold"], 10)
    : undefined;
  if (threshold !== undefined && (!Number.isInteger(threshold) || threshold < 1)) {
    return fail("--many-families-threshold must be a positive integer");
  }
  const signals = evaluateSignals(catalog, doc.inventory, { manyFamiliesThreshold: threshold });
  const failing = failsOn(signals, failOn);
  const out = {
    schema_version: "1.0",
    generator: "rmm-sentinel",
    generator_version: VERSION,
    version: VERSION,
    catalog_version: catalog.version,
    fail_on: failOn,
    rules: SIGNAL_RULES.map((r) => ({ id: r.id, severity: r.severity, title: r.title })),
    inventory_tools: doc.inventory.length,
    signals,
    failing_count: failing.length,
    warnings,
  };
  if (flags.format === "json") {
    emit(flags, JSON.stringify(out, null, 2));
  } else {
    emit(flags, renderSignalsText(out));
  }
  if (failing.length > 0) {
    process.stdout.write(`WARNING: ${failing.length} signal(s) at or above --fail-on ${failOn}\n`);
    return 1;
  }
  return 0;
}

function cmdIoc(flags) {
  const catalog = loadValidatedCatalog(flags);
  const meta = { version: VERSION };
  let content;
  let format = flags.format ?? "json";
  if (format === "json") content = JSON.stringify(iocJson(catalog, meta), null, 2);
  else if (format === "csv") content = iocCsv(catalog);
  else if (format === "sigma") content = sigmaYaml(catalog);
  else return fail(`--format for ioc must be json|csv|sigma (got '${format}')`);
  emit(flags, content);
  return 0;
}

function cmdTools(flags) {
  const catalog = loadValidatedCatalog(flags);
  if (flags.format === "json") {
    emit(flags, JSON.stringify({ version: VERSION, catalog_version: catalog.version, catalog_tools: toolCount(catalog), tools: catalog.tools.map((t) => ({ id: t.id, name: t.name })) }, null, 2));
    return 0;
  }
  const lines = [`RMM-Sentinel ${VERSION} - shipped catalog (schema ${catalog.schema})`, `catalog: ${catalog.version}, ${toolCount(catalog)} tools, generated ${catalog.generated_at}`, `source: ${catalog.source.name} (${catalog.source.url}, ${catalog.source.license}, snapshot ${catalog.source.snapshot_date})`, ""];
  for (const tool of catalog.tools) {
    const kinds = Object.entries(tool.artifacts)
      .map(([k, v]) => `${k}:${v.length}`)
      .join(" ");
    lines.push(`${tool.id.padEnd(40)} ${tool.name}  [${kinds}]`);
  }
  emit(flags, lines.join("\n"));
  return 0;
}

export function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv.includes("--version")) {
    process.stdout.write(`rmm-sentinel ${VERSION}\n`);
    return 0;
  }
  const { flags, positional, error } = parseFlags(argv);
  if (error) return fail(error);
  const command = positional[0];
  const extra = positional.slice(1);
  if (extra.length > 0) return fail(`unexpected argument: '${extra[0]}' (commands take no positional arguments)`);
  try {
    switch (command) {
      case "scan":
        return cmdScan(flags);
      case "signals":
        return cmdSignals(flags);
      case "ioc":
        return cmdIoc(flags);
      case "tools":
        return cmdTools(flags);
      case "version":
        process.stdout.write(`rmm-sentinel ${VERSION}\n`);
        return 0;
      case undefined:
        process.stdout.write(USAGE);
        return 2;
      default:
        return fail(`unknown command: '${command}'`);
    }
  } catch (err) {
    if (err instanceof CatalogError) return fail(err.message);
    return fail(`runtime error: ${err.message}`);
  }
}

const invoked = process.argv[1] ?? "";
if (invoked.endsWith("rmm-sentinel.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
