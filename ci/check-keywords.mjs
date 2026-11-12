#!/usr/bin/env node
// check-keywords.mjs — RMM-Sentinel scope and safety gate (node builtins only).
//
// Blocks commit content that would turn this defensive scanner into an
// offensive tool, plus secret-shaped data. Runs offline against the working
// tree or a directory root.
//
// Exit codes: 0 = clean, 1 = findings, 2 = usage/internal error.
//
// Three tiers:
//   1. Scope rules: read-only-by-construction invariants for *production*
//      code (src/** and rmm-sentinel.mjs):
//        - child_process may be imported ONLY in src/runner.mjs
//        - src/runner.mjs must contain no mutating command verbs
//        - no network clients anywhere in production code
//        - filesystem writes only in src/report.mjs (opt-in --out)
//        - no eval-style dynamic code loading in production code
//      Tests (test/**) and CI scripts (ci/**) are exempt from the scope
//      rules - they run the tool and its gates, and are reviewed as such.
//   2. Content rules: unmistakable offense markers (reverse shells,
//      webshells, exploit PoC payloads, credential stealers, phishing kit
//      templates) anywhere in the tree, except in documented rule contexts
//      (the catalog data and test fixtures, which are inert data).
//   3. Secret rules: secret-shaped material is blocked EVERYWHERE, including
//      fixtures and data.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import process from "node:process";

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".vscode",
  ".idea",
  "coverage",
  "dist",
  "bin",
]);

// Files whose content is *by design* tool- and rule-shaped: the catalog data
// and test fixtures. Content rules do not apply there - they are inert data,
// reviewed like any other change, and never executed. Secret scanning still
// applies everywhere.
const RULE_CONTEXT = /(^|[\\/])(data[\\/]|testdata[\\/]|fixtures?[\\/])/;

// The gate defines these patterns as literals, so scanning it would always
// flag itself. Kept to exactly these paths; every other file in the
// repository is scanned (asserted by ci/test-gates.mjs).
const SELF_EXCLUDE = new Set(["ci/check-keywords.mjs", "ci/test-gates.mjs"]);

const PRODUCTION_RE = /^(src[\\/][^\\/]+\.mjs|rmm-sentinel\.mjs)$/;

const CHILD_PROCESS_RE =
  /node:child_process|require\s*\(\s*["']child_process["']\s*\)|from\s+["']child_process["']/;

// Mutating command verbs that must never appear in the runner file (the only
// place that builds argv arrays). Read-only query strings are safe.
const MUTATING_VERB_RE =
  /\b(delete|del|remove|remov-item|remove-item|stop-service|stop-process|stop-computer|kill|taskkill|net\s+(stop|start|user|localgroup)|reg\s+(add|delete|import|load|restore|save|unload)|sc\s+(start|stop|config|create|delete)|schtasks\s+\/(create|delete|change|end|run)|new-service|set-service|set-itemproperty|set-registry|start-process|start-service|invoke-expression|\biex\b|shutdown|format|rmdir|md\s+\w|copy-item|move-item|rename-item|clear-content|set-content|add-content|out-file)\b/i;

const NETWORK_RE =
  /node:(http|https|net|dgram|tls|dns|undici)|\bfetch\s*\(|XMLHttpRequest|WebSocket\b/;

const WRITE_API_RE =
  /writeFile|appendFile|createWriteStream|\.rm(Sync)?\(|rmdirSync|unlinkSync|chmodSync|copyFileSync|renameSync|mkdirSync|openSync|truncateSync|mkdtempSync/;

// Any dynamic import() is forbidden in production code - static imports
// only. This blocks the dangerous variable-form (import(userPath)) and the
// literal-form (import("./x")) alike; production code needs neither.
const EVAL_RE =
  /\beval\s*\(|new\s+Function\s*\(|node:vm|\bimport\s*\(/;

// Unmistakable offense markers: never acceptable in this repository,
// not even in docs. Kept deliberately narrow (code-shaped, not words),
// because the README/ETHICS text legitimately *discusses* attacks.
const CONTENT_RULES = [
  {
    id: "OFFENSE-REVSHELL-001",
    why: "reverse shell one-liner",
    pattern: /bash -i >& ?\/dev\/tcp\/|ncat .*-e \/bin\/(ba)?sh|\/bin\/bash -i >&/,
  },
  {
    id: "OFFENSE-WEBSHELL-001",
    why: "PHP webshell snippet",
    pattern: /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|system\s*\(\s*\$_(POST|GET|REQUEST)|passthru\s*\(\s*\$_(POST|GET)/,
  },
  {
    id: "OFFENSE-POC-001",
    why: "exploit PoC payload marker (Log4Shell JNDI injection string)",
    pattern: /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//,
  },
  {
    id: "OFFENSE-STAGER-001",
    why: "credential-dumping / loader tooling invocation",
    pattern: /mimikatz|sekurlsa::logonpasswords|procdump(64)?\.exe.{0,40}lsass|msfvenom\s+-p\s/,
  },
  {
    id: "OFFENSE-C2-001",
    why: "command-and-control beacon configuration key",
    pattern: /beacon_interval\s*[:=]|"c2_server"\s*:|cobaltstrike[_-]beacon/,
  },
  {
    id: "OFFENSE-PHISH-001",
    why: "phishing kit template marker (credential harvest form action)",
    pattern: /<form[^>]+action=["'][^"']*(login|verify|signin|account)[-_.]?(confirm|update|secure)?[^"']*["'][^>]*>\s*<input[^>]+name=["'](pass|pwd|credential)/i,
  },
  {
    id: "OFFENSE-STEALER-001",
    why: "info-stealer / webinject marker",
    pattern: /webinject|redline[_-]stealer|raccoon[_-]stealer|steal(er)?[_-]log/,
  },
];

const SCOPE_RULES = [
  {
    id: "SCOPE-EXEC-001",
    why: "only src/runner.mjs may import child_process (read-only probe allowlist)",
    fileRe: PRODUCTION_RE,
    skipRe: /^src[\\/]runner\.mjs$/,
    pattern: CHILD_PROCESS_RE,
  },
  {
    id: "SCOPE-EXEC-002",
    why: "src/runner.mjs must not contain mutating command verbs",
    fileRe: /^src[\\/]runner\.mjs$/,
    skipRe: null,
    pattern: MUTATING_VERB_RE,
  },
  {
    id: "SCOPE-NET-001",
    why: "production code must not open network connections (offline by construction)",
    fileRe: PRODUCTION_RE,
    skipRe: null,
    pattern: NETWORK_RE,
  },
  {
    id: "SCOPE-WRITE-001",
    why: "filesystem writes must live in src/report.mjs and stay behind the --out flag",
    fileRe: PRODUCTION_RE,
    skipRe: /^src[\\/]report\.mjs$/,
    pattern: WRITE_API_RE,
  },
  {
    id: "SCOPE-EVAL-001",
    why: "production code must not use eval-style dynamic code loading",
    fileRe: PRODUCTION_RE,
    skipRe: null,
    pattern: EVAL_RE,
  },
  {
    id: "SCOPE-SECRETS-001",
    why: "no secret-shaped material may enter the repository",
    fileRe: /\.(mjs|js|md|yml|yaml|json|txt|py|csv)$/,
    skipRe: /(^|[\\/])LICENSE(-CC-BY-4\.0)?\.txt$/,
    pattern:
      /-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|hf_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}/,
  },
];

const TEXT_EXT = new Set([
  ".mjs", ".js", ".ts", ".py", ".md", ".txt", ".yml", ".yaml",
  ".json", ".toml", ".csv", ".html", ".css", ".sh", ".ps1",
  ".gitignore", ".gitattributes", "",
]);

function walk(root, out = []) {
  for (const name of readdirSync(root)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(root, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

function isTextFile(path) {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  const ext = dot >= 0 ? lower.slice(dot) : "";
  return TEXT_EXT.has(ext) || TEXT_EXT.has(lower.slice(lower.lastIndexOf(sep) + 1));
}

export function scanFile(relPath, content) {
  const findings = [];
  const inRuleContext = RULE_CONTEXT.test(relPath);
  for (const rule of SCOPE_RULES) {
    if (!rule.fileRe.test(relPath)) continue;
    if (rule.skipRe && rule.skipRe.test(relPath)) continue;
    if (inRuleContext && rule.id !== "SCOPE-SECRETS-001") continue;
    const m = content.match(rule.pattern);
    if (m) {
      findings.push({ rule: rule.id, path: relPath, why: rule.why, sample: m[0].slice(0, 60) });
    }
  }
  for (const rule of CONTENT_RULES) {
    if (inRuleContext) continue;
    const m = content.match(rule.pattern);
    if (m) {
      findings.push({ rule: rule.id, path: relPath, why: rule.why, sample: m[0].slice(0, 60) });
    }
  }
  return findings;
}

export function scanTree(root) {
  const findings = [];
  for (const file of walk(root)) {
    const rel = relative(root, file);
    if (rel.split(sep).includes(".git")) continue;
    const relPosix = rel.split(sep).join("/");
    if (SELF_EXCLUDE.has(relPosix)) continue;
    if (!isTextFile(file)) continue;
    let content;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    // Strip NUL-heavy binaries that slipped through the extension filter.
    if (content.includes("\u0000")) continue;
    findings.push(...scanFile(relPosix, content));
  }
  return findings;
}

function main(argv) {
  const root = argv.includes("--root")
    ? argv[argv.indexOf("--root") + 1]
    : process.cwd();
  if (!root || argv.includes("--help")) {
    process.stderr.write(
      "usage: node ci/check-keywords.mjs [--root <dir>]\n" +
        "exit 0 = clean, 1 = findings, 2 = usage error\n",
    );
    return argv.includes("--help") ? 0 : 2;
  }
  let findings;
  try {
    findings = scanTree(root);
  } catch (err) {
    process.stderr.write(`check-keywords: ${err.message}\n`);
    return 2;
  }
  if (findings.length > 0) {
    for (const f of findings) {
      process.stdout.write(`${f.rule} ${f.path}: ${f.why} [${f.sample}]\n`);
    }
    process.stdout.write(`check-keywords: ${findings.length} finding(s)\n`);
    return 1;
  }
  process.stdout.write("check-keywords: clean\n");
  return 0;
}

if ((process.argv[1] ?? "").endsWith("check-keywords.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
