// parse.mjs — pure helpers for hostile input parsing (no I/O, no process).
//
// Every parser here is fail-soft: malformed lines are skipped and counted,
// never thrown. The fuzz tests (test/test-fuzz.mjs) hammer all of them with
// mutated inputs; a thrown exception inside parsing is always a bug.

/** Case-insensitive lookup key. */
export function ikey(value) {
  return String(value ?? "").trim().toLowerCase();
}

/**
 * RFC 4180-style CSV line parser for a single logical row.
 * Returns the field array, or null for an empty or malformed row.
 * Handles quoted fields with embedded commas and escaped quotes.
 * Callers supply one physical line at a time.
 */
export function parseCsvRow(line) {
  const fields = [];
  let field = "";
  let inQuotes = false;
  let closedQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
          closedQuote = true;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === ",") {
      fields.push(field);
      field = "";
      closedQuote = false;
      continue;
    }
    if (closedQuote) return null;
    if (ch === '"') {
      if (field !== "") return null;
      inQuotes = true;
      continue;
    }
    field += ch;
  }
  if (inQuotes) return null;
  fields.push(field);
  // a row of whitespace-only fields is blank - callers must not see it as data
  if (fields.every((f) => f.trim() === "")) return null;
  return fields;
}

/**
 * Parse a full CSV document (with or without header row).
 * Returns { rows, skipped } where rows is an array of field arrays.
 */
export function parseCsv(text, { header = false } = {}) {
  const rows = [];
  let skipped = 0;
  if (text === null || text === undefined) return { rows, skipped };
  const lines = String(text).split(/\r?\n/);
  let first = true;
  for (const line of lines) {
    if (line.trim() === "") continue;
    if (header && first) {
      first = false;
      continue;
    }
    first = false;
    const row = parseCsvRow(line);
    if (row === null) {
      skipped++;
      continue;
    }
    rows.push(row);
  }
  return { rows, skipped };
}

/**
 * PowerShell ConvertTo-Csv output for probes with known column order:
 * the header row (if any) is skipped and each record is mapped through
 * `columns` (ordered names). Records with the wrong arity are skipped.
 * Returns { records, skipped } with plain string records.
 */
export function parsePowerShellCsv(text, columns) {
  const { rows, skipped } = parseCsv(text, { header: true });
  const records = [];
  let badArity = skipped;
  for (const row of rows) {
    if (row.length !== columns.length) {
      badArity++;
      continue;
    }
    const rec = {};
    for (let i = 0; i < columns.length; i++) rec[columns[i]] = row[i] ?? "";
    records.push(rec);
  }
  return { records, skipped: badArity };
}

/** Basename of a Windows path ('C:\\a\\b\\Tool.exe' -> 'Tool.exe'). */
export function windowsBasename(path) {
  const s = String(path ?? "");
  const trimmed = s.replace(/"+$/, "");
  const idx = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  return idx >= 0 ? trimmed.slice(idx + 1) : trimmed;
}

/** Directory part of a Windows path including the trailing separator. */
export function windowsDirname(path) {
  const s = String(path ?? "");
  const trimmed = s.replace(/"+$/, "");
  const idx = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  return idx > 0 ? trimmed.slice(0, idx + 1) : "";
}

/**
 * Wildcard matcher for catalog artifact values. Only '*' is a wildcard
 * (any run of any character), everything else is literal. Case-insensitive.
 */
export function wildcardMatch(pattern, value) {
  const p = ikey(pattern);
  const v = ikey(value);
  if (!p) return false;
  if (!p.includes("*")) return p === v;
  const re = new RegExp(
    `^${p.split("*").map(escapeRe).join("[\\s\\S]*")}$`,
  );
  return re.test(v);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Normalize a catalog install-path pattern to a lowercase literal prefix
 * usable with startsWith semantics. Returns null for patterns that are too
 * loose to anchor a "typical location" decision (leading '*' wildcards,
 * relative patterns, bare executable names).
 *
 * %VAR% tokens in the documented table are kept as-is (they still anchor a
 * prefix in the caller's comparison, which normalizes both sides through
 * expandWinVars first).
 */
export function typicalDirPrefix(pattern) {
  const p = String(pattern ?? "");
  if (!p) return null;
  const lower = p.toLowerCase();
  if (lower.startsWith("*") || lower.startsWith("\\")) return null;
  // bare filename patterns ("tool.exe", "tool*.exe") cannot anchor a dir
  if (/^[a-z0-9][a-z0-9._*-]*\.exe$/.test(lower)) return null;
  let prefix = lower;
  const star = prefix.indexOf("*");
  if (star >= 0) prefix = prefix.slice(0, star);
  // drop a trailing partial segment: a prefix must end at a separator
  if (!prefix.endsWith("\\")) {
    const idx = prefix.lastIndexOf("\\");
    if (idx < 0) return null;
    prefix = prefix.slice(0, idx + 1);
  }
  if (prefix.length < 4) return null;
  return prefix;
}

/**
 * Expand a small, documented set of Windows environment variables in a path
 * string so comparisons between '%programdata%\X' and 'C:\ProgramData\X'
 * agree. Unknown variables are left untouched. Both arguments go through
 * this before comparison.
 */
export function expandWinVars(path) {
  const table = {
    "%programdata%": "c:\\programdata",
    "%programfiles%": "c:\\program files",
    "%programfiles(x86)%": "c:\\program files (x86)",
    "%appdata%": "c:\\users\\<user>\\appdata\\roaming",
    "%localappdata%": "c:\\users\\<user>\\appdata\\local",
    "%windir%": "c:\\windows",
    "%systemroot%": "c:\\windows",
    "%public%": "c:\\users\\public",
  };
  let out = String(path ?? "").toLowerCase();
  for (const [k, v] of Object.entries(table)) {
    if (out.startsWith(k)) out = v + out.slice(k.length);
  }
  return out;
}

/**
 * Does `path` sit inside the tool's typical install locations?
 * `entry` is a catalog tool; only anchored patterns count (see
 * typicalDirPrefix). Generic 'Program Files' roots are deliberately NOT
 * treated as typical on their own - a vendor binary in a custom Program
 * Files subdirectory is exactly what RS-SIG-001 wants to flag.
 */
export function isTypicalInstallPath(path, entry) {
  const dirs = entry?.artifacts?.typical_dirs ?? [];
  if (!dirs.length) return false;
  const expanded = expandWinVars(path);
  for (const pattern of dirs) {
    const prefix = typicalDirPrefix(pattern);
    if (!prefix) continue;
    if (expanded.startsWith(expandWinVars(prefix))) return true;
  }
  return false;
}

const USER_WRITABLE_SEGMENTS = [
  "\\temp\\",
  "\\tmp\\",
  "\\downloads\\",
  "\\public\\",
  "\\desktop\\",
  "\\recycle\\",
];

/**
 * Is the path inside a user-writable location (the classic "agent dropped
 * by the operator" locations)? Fixed list, deliberately narrow, documented
 * in README: Temp, Downloads, Public, Desktop, Recycle. %APPDATA%\Roaming is
 * excluded on purpose - several legitimate remote-support tools run their
 * user-mode parts from there.
 */
export function isUserWritablePath(path) {
  const expanded = expandWinVars(path);
  return USER_WRITABLE_SEGMENTS.some((seg) => expanded.includes(seg));
}

/** Cap long evidence strings for report hygiene. */
export function clip(value, max = 300) {
  const s = String(value ?? "");
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
