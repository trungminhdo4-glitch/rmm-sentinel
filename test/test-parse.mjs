// test-parse.mjs — pure parser and path-helper tests (node:test, offline).
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  clip,
  expandWinVars,
  ikey,
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
import { loadCatalog } from "../src/catalog.mjs";

test("parseCsvRow splits plain rows", () => {
  assert.deepEqual(parseCsvRow("a,b,c"), ["a", "b", "c"]);
});

test("parseCsvRow handles quoted commas and doubled quotes", () => {
  assert.deepEqual(parseCsvRow('"a,b","c""d"'), ["a,b", 'c"d']);
});

test("parseCsvRow returns null for empty rows", () => {
  assert.equal(parseCsvRow(""), null);
  assert.equal(parseCsvRow("   "), null);
});

test("parseCsv skips empty lines and counts nothing", () => {
  const { rows, skipped } = parseCsv("a,b\n\nc,d\n", { header: false });
  assert.equal(rows.length, 2);
  assert.equal(skipped, 0);
});

test("parseCsv drops the header when asked", () => {
  const { rows } = parseCsv('Name,Path\n"tool.exe","C:\\x\\tool.exe"\n', { header: true });
  assert.deepEqual(rows, [["tool.exe", "C:\\x\\tool.exe"]]);
});

test("parsePowerShellCsv maps columns and skips wrong arity", () => {
  const text = '"Name","Path"\n"tool.exe","C:\\x\\tool.exe"\n"bad"\n"n2",\n';
  const { records, skipped } = parsePowerShellCsv(text, ["name", "path"]);
  assert.equal(records.length, 2);
  assert.equal(records[0].name, "tool.exe");
  assert.equal(records[1].path, "");
  assert.equal(skipped, 1);
});

test("parsePowerShellCsv tolerates empty output", () => {
  const { records } = parsePowerShellCsv("", ["name"]);
  assert.deepEqual(records, []);
});

test("windowsBasename and windowsDirname", () => {
  assert.equal(windowsBasename("C:\\a\\b\\Tool.exe"), "Tool.exe");
  assert.equal(windowsBasename("Tool.exe"), "Tool.exe");
  assert.equal(windowsBasename("C:\\a\\b\\tool.exe\""), "tool.exe");
  assert.equal(windowsDirname("C:\\a\\b\\Tool.exe"), "C:\\a\\b\\");
  assert.equal(windowsDirname("Tool.exe"), "");
});

test("wildcardMatch is exact without '*'", () => {
  assert.ok(wildcardMatch("Tool.exe", "tool.exe"));
  assert.ok(!wildcardMatch("Tool.exe", "toolx.exe"));
});

test("wildcardMatch supports '*' runs", () => {
  assert.ok(wildcardMatch("AnyDesk-*", "anydesk-4321"));
  assert.ok(wildcardMatch("screenconnect*.exe", "ScreenConnect.ClientService.exe"));
  assert.ok(!wildcardMatch("anydesk-*", "teamviewer"));
});

test("typicalDirPrefix rejects unanchored patterns", () => {
  assert.equal(typicalDirPrefix("*\\Anywhere\\"), null);
  assert.equal(typicalDirPrefix("tool.exe"), null);
  assert.equal(typicalDirPrefix(""), null);
});

test("typicalDirPrefix anchors drive and %var% patterns", () => {
  assert.equal(typicalDirPrefix("C:\\Program Files\\Tool\\*"), "c:\\program files\\tool\\");
  assert.equal(typicalDirPrefix("%programdata%\\Tool\\"), "%programdata%\\tool\\");
  assert.equal(typicalDirPrefix("C:\\Temp\\tool*.exe"), "c:\\temp\\");
});

test("expandWinVars maps the documented table", () => {
  assert.equal(expandWinVars("%ProgramData%\\X\\"), "c:\\programdata\\x\\");
  assert.equal(expandWinVars("%WINDIR%\\a"), "c:\\windows\\a");
  assert.equal(expandWinVars("C:\\x"), "c:\\x");
  assert.equal(expandWinVars("%unknown%\\x"), "%unknown%\\x");
});

test("isTypicalInstallPath matches anchored tool patterns", () => {
  const catalog = loadCatalog("test/fixtures/catalog-mini.json");
  const tool = catalog.tools.find((t) => t.id === "synthrmm");
  assert.ok(isTypicalInstallPath("C:\\Program Files\\SynthRMM\\synthrmm.exe", tool));
  assert.ok(!isTypicalInstallPath("C:\\Custom\\SynthRMM\\synthrmm.exe", tool));
});

test("isUserWritablePath covers the documented narrow list", () => {
  assert.ok(isUserWritablePath("C:\\Users\\a\\AppData\\Local\\Temp\\x\\agent.exe"));
  assert.ok(isUserWritablePath("C:\\Users\\Public\\agent.exe"));
  assert.ok(isUserWritablePath("C:\\Users\\a\\Downloads\\agent.exe"));
  assert.ok(!isUserWritablePath("C:\\Program Files\\agent.exe"));
  assert.ok(!isUserWritablePath("C:\\Users\\a\\AppData\\Roaming\\AnyDesk\\anydesk.exe"));
});

test("ikey trims and lowercases", () => {
  assert.equal(ikey("  Tool.EXE "), "tool.exe");
});

test("clip truncates long evidence", () => {
  assert.equal(clip("x".repeat(400)), `${"x".repeat(299)}…`);
  assert.equal(clip("short"), "short");
});
