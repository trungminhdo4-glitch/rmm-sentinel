// test-report.mjs — renderer + opt-in write tests. The no-write default is
// proven: without --out the writer is never called.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  renderInventoryText,
  renderIocText,
  renderSignalsText,
  writeIfOut,
} from "../src/report.mjs";

const inventoryDoc = {
  version: "0.1.0",
  catalog_version: "0.1.0",
  catalog_tools: 2,
  probes_run: ["process-list", "service-list", "uninstall-list", "task-list"],
  probes_failed: [],
  skipped_rows: 0,
  inventory: [
    {
      tool_id: "synthrmm",
      tool_name: "SynthRMM",
      evidence: [{ kind: "process", detail: "process SynthRMM.exe at C:\\Program Files\\SynthRMM\\SynthRMM.exe", path: "C:\\Program Files\\SynthRMM\\SynthRMM.exe" }],
    },
  ],
};

const signalsDoc = {
  version: "0.1.0",
  fail_on: "high",
  signals: [
    {
      rule_id: "RS-SIG-001",
      title: "t",
      severity: "medium",
      tool_id: "synthrmm",
      detail: "service binary at C:\\Custom\\x.exe",
      why: "because",
      falsepositives: ["custom installs"],
    },
  ],
  failing_count: 0,
};

test("renderInventoryText reports a clean scan honestly", () => {
  const text = renderInventoryText({ ...inventoryDoc, inventory: [] });
  assert.match(text, /No catalogued RMM tools detected/);
  assert.match(text, /not a guarantee/);
});

test("renderInventoryText lists tools and evidence with probe status", () => {
  const text = renderInventoryText(inventoryDoc);
  assert.match(text, /SynthRMM \(synthrmm\)/);
  assert.match(text, /\[process\]/);
  assert.match(text, /context, not evidence of misuse/);
});

test("renderInventoryText marks failed probes as partial inventory", () => {
  const text = renderInventoryText({ ...inventoryDoc, probes_failed: ["task-list"] });
  assert.match(text, /partial inventory!/);
});

test("renderSignalsText lists signals with severity and falsepositives", () => {
  const text = renderSignalsText(signalsDoc);
  assert.match(text, /MEDIUM\s+RS-SIG-001 \(synthrmm\)/);
  assert.match(text, /falsepositive: custom installs/);
});

test("renderSignalsText warns when signals exist below fail-on", () => {
  const text = renderSignalsText(signalsDoc);
  assert.match(text, /WARNING: signals exist but none at or above --fail-on high/);
});

test("renderSignalsText clean run states the limit", () => {
  const text = renderSignalsText({ ...signalsDoc, signals: [] });
  assert.match(text, /No abuse signals above 'info'/);
  assert.match(text, /not a guarantee/);
});

test("renderIocText states the offline catalog origin", () => {
  const text = renderIocText({ version: "0.1.0", count: 42, catalog_version: "0.1.0" });
  assert.match(text, /iocs: 42/);
  assert.match(text, /offline/);
});

test("writeIfOut writes nothing without --out", () => {
  let called = 0;
  const writer = () => called++;
  const res = writeIfOut("data", null, writer);
  assert.equal(res, null);
  assert.equal(called, 0);
  const res2 = writeIfOut("data", "   ", writer);
  assert.equal(res2, null);
  assert.equal(called, 0);
});

test("writeIfOut writes via the injectable writer when a path is given", () => {
  const calls = [];
  const writer = (path, content, enc) => calls.push([path, content, enc]);
  const mkDir = () => calls.push(["mkdir"]);
  const res = writeIfOut("data", "C:\\tmp\\out.json", writer, mkDir);
  assert.equal(res, "C:\\tmp\\out.json");
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], ["C:\\tmp\\out.json", "data", "utf8"]);
});
