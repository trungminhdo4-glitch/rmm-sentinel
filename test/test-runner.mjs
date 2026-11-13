// test-runner.mjs — unit tests for the only exec-sanctioned module.
// runProbe takes an injectable exec function and platform, so every branch
// is testable offline: no real process is ever spawned here.
import { test } from "node:test";
import assert from "node:assert/strict";

import { PROBES, runProbe, isWindows } from "../src/runner.mjs";

function fakeExec(handler) {
  const calls = [];
  const exec = (file, args, opts) => {
    calls.push({ file, args, opts });
    return handler(file, args, opts);
  };
  exec.calls = calls;
  return exec;
}

test("the probe allowlist is exactly the four read-only probes", () => {
  assert.deepEqual(Object.keys(PROBES).sort(), [
    "process-list",
    "service-list",
    "task-list",
    "uninstall-list",
  ]);
  for (const probe of Object.values(PROBES)) {
    assert.ok(Array.isArray(probe.argv) && probe.argv.length >= 2);
    assert.equal(typeof probe.encoding, "string");
    assert.ok(Number.isInteger(probe.timeoutMs) && probe.timeoutMs >= 1000);
    // first argv element must be a fixed binary name, never user input
    assert.match(probe.argv[0], /^[\w.]+\.exe$/);
    // the PowerShell probes must run non-interactive without profile
    if (probe.argv[0] === "powershell.exe") {
      assert.ok(probe.argv.includes("-NoProfile"));
      assert.ok(probe.argv.includes("-NonInteractive"));
    }
  }
  // the schtasks probe must be a read-only query
  const tasks = PROBES["task-list"];
  assert.deepEqual(tasks.argv.slice(1), ["/query", "/fo", "csv", "/nh"]);
});

test("runProbe rejects unknown probe ids without spawning anything", () => {
  const exec = fakeExec(() => {
    throw new Error("must not be called");
  });
  for (const id of ["no-such-probe", "constructor", "__proto__", "toString"]) {
    const res = runProbe(id, exec, "win32");
    assert.equal(res.ok, false);
    assert.equal(res.error, `unknown probe: ${id}`);
  }
  assert.equal(exec.calls.length, 0);
});

test("runProbe refuses probes on non-Windows platforms without spawning", () => {
  const exec = fakeExec(() => {
    throw new Error("must not be called");
  });
  const res = runProbe("process-list", exec, "linux");
  assert.equal(res.ok, false);
  assert.match(res.error, /requires Windows/);
  assert.equal(exec.calls.length, 0);
});

test("runProbe forwards the fixed argv to exec and returns success", () => {
  const exec = fakeExec((file, args, opts) => {
    assert.equal(opts.encoding, "utf8");
    assert.equal(opts.windowsHide, true);
    return { status: 0, stdout: "a,b\n", stderr: "", error: null };
  });
  const res = runProbe("process-list", exec, "win32");
  assert.equal(res.ok, true);
  assert.equal(res.stdout, "a,b\n");
  assert.equal(res.status, 0);
  assert.equal(exec.calls[0].file, "powershell.exe");
  assert.equal(exec.calls[0].args.at(-1).includes("Get-CimInstance"), true);
});

test("runProbe captures exec throwing (ENOENT and friends)", () => {
  const exec = fakeExec(() => {
    throw new Error("spawn ENOENT");
  });
  const res = runProbe("service-list", exec, "win32");
  assert.equal(res.ok, false);
  assert.match(res.error, /spawn ENOENT/);
});

test("runProbe captures non-zero exit codes", () => {
  const exec = fakeExec(() => ({ status: 1, stdout: "", stderr: "boom", error: null }));
  const res = runProbe("task-list", exec, "win32");
  assert.equal(res.ok, false);
  assert.equal(res.status, 1);
  assert.match(res.error, /exited 1/);
});

test("runProbe captures exec error objects (timeout and friends)", () => {
  const exec = fakeExec(() => ({ status: null, stdout: "", stderr: "", error: new Error("timed out") }));
  const res = runProbe("uninstall-list", exec, "win32");
  assert.equal(res.ok, false);
  assert.match(res.error, /timed out/);
});

test("isWindows reflects the platform", () => {
  assert.equal(isWindows("win32"), true);
  assert.equal(isWindows("linux"), false);
  assert.equal(isWindows("darwin"), false);
});
