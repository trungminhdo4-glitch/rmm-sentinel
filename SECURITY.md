# Security Policy

## Reporting a vulnerability

Report vulnerabilities **privately** through
[GitHub Security Advisories](https://github.com/trungminhdo4-glitch/rmm-sentinel/security/advisories/new)
for this repository. Do **not** open a public issue for security-relevant
reports.

Please include:

* the RMM-Sentinel version (`node rmm-sentinel.mjs version`) and how you
  obtained it,
* a minimal reproduction (command line, host context in rough terms, and the
  observed output — never paste real hostnames, user names, or credentials),
* the impact you believe it has (for example: a signal is missed, a command
  outside the probe allowlist runs, a file is written without `--out`).

**What counts as a vulnerability here**

* any path that makes RMM-Sentinel execute scanned programs or arbitrary
  commands beyond the fixed read-only probe allowlist in `src/runner.mjs`,
* any write to disk other than the documented opt-in `--out` destination,
* any network request at all (the tool is offline by construction),
* secret leakage through reports, logs, or SBOM output,
* a signal-rule bypass that makes a documented misuse shape report as clean
  without any warning,
* denial of service through unbounded resource use on hostile input
  (malformed probe output or a hostile catalog file).

**What does not count**

* a host that simply contains no catalogued RMM artifacts or no signals (a
  clean run is a heuristic, not a guarantee — see the README disclaimer),
* heuristic false positives that are documented behaviour of a signal rule,
* findings about third-party RMM products themselves (report those to the
  vendor).

## Response commitments

* **Acknowledgement within 48 hours** of the report (abuse and security
  reports alike).
* **Triage and status update within 7 days**, including whether the report is
  accepted, needs more information, or is out of scope.
* Fixes for accepted critical and high severity issues are prioritised ahead
  of new features; the timeline is agreed with the reporter.
* Credit is given in the advisory and CHANGELOG unless the reporter prefers
  to remain anonymous.

## Abuse process (48 hours)

Reports about *use* of this project (for example someone scanning endpoints
they do not own, or redistributing it as an offensive tool) follow the same
48-hour acknowledgement window and are handled under
[ETHICS.md](ETHICS.md). Decisions are recorded and can be challenged through
the appeal path in [APPEAL.md](APPEAL.md); the process itself is described in
[TRANSPARENCY.md](TRANSPARENCY.md).

## Supported versions

Only the latest MAJOR line receives security fixes. See the
[Support-Ende und Versionierung](README.md#support-ende-und-versionierung)
section of the README for the exact policy.

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ (initial line) |
| older  | ❌ end of life |
