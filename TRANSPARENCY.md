# Transparency

RMM-Sentinel is a defensive security tool. Trust in it depends on being able
to verify what it does, what it collects, and how decisions about it are
made. This document states all three plainly.

## 1. What the software collects: nothing

* **No telemetry, no analytics, no crash reporting, no update checks.** The
  tool does not phone home; it is offline by construction and the build
  fails if production code opens any network handle.
* **No accounts, no cookies, no local state.** RMM-Sentinel reads no
  configuration files and writes none. The only filesystem write is the
  explicit `--out` destination you name on the command line (pinned to
  `src/report.mjs` by the CI scope gate).
* **What it reads:** the shipped catalog file (and any `--catalog` file you
  point it at), plus the outputs of four read-only system probes
  (process list, service list, uninstall entries, scheduled-task list) on
  the local Windows host it runs on. Probes are fixed argv arrays in
  `src/runner.mjs`; there is no plumbing to run arbitrary commands.
* **No code is executed.** Probe output and catalog data are parsed and
  matched against static rules; nothing is imported, evaluated, or spawned
  beyond the probe allowlist itself.

## 2. What appears in reports

Reports contain: cataloged tool identifiers and display names, artifact
kinds (process/service/uninstall/task), evidence strings with paths, signal
rule IDs with severity, and the probe status (which probes ran, which
failed — partial inventories are labelled as partial). They contain **no
personal data and no credentials** by design; the scanner never collects
user names, host names beyond what the OS query returns, or file contents.

## 3. How the project itself is run

| Topic | Practice |
| --- | --- |
| Source of truth | This repository; every policy change lands as a reviewed pull request. |
| Decision log | Issues, pull requests, and release notes are public. Substantive decisions get a written rationale in the issue or PR. |
| CI | All workflows are public and blocking: CI (syntax/tests/coverage/gates/DCO), CodeQL, dependency review, gitleaks, SBOM, Scorecard. |
| Supply chain | Dependabot for npm and GitHub Actions; pinned action major versions; a CycloneDX 1.6 SBOM (application + SHA-256'd file components) is generated on every push; the gitleaks binary in CI is a pinned release download with a locally verified sha256. |
| Catalog provenance | The catalog is derived data from LOLRMM (Apache-2.0) with snapshot date and derivation rules recorded in the file; see [NOTICE](NOTICE). |
| Abuse reports | 48-hour acknowledgement window (see [SECURITY.md](SECURITY.md)). |
| Moderation | Conduct decisions follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and are communicated with reasons. |
| Data held about people | Only what a report or appeal requires to be processed (contact handle, message text). Kept no longer than the process needs; never sold, never shared beyond the maintainers handling the case. |

## 4. The 48-hour abuse process

1. **Day 0** — report received through the channel in
   [SECURITY.md](SECURITY.md) (GitHub Security Advisories). Automatic
   acknowledgement.
2. **Within 48 hours** — a human confirms receipt and states whether the
   report is in scope, needs more detail, or is rejected with reasons.
3. **Within 7 days** — triage outcome: accepted (fix or policy action
   scheduled, timeline agreed), needs information, or out of scope.
4. **Action** — accepted reports are handled under
   [ETHICS.md](ETHICS.md); affected parties are told what will change and
   when.
5. **Appeal** — any party affected by a decision may appeal under
   [APPEAL.md](APPEAL.md). Appeals do not restart the 48-hour clock but are
   acknowledged within 48 hours as well.
6. **Record** — outcomes are recorded in aggregate (category, outcome, date)
   in the project's public record; personal data stays inside the process.

## 5. Changes to this document

Material changes to policies (ethics, security, transparency, appeal)
require a pull request with rationale, are listed in
[CHANGELOG.md](CHANGELOG.md), and are announced in the release notes of the
first release that contains them.
