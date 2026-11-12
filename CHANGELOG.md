# Changelog

All notable changes to RMM-Sentinel are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release tags are `vMAJOR.MINOR.PATCH`. See [RELEASING.md](RELEASING.md) for the
signing and support policy.

## [Unreleased]

### Added

* **Read-only scanner core** — Windows inventory of catalogued RMM tools via
  a fixed probe allowlist (process list, service list, uninstall entries,
  scheduled tasks); probe failures are recorded, partial inventories are
  labelled as partial.
* **Catalog of 237 RMM tool families** (`data/rmm-catalog.json`,
  schema `rmm-sentinel-catalog/1`) — derived deterministically from the
  LOLRMM API snapshot 2026-11-12 (Apache-2.0, attributed in NOTICE) with
  Windows-only scope, per-kind caps and case-insensitive dedup.
* **Abuse-signal heuristics RS-SIG-001..005** — service binary outside
  documented install locations (medium), RMM process in a user-writable
  location (high), non-catalogued service binary (medium), uninstall entry
  outside documented locations (low), many RMM families at once (info,
  threshold configurable); severity-ordered output with a `--fail-on` gate
  (default `high`), each rule documented with `why` and `falsepositives`.
* **IOC / detection-rule generator** — JSON (schema `1.0`), CSV and Sigma
  output (process-creation rules and EventID 7045 service-installation
  rules), IDs as deterministic uuid5, byte-stable for the same catalog,
  every emitted value a direct transcription of the catalog.
* **Exit codes** — `0` clean / below fail-on, `1` signals at or above
  `--fail-on`, `2` usage or runtime error; `WARNING:` line whenever a run
  fails the gate.
* **Defensive hardening** — hostile-input fuzz sweep over every parser
  (seeded, deterministic, offline), fail-closed catalog validation
  (`CatalogError` → exit 2), evidence path fields instead of re-parsed
  strings, probe errors surfaced in the report.
* **CI (blocking)** — syntax check over every shipped `.mjs`, full test
  suite with the fuzz sweep, line-coverage gate (≥ 80 %, every production
  file accounted, fail-closed), keyword and scope gate
  (`child_process` only in `src/runner.mjs`, writes only in `src/report.mjs`,
  no production networking), DCO check, CodeQL (javascript-typescript),
  dependency review, gitleaks (pinned v8.30.1 binary, sha256 verified),
  CycloneDX 1.6 SBOM (application + SHA-256'd file components,
  deterministic serial), OpenSSF Scorecard.
* **Governance** — README with purpose, data provenance, dual-use notice,
  unauthorized-use prohibition and AUP, disclaimer (§ 521 / § 276 Abs. 3
  BGB), support-end and versioning policy; SECURITY, ETHICS, CONTRIBUTING
  (DCO), CODE_OF_CONDUCT, NOTICE (LOLRMM attribution + trademark note),
  TRANSPARENCY, APPEAL, RELEASING; issue and pull request templates;
  Dependabot configuration.

[Unreleased]: https://github.com/trungminhdo4-glitch/rmm-sentinel/compare/HEAD
