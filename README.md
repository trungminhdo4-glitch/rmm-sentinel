# RMM-Sentinel

RMM-Sentinel is a **static, read-only Windows scanner and generator for
Remote Monitoring & Management (RMM) software**. It enumerates the RMM
artifacts on a local Windows host (processes, services, uninstall entries,
scheduled tasks) using a fixed, read-only probe allowlist, matches them
against a curated catalog of 237 RMM tool families, raises abuse-signal
heuristics for human review, and generates IOC / Sigma rule packs from the
shipped catalog — fully offline, without executing or changing anything on
the scanned host.

**RMM-Sentinel never executes scanned programs, never modifies the system,
and never talks to the network.** There is no telemetry, no update check, and
no listener: the only process spawn is the fixed read-only probe allowlist
(`src/runner.mjs`), and the only filesystem write is the explicit `--out`
destination.

```console
$ node rmm-sentinel.mjs scan
RMM-Sentinel 0.1.0 - read-only RMM inventory (no system changes)
catalog: 0.1.0 (237 tools), probes ok: process-list, service-list, uninstall-list, task-list

Detected 2 catalogued RMM tool(s):
- TeamViewer (teamviewer)
  [service] service TeamViewer via C:\Program Files\TeamViewer\TeamViewer_Service.exe (Running)
  ...
```

## Zweck

The tool answers one question **before** an incident — and one during it:

> *Which remote-access / remote-management software is present on this host,
> does anything about it look off, and what would we hunt for in the SIEM?*

Built for defensive use cases:

* **Inventory and posture review** — what remote-access surface does a
  Windows host expose (IT ops, incident responders, MSPs reviewing their own
  stack).
* **Abuse-signal triage** — heuristic signals for the classic "legitimate RMM
  dropped in a strange place" shapes: an agent running from Temp, a renamed
  service binary, an uninstall entry outside the documented install
  locations, sprawl of many families at once.
* **Detection engineering** — Sigma (process creation + EventID 7045) and
  IOC packs (JSON/CSV) derived deterministically from the catalog, ready for
  a SIEM/EDR tune-up.
* **Security research** into RMM abuse, conducted lawfully and without
  harming third parties.

Scope of v0.1:

| Surface | What is checked |
| --- | --- |
| Processes | names matched against 237 catalogued RMM families (wildcard-aware, case-insensitive) |
| Services | service names + service binary path names |
| Uninstall entries | display names vs. catalog uninstall-key names |
| Scheduled tasks | task names against catalogued task names (`schtasks /query`) |
| Abuse signals | RS-SIG-001..005 heuristics (below), severity-ordered, `--fail-on` gate |
| IOC generator | process names, service names, task names, uninstall keys, install paths → JSON/CSV/Sigma |

Signal rules (heuristic, for human review — never verdicts):

| ID | Severity | What it flags |
| --- | --- | --- |
| RS-SIG-001 | medium | service binary outside the tool's documented install locations |
| RS-SIG-002 | high | RMM process running from Temp/Downloads/Public/Desktop/Recycle |
| RS-SIG-003 | medium | service whose binary name is not catalogued for the tool |
| RS-SIG-004 | low | uninstall entry pointing outside documented install locations |
| RS-SIG-005 | info | many distinct RMM families present (threshold configurable, default 4) |

What RMM-Sentinel deliberately does **not** do: execute scanned binaries,
modify services/tasks/files, reach out to the network, or write to disk
unless you explicitly pass `--out`.

## Data provenance (LOLRMM)

The shipped catalog `data/rmm-catalog.json` is **derived data**:
[LOLRMM](https://lolrmm.io/) ("Living Off The Land - Remote Monitoring &
Management", the RMM companion of the LOLBin project family, maintained by
magicsword-io) publishes a machine-readable API of RMM tools with their
Windows artifacts. RMM-Sentinel derives from a dated API snapshot
(2026-11-12, licensed Apache-2.0) a filtered subset: Category RMM entries
with at least one extractable Windows artifact — 237 tool families, each
with capped, case-insensitively deduplicated artifact lists.

The derivation is deterministic (same snapshot → byte-identical catalog);
the snapshot itself is **not** committed. Full attribution, licence split
and trademark note: [NOTICE](NOTICE).

Known data properties (by design): several catalogued RMM products bundle a
third-party remote-control component (for example Atera shipping Splashtop),
so a scan can attribute the same binary to two catalog entries — that is
correct, documented behaviour of the upstream data.

## Dual-Use

RMM-Sentinel is **defensive security software**. The catalog and signals
describe how RMM abuse *looks*; the scanner itself only reads and reports.
This is inherently dual-use knowledge — the same observations that let a
defender spot a misused remote-access agent could, in other hands, help
someone pick a quieter variant.

That risk is managed, not denied:

* The repository ships **detections, never capabilities**: no exploit code,
  no payloads, no phishing or credential-harvesting material, no
  command-and-control tooling, no capture or exfiltration code.
* Fixtures used by the test suite are **synthetic and inert**: static files
  that are read, never executed, and containing no real host names or user
  data.
* Everything is published under a defensive-use licence and ethics policy
  ([ETHICS.md](ETHICS.md)) that prohibits weaponisation.
* A blocking keyword gate (`ci/check-keywords.mjs`) fails the build if
  offense markers or secret-shaped material enter the tree, and a scope gate
  pins the exec/write surface (`child_process` only in `src/runner.mjs`,
  filesystem writes only in `src/report.mjs`).

If you are unsure whether your intended use is covered, ask **before** you
build on top of this project (see [SECURITY.md](SECURITY.md)).

## Unauthorized Use — Verbot und Acceptable Use Policy (AUP)

**Using RMM-Sentinel against systems, accounts, or data you are not
authorised to examine is prohibited.** Unauthorised use includes, without
limitation:

1. Scanning or probing hosts, endpoints, or networks of third parties
   without documented permission from their owner.
2. Using RMM-Sentinel — or what you learn from it — to develop, test,
   improve, or validate malware, backdoors, exploits, phishing content, or
   command-and-control infrastructure, including selecting stealthier
   delivery locations for remote-access software you are not entitled to
   place.
3. Using findings to target individuals, to extort, to harass, or to
   facilitate any other unlawful act.
4. Removing, altering, or hiding the licence, ethics, or attribution notices
   to present the work as your own offensive tool.
5. Circumventing the read-only construction (for example by adding write or
   execute probes) and redistributing the result under this project's name.

Acceptable use is the inverse: inventory and review of hosts you are
entitled to assess, detection engineering, incident response, academic
research, and hardening of your own organisation's remote-access surface.
The full policy, including enforcement and reporting, lives in
[ETHICS.md](ETHICS.md); the abuse and appeal process is documented in
[TRANSPARENCY.md](TRANSPARENCY.md) and [APPEAL.md](APPEAL.md).

Violations reported through the channel in [SECURITY.md](SECURITY.md) are
handled within the 48-hour abuse process described there.

## Disclaimer (§ 521 / § 276 Abs. 3 BGB)

RMM-Sentinel wird **"wie besehen" (as-is)** bereitgestellt, ohne Gewähr auf
Vollständigkeit, Richtigkeit oder Eignung für einen bestimmten Zweck. Der
Katalog ist eine Momentaufnahme einer externen Quelle, und die Signale sind
heuristische Erkennungsmuster: ein sauberer Lauf ist **kein** Nachweis, dass
ein Host frei von unerwünschter Remote-Access-Software ist, und ein Signal
ist **kein** Nachweis für einen Angriff — beide erfordern fachliche
Nachprüfung.

Soweit die unentgeltliche Bereitstellung dieser Software als Schenkung zu
werten ist, haftet der Anbieter gemäß **§ 521 BGB** nur bei Vorsatz und
grober Fahrlässigkeit. Eine Haftung für **Vorsatz bleibt gemäß § 276 Abs. 3
BGB ausdrücklich vorbehalten** und kann nicht ausgeschlossen werden; ebenso
unberührt bleiben die zwingenden Haftungsvorschriften des
Produkthaftungsrechts. Für leichte Fahrlässigkeit wird die Haftung — soweit
gesetzlich zulässig — ausgeschlossen.

Der Anbieter übernimmt keine Verantwortung für Schäden, die aus der Nutzung
oder Nicht-Nutzung dieses Werkzeugs entstehen, und keine Verpflichtung zur
Aktualität des Katalogs. Es wird **kein Rechtsrat** erteilt; die genannten
Vorschriften ersetzen keine anwaltliche Beratung im Einzelfall.

Drittanbieter-Inhalte (RMM-Produktnamen und -Artefakte aus der LOLRMM-Quelle)
unterliegen den Lizenzen ihrer jeweiligen Verfasser und werden nur abgeleitet,
nicht verändert. Produkt- und Markennamen sind Marken ihrer jeweiligen
Inhaber; die Nennung dient der reinen Erkennung und impliziert keine
Zugehörigkeit zu oder Billigung durch diese Inhaber.

## Support-Ende und Versionierung

* **Semantic Versioning:** `MAJOR.MINOR.PATCH`. The report schemas
  (`schema_version` `1.0`), the catalog schema (`rmm-sentinel-catalog/1`),
  rule IDs (`RS-SIG-*`), exit codes and CLI flags are part of the public
  contract; breaking any of them requires a MAJOR bump.
* **Support window (best effort):** each MAJOR line is *intended* to receive
  security fixes for about **6 months** after the next MAJOR release; after
  that it is declared end-of-life (EOL) and receives no further updates,
  including for newly disclosed vulnerabilities. This is a best-effort
  intention of a non-commercial, volunteer-run project - not a binding
  promise, warranty or SLA. If capacity changes, the window may be shorter;
  the CHANGELOG and [RELEASING.md](RELEASING.md) carry the authoritative
  statement at any time.
* **No SLA:** releases happen as capacity allows; there is no guaranteed
  response or delivery time for features.
* The current version is printed by `node rmm-sentinel.mjs version` and
  recorded in [CHANGELOG.md](CHANGELOG.md).

## Installation

```console
$ git clone https://github.com/trungminhdo4-glitch/rmm-sentinel
$ cd rmm-sentinel
$ node ci/bootstrap.mjs        # full gate run: syntax, tests, gates
$ node rmm-sentinel.mjs version
rmm-sentinel 0.1.0
```

Requires **Node.js 22 or newer** and **Windows** for `scan`/`signals`
(the generator commands `ioc` and `tools` work on every platform).
No runtime dependencies, no configuration files, no telemetry.

## Usage

```console
node rmm-sentinel.mjs scan      read-only RMM inventory of this Windows host
node rmm-sentinel.mjs signals   abuse-signal heuristics over the inventory
node rmm-sentinel.mjs ioc       IOC / Sigma generator (offline, catalog only)
node rmm-sentinel.mjs tools     list the shipped catalog
node rmm-sentinel.mjs version   print the version
```

Important flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format` | `text` | `text`/`json` for scan/signals; `json`/`csv`/`sigma` for ioc |
| `--out` | — | **the only** filesystem write; opt-in by flag |
| `--fail-on` | `high` | minimum signal severity that exits 1 (`info`, `low`, `medium`, `high`) |
| `--catalog` | `data/rmm-catalog.json` | alternative catalog JSON (validated, fail-closed) |
| `--many-families-threshold` | `4` | RS-SIG-005 threshold |

Exit codes: **0** — clean / no signal at or above `--fail-on`;
**1** — signals at or above `--fail-on` (a `WARNING:` line is printed);
**2** — usage or runtime error.

Catalog-scanning semantics: catalog values match case-insensitively; `*`
inside a value is a wildcard (`AnyDesk-*` matches `AnyDesk-1234`). Uninstall
entries match by exact display name or uninstall-key name. `schtasks` task
names are locale-dependent beyond the name column — the tool only reads the
task name.

CI / scheduled use:

```yaml
- run: node rmm-sentinel.mjs signals --format json --fail-on medium --out signals.json
```

## Repository layout

```
rmm-sentinel.mjs       CLI entry point (wiring only, exit codes 0/1/2)
src/                   catalog loader, parsers, scan, signals, ioc, report,
                       runner (the ONLY child_process consumer), version
data/                  rmm-catalog.json (derived, attributed in NOTICE)
ci/                    blocking CI gates (keywords, DCO, SBOM, coverage,
                       bootstrap) + their tests
test/                  offline unit/acceptance/fuzz tests + synthetic fixtures
.github/workflows/     CI, CodeQL, dependency-review, gitleaks, SBOM, Scorecard
```

## Governance

| Document | Purpose |
| --- | --- |
| [SECURITY.md](SECURITY.md) | vulnerability reporting, 48-hour abuse process |
| [ETHICS.md](ETHICS.md) | defensive-only doctrine and dual-use rules |
| [CONTRIBUTING.md](CONTRIBUTING.md) | contribution and DCO sign-off rules |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | community standards |
| [TRANSPARENCY.md](TRANSPARENCY.md) | what we collect (nothing) and how decisions are published |
| [APPEAL.md](APPEAL.md) | how to appeal an abuse decision |
| [NOTICE](NOTICE) | attribution, the Apache-2.0 / CC-BY-4.0 licence split, LOLRMM provenance |
| [CHANGELOG.md](CHANGELOG.md) | release history (SemVer) |
| [RELEASING.md](RELEASING.md) | release and signing procedure |

## Licence

* **Code** — [Apache License 2.0](LICENSE).
* **Detection rules, catalog data, fixtures, documentation and IOC-like
  content** — [CC BY 4.0](LICENSE-CC-BY-4.0.txt), attribution required.

See [NOTICE](NOTICE) for the exact split and the LOLRMM attribution.

---

<!-- Badges last, after purpose, dual-use, AUP, disclaimer and support policy. -->

[![CI](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/codeql.yml)
[![Gitleaks](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/gitleaks.yml)
[![SBOM](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/sbom.yml/badge.svg)](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/sbom.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)](https://github.com/trungminhdo4-glitch/rmm-sentinel/actions/workflows/ci.yml)
[![Node](https://img.shields.io/badge/node-%E2%89%A522-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: Code](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![License: Content](https://img.shields.io/badge/license-CC%20BY%204.0-lightgrey.svg)](LICENSE-CC-BY-4.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/trungminhdo4-glitch/rmm-sentinel/badge)](https://securityscorecards.dev/viewer/?uri=github.com/trungminhdo4-glitch/rmm-sentinel)
[![DCO](https://img.shields.io/badge/DCO-required-green.svg)](CONTRIBUTING.md)
