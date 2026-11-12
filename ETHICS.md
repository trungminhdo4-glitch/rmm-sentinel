# Ethics Policy

RMM-Sentinel exists to **defend** Windows fleets against the misuse of
legitimate remote-access and remote-management software. This document is
binding for everyone who contributes to, distributes, or operates this
project.

## 1. Defensive purpose only

The project is limited to detection, hardening, forensics, and defensive
research:

* **Allowed:** local inventory and review of hosts you are entitled to
  assess, abuse-signal development, SIEM/EDR rule engineering (Sigma, IOC
  packs), incident response, academic and defensive security research, and
  hardening your own organisation's remote-access surface.
* **Forbidden:** developing or improving exploits, payloads, shellcode,
  backdoors, malware, phishing or credential-harvesting material,
  command-and-control tooling, credential theft, surveillance capabilities —
  and any use of the catalog to select stealthier deployment locations for
  remote-access software you are not entitled to place.

The repository must never contain exploit code, proof-of-concept exploits,
payloads, phishing templates, C2 infrastructure, or capture/exfiltration
code — in source, fixtures, documentation, or generated artifacts. This is
enforced by `ci/check-keywords.mjs`, which blocks the build when offense
markers appear.

## 2. Read-only by construction

RMM-Sentinel must stay read-only unless the user explicitly opts in:

* system queries run **only** through the fixed probe allowlist in
  `src/runner.mjs` (read-only PowerShell CIM/registry reads and a read-only
  `schtasks /query`) — the gate pins that no other production file may
  import `child_process` and that the runner may not contain mutating
  command verbs;
* filesystem writes happen **only** through the explicit `--out` flag in
  `src/report.mjs` (pinned by the same gate);
* **no network access at all**: the tool is offline by construction, and any
  networking in production code fails the build;
* scanned content is parsed and matched, never executed; fixtures are inert
  data, proven by the no-write and probe-allowlist tests.

Weakening any of these properties requires an explicit design discussion in
an issue before code is written, and cannot be merged behind a default-on
flag.

## 3. Authorisation and scope

Do not use this project to examine hosts, endpoints, accounts, or private
data without documented permission from their owner. Lawful use requires
prior authorisation from the owner of the target system (for an MSP, the
client's scope of service; for a SOC, the estate it monitors). The
maintainers do not provide authorisation for third-party systems and will
not assist with unauthorised scanning.

## 4. Honest reporting

* A clean run means "no catalogued RMM artifacts or signals found", never
  "safe". Reports, README text, and CI output must keep that distinction
  visible.
* Signals are evidence for human review, not verdicts. Do not publish
  accusations about named hosts, users, or organisations based on heuristic
  output alone — presence of a catalogued tool is context, not misuse.
* Do not fabricate test results, coverage numbers, catalog provenance, or
  vulnerability claims. Unverified items must be marked as such.
* The catalog is derived from LOLRMM under Apache-2.0 attribution; claim no
  originality for upstream data (see [NOTICE](NOTICE)).

## 5. Responsible disclosure

Vulnerability and abuse reports go through [SECURITY.md](SECURITY.md). We
acknowledge within 48 hours, triage within 7 days, and give affected
reporters a chance to be heard before decisions are final (see
[APPEAL.md](APPEAL.md)).

## 6. No weaponised derivatives

Redistributing RMM-Sentinel with its read-only construction removed, or
presenting it as an offensive tool, violates this policy and the attribution
conditions in [NOTICE](NOTICE). Dual-use knowledge published here stays
dual-use: it is shared so defenders can see the same signals attackers leave
behind when they misuse legitimate remote-access tooling.

## 7. Conflicts of interest and enforcement

Maintainers disclose conflicts before acting on a report about systems they
operate themselves. Decisions under this policy are recorded (without
personal data beyond what the process requires) in line with
[TRANSPARENCY.md](TRANSPARENCY.md). Anyone affected by a decision may appeal
it under [APPEAL.md](APPEAL.md).

Questions about the boundary of an acceptable contribution: open a
discussion issue **before** submitting the code.
