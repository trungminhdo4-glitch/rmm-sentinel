# Contributing to RMM-Sentinel

Thanks for helping improve a defensive security tool. Please read
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first, and note that contributions
must stay inside the defensive scope defined in [ETHICS.md](ETHICS.md).

## Where to start

* **Bug reports and feature ideas** - GitHub Issues (use the templates).
* **Security vulnerabilities** - [SECURITY.md](SECURITY.md), never a public
  issue.
* **Questions about acceptable scope** - open a discussion issue *before*
  writing code.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. The sign-off certifies that you have the
right to contribute the work under the licences in [NOTICE](NOTICE):

```console
$ git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match your Git identity (`git config user.name` /
`git config user.email`). Commits without a matching sign-off fail the
blocking `dco` CI job - see `ci/check-dco.mjs`.

**Decision (identity vs. DCO check):** the repository-local Git identity is
`trung-dev <trung-dev@users.noreply.github.com>` and the DCO check stays
configured against the pusher's commit email, so the sign-off must use the
same address. Contributors keep whatever identity they publish with; the
requirement is only that sign-off and author email agree.

If you have commits that are already unsigned:

```console
$ git rebase HEAD~n --exec 'git commit --amend --no-edit --reset-author -s'
```

(Only rewrite your own unpushed commits, and never rewrite someone else's.)

## Local quality gates (all blocking in CI)

Run these before every pull request:

```console
$ node ci/bootstrap.mjs           # full green run: preflight, syntax, tests, gates
$ node --test                     # unit + acceptance, includes the fuzz sweep
$ node --test ci/test-gates.mjs ci/test-bootstrap.mjs
$ node ci/check-keywords.mjs      # scope + secret gate on this tree
$ node ci/coverage.mjs            # line coverage >= 80 %
$ gitleaks dir . --redact         # no secrets
```

Line coverage of the production files must stay at or above **80 %**; every
production file must appear in the coverage table
(`node ci/coverage.mjs` enforces both, fail-closed).

Workspace-level check (when working in the agent workspace):

```console
$ node school/quality-loop/quality-loop.mjs run builtin:mjs --cwd <repo>
```

## Pull request rules

1. **One task per PR.** Unrelated changes go in a separate PR.
2. **Tests first.** A behaviour change needs a test that fails before your
   fix and passes after (TDD). Fuzz findings must be added to the mutation
   corpus in `test/test-fuzz.mjs` together with the fix.
3. **Stay defensive.** No exploit code, payloads, phishing material, C2
   tooling, or code-execution paths. `ci/check-keywords.mjs` blocks the
   build if this is violated, and reviewers will reject it anyway.
4. **Read-only by construction.** The probe allowlist lives exclusively in
   `src/runner.mjs` (read-only queries only); any new filesystem write must
   stay in `src/report.mjs` behind an explicit opt-in flag; no production
   networking at all. The scope gate enforces all three - do not fight the
   gate, propose a design discussion instead.
5. **Signal-rule contributions** must follow the catalogue format: ID
   `RS-SIG-<NNN>`, severity, title, `why`, `falsepositives`, plus a test in
   `test/test-signals.mjs` covering both a matching and a non-matching
   sample. Signal metadata is licensed CC BY 4.0 (see [NOTICE](NOTICE)).
6. **Catalog contributions** stay derived data: the provenance block
   (`source`, `license_note`) in `data/rmm-catalog.json` must remain intact,
   caps and dedup rules must be re-run deterministically, and new artifact
   kinds must be added to the validation schema with a non-empty test
   catalog. Never invent artifact values - every value must come from a
   cited upstream source.
7. **Docs and changelog.** User-visible changes update `README.md` and add a
   bullet under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
8. **No secrets, no personal data.** Never commit credentials, tokens, or
   real user/host data — including in fixtures (use synthetic values only).
   Scan output pasted into an issue must be redacted.

## Commit style

* Imperative subject, ≤ 72 characters, prefixed with the area when useful
  (`scan:`, `signals:`, `ioc:`, `cli:`, `ci:`, `catalog:`, `docs:`).
* Body explains *why*, not *what* (the diff shows what).
* Always `-s` (DCO).

## Release process

Maintainers follow [RELEASING.md](RELEASING.md): SemVer, changelog, full
gate run, SBOM, and signed artifacts. Contributors do not need to worry
about signing — that happens in CI at release time.
