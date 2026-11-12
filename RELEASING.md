# Releasing RMM-Sentinel

Releases are produced by maintainers only. Every step below is mechanical; if
any step fails, stop and do not tag.

## Versioning

* **Semantic Versioning.** `MAJOR.MINOR.PATCH`.
* The following are public contract and may only change with a MAJOR bump:
  exit codes (`0`/`1`/`2`), CLI flags and their defaults, signal rule IDs
  (`RS-SIG-<NNN>`), the report JSON `schema_version` (`1.0`), the catalog
  schema (`rmm-sentinel-catalog/1`), the IOC JSON/CSV/Sigma output shapes,
  and the probe allowlist semantics of `src/runner.mjs`.
* New signals, new flags, and catalog updates are MINOR. Fixes that change
  no contract are PATCH.
* Pre-releases use a suffix (`v0.2.0-rc.1`) and are never the default
  download.

## Support window

* **Support window (best effort).** Each MAJOR line is intended to receive
  security fixes for 6 months after the next MAJOR release, then declared
  end-of-life (EOL) in the README and CHANGELOG. This is a best-effort
  intention of a non-commercial project, not a binding commitment or SLA;
  a shorter window may be announced in the CHANGELOG when capacity requires
  it.
* EOL versions receive no backports, including for disclosed vulnerabilities.

## Repository bootstrap (fresh clone)

A fresh clone becomes green with one command:

```console
$ node ci/bootstrap.mjs
```

The script executes a fixed step plan (tool preflight first, then a syntax
check of every shipped `.mjs`, the full test suite, the gate unit tests, the
keyword gate). A missing required tool (`node`, `gitleaks`, `actionlint`,
`yamllint`) fails closed with exit 2 and a pointer to the machine tool
registry (`school/tool-registry`) — or, on machines without that registry,
with a pointer to this section of RELEASING.md. A failing step exits 1. The
script always runs against the repository root, regardless of the invoking
directory. Step semantics are pinned by `ci/test-bootstrap.mjs`.

**Deliberate deviation from a sibling project:** unlike the Go-based
ModelGate, there is **no `--offline` flag**. The project has zero runtime
dependencies, so there is no module-download step to skip — the step plan is
identical on- and offline, and passing an unknown argument (including
`--offline`) fails with exit 2. If a dependency is ever introduced, the flag
must be reintroduced together with the download step in the same change.

## Reproducible repository initialization

The repository layout was created with this command set; re-creating it
(mirror, fork recovery) follows the same order:

```console
$ git init -b main
$ git config user.name  "trung-dev"
$ git config user.email "trung-dev@users.noreply.github.com"  # == DCO email
$ # layout, in commit order:
$ #   rmm-sentinel.mjs       CLI entry point (wiring only)
$ #   src/                   catalog/parse/scan/signals/ioc/report/runner/version
$ #   data/                  rmm-catalog.json (derived, attributed in NOTICE)
$ #   test/                  offline tests + synthetic fixtures
$ #   ci/                    test-gates, test-bootstrap, check-keywords,
$ #                          check-dco, sbom, coverage, bootstrap
$ #   .github/               workflows (ci, codeql, dependency-review,
$ #                          gitleaks, sbom, scorecard), dependabot,
$ #                          issue and PR templates
$ #   governance docs        README, SECURITY, ETHICS, CONTRIBUTING (+ DCO),
$ #                          CODE_OF_CONDUCT, NOTICE, TRANSPARENCY, APPEAL,
$ #                          CHANGELOG, RELEASING, LICENSE, LICENSE-CC-BY-4.0.txt
$ git add -A && git commit -s -m "initial import"
$ node ci/bootstrap.mjs && git status --short   # must end green and clean
```

## Release checklist

1. **Green gates on the release commit**
   ```console
   $ node --test
   $ node --test ci/test-gates.mjs ci/test-bootstrap.mjs
   $ node ci/check-keywords.mjs
   $ node ci/coverage.mjs
   $ gitleaks dir . --redact
   ```
   Line coverage of the production files ≥ 80 %, every production file
   accounted (see CONTRIBUTING.md; `node ci/coverage.mjs` enforces both).
2. **Changelog** — move the `[Unreleased]` entries into a new versioned
   section with today's date; add the comparison links.
3. **README** — version references and support table still accurate; catalog
   tool count matches `data/rmm-catalog.json`.
4. **Tag** — annotated and signed:
   ```console
   $ git tag -s v0.1.0 -m "RMM-Sentinel v0.1.0"
   ```
5. **Distribution** — the tool ships from source; there are no compiled
   binaries. The release artifact is the source tree:
   ```console
   $ git archive --format=tar.gz --prefix=rmm-sentinel-0.1.0/ -o rmm-sentinel-0.1.0.tar.gz v0.1.0
   $ sha256sum rmm-sentinel-0.1.0.tar.gz > checksums.txt
   ```
6. **SBOM** — generate the CycloneDX SBOM of the release and attach it:
   ```console
   $ node ci/sbom.mjs --out sbom.cdx.json --tool-version 0.1.0
   ```
7. **Sign** — sign the checksums and SBOM with cosign (keyless/OIDC):
   ```console
   $ cosign sign-blob --yes --bundle release.bundle checksums.txt
   $ cosign sign-blob --yes --bundle release.bundle sbom.cdx.json
   ```
8. **Publish** — GitHub Release with the source archive, `checksums.txt`,
   `sbom.cdx.json`, `release.bundle`, and the CHANGELOG section as release
   notes. The catalog's snapshot date and tool count are stated in the
   release notes (provenance, see NOTICE).
9. **Post-release** — open the next `[Unreleased]` section; announce
   policy-relevant changes (see TRANSPARENCY.md §5).

## Hotfix releases

Security fixes skip the MINOR cycle: branch from the affected MAJOR line,
ship as PATCH, and reference the advisory in the CHANGELOG entry. The
advisory is published together with the release.

## Yanking

A broken release may be marked *yanked* on GitHub (never deleted): the tag
stays, the release notes are prefixed with the reason, and users are pointed
at the replacement version. Deleting tags or releases requires explicit owner
approval.
