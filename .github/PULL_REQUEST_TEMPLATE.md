## Summary

<!-- What does this change, and why? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New catalog rule / signal / IOC capability
- [ ] Refactor (no behaviour change)
- [ ] Documentation / governance
- [ ] CI

## Checklist

- [ ] Tests cover the change; any behaviour change has a test that fails without this patch
- [ ] `node --test` passes; every signal rule change has match **and** non-match tests
- [ ] Line coverage stays >= 80 % (`node ci/coverage.mjs`)
- [ ] `node --test ci/test-gates.mjs ci/test-bootstrap.mjs` and `node ci/check-keywords.mjs` pass locally
- [ ] No secrets, credentials, or personal data in code, fixtures, or docs
- [ ] Change stays **defensive only**: no exploit code, payloads, phishing material, C2 tooling, or code execution
- [ ] Read-only by construction preserved: probes stay inside the `src/runner.mjs` allowlist, filesystem writes only behind `--out`
- [ ] `README.md` updated for user-visible changes; `[Unreleased]` entry added to `CHANGELOG.md`
- [ ] Catalog contributions stay inside the derived-data rules (`data/rmm-catalog.json` provenance preserved, LOLRMM attribution intact)

## DCO

- [ ] All commits are signed off (`git commit -s`) and the `Signed-off-by`
      line matches my Git identity - I certify the right to contribute this
      work under the licences in `NOTICE` (Apache-2.0 code, CC BY 4.0 rules
      and docs).
