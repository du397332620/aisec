# Contributing

1. Add or change a detector with the smallest useful rule surface.
2. Add a vulnerable fixture proving the true positive.
3. Add a safe near-miss proving that the rule does not over-fire.
4. Add the rule and its CWE, default evidence, applicability profile, known
   false-positive modes and review guidance to `rules/catalog.json`. Add a new
   applicability profile only when the existing version policy does not fit.
5. Add the rule ID to the positive and near-miss cases in
   `benchmark/manifest.json`, then run `npm run rules:render`; do not edit
   `RULES.md` by hand.
6. Keep credential-shaped values as placeholders that are materialized only in
   a temporary test directory, and ensure serialized reports redact them.
7. Run `npm test`, `npm run benchmark`, `npm run benchmark:resources`,
   `npm run test:docs`, `npm run test:package` and `npm run test:release`; every
   category must have zero false positives, false negatives and evidence-level
   or CWE mismatches, `npm run rules:check` must pass, and the
   documentation/resource/release budgets must remain green.
8. For adapter or compatibility changes, prepare the Trivy database and run
   `npm run test:engines` with every version newly added to the verified matrix.

Detection changes should explain their evidence level, expected false-positive
mode, affected framework versions, CWE mapping and remediation. A rule based on
file or route naming alone must be `inferred`; it cannot become blocking without
additional deterministic evidence.

Do not add install scripts, curl-to-shell flows, automatic project builds, or
network access to the default scan path.

Security-policy changes must preserve the monotonic trust boundary: policies
are explicit operator-owned files outside the target and may only retain or
strengthen default predeploy requirements. Do not add target policy discovery,
rule/engine disable lists, coverage overrides or silent baseline-policy
migration. Update the public policy/report schemas and positive/negative policy
tests together.

Declarative rule-pack changes must preserve the non-executable extension
boundary. Packs are explicit operator-owned files outside the target and may
only add bounded literal findings and required coverage. Do not add dynamic
imports, JavaScript/Python/WASM execution, regex, commands, target-side pack
discovery, suppressions or gate relaxation. Update the public RulePack,
ScanReport and CI schemas plus path, resource, baseline and installed-package
tests together. Required-literal absence rules must remain inferred and
path-only: selecting no file or reaching a bound is partial coverage, never a
fabricated vulnerability finding. Selector-preview changes must reuse the scan
predicate, retain strict output validation and deterministic path/work bounds,
and must not expose local pack paths, literal definitions or vulnerability
claims.

Report-format changes must validate their public contract before serialization
and include hostile target-controlled text tests. GitHub annotations must reject
unsafe paths, escape workflow-command syntax and retain deterministic bounds;
Markdown and HTML must not turn report content into active links or markup.
