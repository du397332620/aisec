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
tests together. Baseline gates must remain additive, distinguish confirmed
blockers from incomplete comparison evidence, and retain explicit suppression
semantics.

Local-gate changes must keep state outside the target, reject shared or
ambiguous state, preserve owner-only files and never advance a pinned baseline
automatically. A blocked or incomplete run must remain compared with the same
baseline on repetition.

External-adapter changes must keep target-controlled ignores ineffective while
preserving AIsec's deterministic inventory exclusions. Add both a captured
adapter-input regression and a verified real-engine fixture when target
selection semantics change.

Trivy package-context changes must use schema-v2 `Packages` evidence and keep an
unmatched or ambiguous relationship `unknown`; never infer directness from a
manifest name. Add direct, indirect, unknown, malformed-record, fix/no-fix and
real-engine cases, plus proof that presentation grouping leaves canonical
signals, findings, fingerprints and decisions unchanged.

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
claims. Scan and preview coverage must reuse the shared project-inventory
decision: unsafe inventory gaps make active packs partial, while expected
directory exclusions alone remain complete.

Report-format changes must validate their public contract before serialization
and include hostile target-controlled text tests. GitHub annotations must reject
unsafe paths, escape workflow-command syntax and retain deterministic bounds;
Markdown and HTML must not turn report content into active links or markup.

Interface-queue changes must remain a zero-request transformation of a validated
stored report and reuse both the route-security review and BOLA route policy.
Keep candidate/exclusion output deterministic and bounded, reject unsafe source
paths and contradictory counts, preserve aggregate exclusion reasons, and never
add target hosts, credentials, concrete object IDs, request bodies or automatic
verifier execution. Update the public queue schema, CLI/API, docs and installed-
package tests together.

Queue-to-BOLA selection changes must resolve candidate IDs only against a queue
regenerated from the same validated report. Preserve legacy unselected draft
compatibility, the nine-case bound, deterministic exact-route ordering and the
explicit queue/interface-candidate/route/signal/BOLA-candidate binding. Unknown,
duplicate, omitted, multi-source or truncated-evidence selections must fail
closed; never accept target hosts, credentials, concrete object IDs, external
queue files or automatic verifier execution.

BOLA preflight changes must keep `prepare-bola` and `check-bola` completely
offline. The template must remain invalid as an active manifest until every
critical instruction is replaced, retain one exact binding per selected case,
and accept only bounded selected 1.1 JSON. The checker may inspect declared
environment-variable names but must never read their values, resolve DNS, open
a socket or invoke the requester. If a template is supplied, every case must
remain bound to its order, ID, fixed request budget, method, route structure,
object-ID fields, account roles, status codes and evidence mode; mismatch must fail rather than
fall back to an unbound check. Its output must stay sanitized and explicitly
review-required. Keep strict template/check 1.0 compatibility and update both
public schemas, placeholder/route rejection tests, CLI/API docs and
installed-package smoke together. Active `verify-bola` changes must retain the
required manifest/template/bound-check handoff, accept strict bound check 1.1
compatibility, reject unbound 1.0 for execution, and complete all receipt
matching before reading credentials or invoking networking. Its active result
must remain strict `BolaVerificationReport 1.1.0`, include only sanitized
receipt/template provenance, validate case order/count/budget and signal/result
relationships, and never copy credentials, tokens, identities, response bodies
or arbitrary requester errors. Keep legacy report 1.0 readable only without a
preflight claim, and update the public report schema plus installed API smoke.
