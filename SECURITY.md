# Security policy and scanner threat model

AIsec processes repositories and archives that may be actively hostile. Treat a
scanner bug that causes command execution, arbitrary file access, credential
disclosure, sandbox escape, unsafe network access, or a false clean result as a
security issue.

## Reporting

Report suspected vulnerabilities through [GitHub's private vulnerability
reporting form](https://github.com/du397332620/aisec/security/advisories/new).
Do not open a public issue, discussion or pull request containing exploit
details. General hardening ideas and rule-quality reports that do not expose a
security boundary bypass can use the public issue tracker.

Include the affected version or commit, platform, minimum reproducer, impact,
whether untrusted project content is required, and any suggested mitigation.
Remove real credentials and personal data from reproductions. If the form is
temporarily unavailable, wait and retry rather than publishing the report.

## Supported versions

| Target | Security support |
| --- | --- |
| `main` before the first tagged beta | Supported |
| Latest tagged release | Supported once a release exists |
| Older tagged releases | Not supported during the beta |

Until the first tagged release, `0.1.0` in `package.json` is an unreleased beta
development version and `main` is the only supported target.

## Response and disclosure process

- The maintainer aims to acknowledge a private report within 3 business days
  and provide an initial assessment within 7 business days.
- Accepted reports are reproduced and fixed privately. The reporter receives a
  status update at least every 14 days while remediation remains open.
- The maintainer and reporter coordinate disclosure. A GitHub Security Advisory
  and patched release are published when a fix and regression test are ready;
  earlier disclosure may be necessary when exploitation is already public.
- Credit is offered unless the reporter asks to remain anonymous.

Good-faith testing must use systems and repositories you own or are explicitly
authorized to test. Avoid privacy violations, service disruption, persistence,
social engineering and access to data beyond the minimum needed to demonstrate
impact. Stop testing and report privately once a vulnerability is confirmed.

## Trust boundaries

- Project source, Git metadata, configuration, archives and dependency names are
  untrusted.
- AIsec's own shipped rules and explicitly selected operator-owned security
  policies or declarative rule packs outside the scanned target are trusted
  data inputs. Target repository configuration is not promoted into this
  boundary, and rule packs are never trusted as executable code.
- PATH executables are trusted by the invoking user; managed executables have a
  pinned SHA-256 checked before every run.
- Scanner child processes receive no ambient variable whose name indicates an
  API key, token, secret, password, private/access key, credential or auth value.
- A configured SHA-256 proves that a managed file has not changed after
  installation; users must still authenticate the original release and digest.
- Only the engine versions listed in the verified Beta compatibility matrix are
  executed. Unknown or unparsable versions fail coverage closed.
- Third-party scanner output is untrusted and normalized/redacted before use.
- A concrete credential found inside a sensitive environment interpolation
  fallback is never retained in evidence or metadata. The native signal keeps
  only the variable name and a fully redacted placeholder, so the value also
  cannot influence its report fingerprint.
- APK/IPA filenames, archive paths and member bytes are untrusted. AIsec rejects
  unsafe paths before reading members, invokes `unzip` without a shell, keeps
  member output in bounded memory and never extracts archive members onto disk.
- Report titles, descriptions and source locations remain untrusted when they
  enter CI output. GitHub workflow-command data and properties are escaped,
  annotations accept only normalized relative paths, and CI/Markdown output is
  bounded. Report rendering performs no upload and reads no ambient CI tokens.
- Target-controlled Gitleaks, Opengrep and Trivy configuration/ignore files are
  not trusted by the adapters and cannot silently suppress acceptance findings.
  This includes Gitleaks allow comments, Opengrep `nosemgrep`/ignore files and
  Trivy general, ignore and secret-scanner configuration. Opengrep instead uses
  an AIsec-owned temporary ignore containing only the same deterministic
  dependency, virtual-environment, cache and build-directory exclusions as the
  native inventory; target ignore content is never imported.
- Trivy dependency relationship and fix context is copied only from validated
  schema-v2 package data. Missing or ambiguous relationships remain unknown;
  the bounded terminal/HTML grouping is presentation-only and cannot merge
  canonical evidence, change the gate or establish runtime reachability.
  Dockerfile/IaC inspection does not imply that packages inside a referenced
  base image were downloaded or vulnerability-scanned.
- A release policy is never discovered from the target. AIsec resolves its real
  path, rejects files or symlinks inside the scan root, validates a strict
  versioned schema and expiry, and records the applied SHA-256 digest. A target
  `.aisec.yml` is ignored and cannot suppress native findings. Policy baselines
  require the same explicitly supplied digest. Non-empty policy suppressions
  also require a separate explicit confirmation and record that approval. The
  optional route-security baseline gate is additive, requires comparison
  evidence, evaluates only eligible open findings, and can require partial or
  bounded route comparison to fail closed as incomplete.
- `local-gate` keeps its baseline and latest report in a dedicated
  operator-selected directory outside the target. The directory must be a real,
  owner-only directory; an unrecognized non-empty directory, symlinked root,
  non-regular baseline, target mismatch or changed policy/rule-pack digest is
  rejected. The first baseline is written once with owner-only permissions and
  is never advanced by a later scan; only `latest.json` is atomically replaced.
- A declarative rule pack is also never discovered from the target. Its real
  path must be outside the scan root, its strict schema has no regex, script,
  command, import or callback fields, and matching is bounded to line-local
  literals over the existing inventory. Required-literal absence rules emit
  only inferred, path-only evidence after a complete bounded scan of a selected
  existing file. No selected file or an interrupted evaluation produces partial
  required coverage rather than an absence finding. Reports record its ID, rule
  count and SHA-256 without recording its local path or literal definitions.
  Baselines require the same pack set and digest. A partial project inventory
  also makes every active pack's scan coverage partial, while retaining valid
  findings from files that were safely inspected; expected directory
  exclusions alone do not cause that downgrade.
- Rule-pack preview uses the same outside-target loader, safe source inventory
  and selector predicate. It evaluates no rule literals and produces no
  findings. Its strict output omits pack paths and literal definitions, lists
  only bounded normalized relative target paths, and becomes `partial` when
  inventory, selector-work or path-output limits prevent a complete preview.
- Trivy scans use an AIsec-owned offline cache. Missing, invalid or stale
  database metadata fails coverage; database download happens only through the
  explicit `engines prepare trivy` setup command.
- A local, test or staging URL is accessed only through an explicit
  authorization manifest plus `--confirm`.
- `interface-audit` accepts one strict ScanReport regular JSON file capped at
  64 MiB (or a stored scan ID) and derives only bounded static evidence. It
  reads no credential values, resolves no DNS, executes no target code and
  sends no request. Its strict `InterfaceSecurityAudit 1.0.0` omits the scan
  target, source snippets, arbitrary metadata, URLs, request/response bodies,
  tokens, credentials and request templates. Route templates and normalized
  relative source paths remain because this is a local reviewer artifact;
  review it before sharing. Omitted evidence, unsafe locations and unattributed
  dangerous-dataflow signals make coverage partial. IDs/digests are local
  consistency evidence, not a signature, discovery guarantee or proof of
  reachability, exploitability, safety or active testing.
- `prepare-interface-review` and `check-interface-review` are separate offline
  operations over an explicitly supplied strict audit (16 MiB maximum) and
  operator disposition (1 MiB maximum). They read no credential values, resolve
  no DNS, execute no target code and send no requests. A disposition is bound to
  the full canonical audit digest and exact ordered entry context; it cannot
  mutate or suppress source findings, change the scan decision/audit coverage,
  advance a baseline or act as a release waiver. Partial audits, unreviewed or
  expired entries fail review completeness. Reviewer names, timestamps, route
  templates and rationales make these internal artifacts that must be inspected
  before sharing. Digests/stable IDs are not signatures or trusted identity/time
  evidence, and even `recorded` is not a security pass or safety claim.
- `check-interface-review-receipt` is a third, separate offline operation over
  the same strict audit and disposition plus one saved strict review (2 MiB
  maximum). It requires exact audit fields, disposition fields, entry content
  and entry order, digest-checks the complete saved receipt, rejects a receipt
  dated later than the current local check and re-evaluates expiry without
  rewriting historical state. Its output omits routes, reviewer identity and
  rationales and fixes credential/DNS/network/target-code counters at zero.
  Local-clock status changes, hashes and stable IDs are consistency evidence,
  not signatures, trusted timestamps, evidence authentication, a release waiver
  or a security/safety claim.
- `interface-queue` is a separate static planning operation over a stored scan
  report. It resolves no host, reads no credentials, emits no concrete object
  identifier or request template, and records zero network requests. Only exact
  open object-authorization routes with detector-recorded object IDs and the
  existing BOLA read classification are eligible; output/source bounds are
  visible as partial coverage and all other reviewed routes retain exclusion
  reasons.
- Selected `draft-bola --candidate` handoff regenerates that queue from the same
  validated scan report; it does not accept an external queue document. It
  permits one to nine unique emitted candidates, requires one complete source
  without truncated finding references, binds queue/route/signal/candidate IDs,
  and still emits placeholders without resolving a host or sending a request.
- `prepare-bola` accepts only a selected 1.1 draft JSON file of at most 1 MiB.
  It preserves exact queue/route/evidence bindings in a strict wrapper whose
  nested authorization skeleton retains critical instruction placeholders and
  therefore cannot be executed. It reads no credentials, resolves no DNS and
  sends no request.
- `check-bola` applies the normal strict BOLA manifest schema and semantic policy
  offline to a file of at most 1 MiB. An optional unchanged template is a
  second, independently bounded 1 MiB JSON input. When supplied, exact case
  order/IDs, fixed request budget, method, route structure, object-ID fields,
  account roles, status codes and evidence modes are required; concrete dynamic route/body IDs may be
  filled, but template drift fails without falling back to an unbound result.
  Residual instruction markers and framework route parameters fail before any
  credential lookup. The strict output omits targets, concrete routes, bodies,
  object IDs, evidence values and credential names/values. A valid check remains
  `review_required`, not proof of authorization, reachability, protection or a
  vulnerability. Template IDs and digests provide local integrity evidence, not
  origin authentication or a signature; keep the template operator-owned.
- `verify-bola` requires the same completed manifest, unchanged template and a
  saved template-bound check 1.1/1.2 receipt in addition to `--confirm`. It loads
  each bounded file once, recomputes the canonical manifest digest and complete
  template binding, and rejects unbound, malformed, forged or drifted inputs
  before reading credential values, resolving DNS or invoking the requester.
  Receipt IDs/digests are consistency evidence, not a signature, freshness
  proof or origin authentication; keep all three artifacts operator-owned.
  A successful active run emits strict `BolaVerificationReport 1.1.0` with only
  sanitized receipt/template provenance. Its validator recomputes receipt
  identity and requires exact result case order, counts and budget. Artifact
  paths, target/route/body/object/fixture values, credential names/values,
  identities, tokens and response bodies are excluded from provenance, and
  arbitrary requester error text is never copied into case results. Low-level
  execution remains report 1.0 without provenance and cannot claim this gate.
- `audit-bola` accepts the retained manifest, template, bound check and saved
  provenance-bound report as four independently bounded 1 MiB inputs. It
  reuses the complete offline preflight, then requires exact report provenance,
  target, account-label order and case ID/method/path/test-label/role binding.
  It reads no credential values, resolves no DNS, invokes no requester and sends
  no request. Its strict `BolaVerificationAudit 1.0.0` output contains only
  stable IDs, canonical digests, aggregate outcomes, fixed binding assertions
  and zero-I/O counters; concrete targets/routes/fixtures, credential names or
  values, identities, tokens, responses and case reasons remain excluded.
  This local consistency record is not a signature, origin/freshness proof or
  proof that the recorded observations occurred. Legacy report 1.0 is not
  eligible because it cannot claim preflight provenance.
- `audit-bola-lineage` additionally accepts a strict JSON ScanReport regular
  file capped at 64 MiB and a selected draft 1.1 regular JSON file capped at
  1 MiB. It regenerates the interface queue and ordered selected draft from the
  exact report, compares deterministic draft fields and template source
  semantics, then reuses the complete `audit-bola` result. It reads no
  credential values, resolves no DNS, invokes no requester, executes no target
  code and sends no request. Its strict `BolaVerificationLineageAudit 1.0.0`
  output exposes only stable IDs, canonical digests, timestamps, aggregate
  counts, fixed assertions and zero-I/O counters; target/route/source details,
  rule/finding evidence and active-test data are excluded. The receipt proves
  retained-file consistency only, not authorship, origin, freshness, scan
  execution or observation authenticity. Legacy unselected draft 1.0 is not
  eligible because it has no interface-queue selection binding.
- `check-bola-lineage` accepts that saved lineage receipt as a seventh strict
  regular JSON file capped at 1 MiB and recomputes the complete six-file lineage
  offline. It compares every stable receipt field; only the freshly regenerated
  top-level `auditedAt` is excluded, while the saved timestamp remains validated
  and bound into the canonical complete-receipt digest. The command reads no
  credential values, resolves no DNS, invokes no requester, executes no target
  code and sends no request. Its strict `BolaVerificationLineageCheck 1.0.0`
  omits target/route/source/rule/finding/object/fixture/credential/identity/token/
  response/case-reason data. IDs and digests prove local consistency only, not
  authorship, origin, freshness, execution or observation authenticity.
- Passive web requests pin a validated DNS answer to the socket and redirects
  must retain the exact authorized origin. Local verification is deliberately
  allowed to reach private addresses; staging/test verification is not.
- BOLA verification uses exactly two declared low-privilege accounts and fixed,
  pre-created test-object assertions. It refuses production, mutation methods,
  mutation-like paths, redirects, object enumeration and credential values in
  manifests or reports. Query-style POST routes remain an explicit trusted
  manifest assertion and should be executed only against disposable fixtures.
  Confirmed active verification also rejects any residual instruction or route
  parameter placeholder rather than sending it literally, and executes the
  already checked in-memory manifest without reopening its path.

## Current limitations

The Node process itself is not a kernel sandbox. Run AIsec in an OS sandbox or a
locked-down CI worker when inspecting unknown public repositories. The beta
doesn't execute project code, but optional scanner engines have their own parser
attack surfaces. AIsec's resource bounds reduce risk; they do not prove parser
safety.

The default source inventory accepts at most 20,000 text files, 2 MiB per file
and reads at most 64 MiB of aggregate candidate input. Every detector/adapter
emits at most 2,000 signals, and at most 10 APK/IPA paths are accepted. Supported
CLI overrides have hard ceilings; reaching a limit is reported as partial or
failed coverage rather than a clean result. The synthetic resource benchmark
checks broad time/RSS budgets, but repository shape and third-party parser
behavior can still vary.

At most 8 operator rule packs, 100 rules per pack and 256 total custom rules are
accepted; each pack is at most 256 KiB. Literal/selector counts, aggregate
rule-file selection work, inspected bytes, literal-byte work and evaluated lines
are separately bounded. Reaching a custom-rule work or output limit makes its
required coverage `partial`. A RulePack absence result proves only that its
reviewed line-local literal was not found in a selected inspected source file;
it does not prove that a runtime security control is missing. Selector preview
lists at most 100 paths per rule and 2,000 total under the shared 1,000,000
rule-file evaluation ceiling. Preview output says nothing about whether a
literal is present or whether a rule would produce a finding.

Mobile archive inspection selects at most 25 supported members after validating
up to 200,000 listed paths. It accepts at most 8 MiB from one member, 16 MiB of
aggregate uncompressed member input and 8 MiB of recovered text. It semantically
decodes binary plists with separate object, collection, string and depth limits,
and recovers printable ASCII/UTF-16 evidence from other selected binary resources;
it is not a DEX, Android binary-XML, resource-table or Mach-O decompiler.
Obfuscation, encryption, unsupported encodings and evidence beyond a bound can be
missed. A reached bound or failed binary-plist decode is reported as partial
coverage.

AIsec passes local rule/configuration paths and disables supported update checks;
Trivy is invoked in explicit offline mode. These application flags are not a
kernel-level egress control. Restrict scanner network access at the OS or CI
layer when no outbound connection attempts are permitted.

The Trivy cache freshness decision relies on Trivy's database metadata and the
upstream OCI distribution path. It does not independently attest each database
record. Keep setup egress restricted and use an authenticated registry mirror
when stronger organizational provenance controls are required.

Policy SHA-256 records exact policy bytes for reproducibility; it is not a
signature and does not prove who authored or approved the file. Protect the
operator policy with normal repository/CI access controls and use a new
baseline for an intentional policy change.

The local-gate state directory is a filesystem trust boundary, not a signed or
tamper-proof store. Another process running as the same OS user can still alter
it. Protect that account and directory, review the first captured baseline, and
use a new empty private state directory when deliberately accepting a changed
policy or baseline. Do not place the state below the target or synchronize it
into an untrusted project checkout.

Rule-pack SHA-256 has the same limitation: it binds report and baseline evidence
to exact bytes but does not establish authorship, review quality or provenance.
Protect rule packs with operator-side access control and review every declared
severity and evidence level.

No result constitutes certification. `no_blockers_found` means only that the
completed checks found no configured blocker. Read the coverage table and
limitations before deployment.
