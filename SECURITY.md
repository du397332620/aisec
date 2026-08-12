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
- AIsec's own shipped rules and explicit user configuration are trusted inputs.
- PATH executables are trusted by the invoking user; managed executables have a
  pinned SHA-256 checked before every run.
- A configured SHA-256 proves that a managed file has not changed after
  installation; users must still authenticate the original release and digest.
- Only the engine versions listed in the verified Beta compatibility matrix are
  executed. Unknown or unparsable versions fail coverage closed.
- Third-party scanner output is untrusted and normalized/redacted before use.
- Target-controlled Gitleaks, Opengrep and Trivy configuration/ignore files are
  not trusted by the adapters and cannot silently suppress acceptance findings.
  This includes Gitleaks allow comments, Opengrep `nosemgrep`/ignore files and
  Trivy general, ignore and secret-scanner configuration.
- Trivy scans use an AIsec-owned offline cache. Missing, invalid or stale
  database metadata fails coverage; database download happens only through the
  explicit `engines prepare trivy` setup command.
- A test or staging URL is accessed only through an explicit authorization
  manifest plus `--confirm`.
- Passive web requests pin a validated DNS answer to the socket and redirects
  must retain the exact authorized origin. Local verification is deliberately
  allowed to reach private addresses; staging/test verification is not.

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

AIsec passes local rule/configuration paths and disables supported update checks;
Trivy is invoked in explicit offline mode. These application flags are not a
kernel-level egress control. Restrict scanner network access at the OS or CI
layer when no outbound connection attempts are permitted.

The Trivy cache freshness decision relies on Trivy's database metadata and the
upstream OCI distribution path. It does not independently attest each database
record. Keep setup egress restricted and use an authenticated registry mirror
when stronger organizational provenance controls are required.

No result constitutes certification. `no_blockers_found` means only that the
completed checks found no configured blocker. Read the coverage table and
limitations before deployment.
