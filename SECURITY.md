# Security policy and scanner threat model

AIsec processes repositories and archives that may be actively hostile. Treat a
scanner bug that causes command execution, arbitrary file access, credential
disclosure, sandbox escape, unsafe network access, or a false clean result as a
security issue.

## Reporting

Until a private advisory address is configured for the public repository, do
not publish an exploit. Open a GitHub Security Advisory after publication of the
repository, or contact the maintainer privately. Include the affected version,
platform, minimum reproducer, impact and whether untrusted project content is
required.

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
