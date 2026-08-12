# AIsec

AIsec is a local-first security acceptance CLI and MCP server for applications
built with coding agents. It treats generated code as untrusted input, maps the
project's attack surface, correlates related evidence into attack paths, and
produces constrained repair contracts for an existing coding agent.

It does **not** try to guess whether code was written by a human or an AI. It
does **not** certify an application as secure.

## Current beta scope

Depth is intentionally concentrated in:

- JavaScript/TypeScript, Next.js, React and Node.js
- Supabase and Firebase authorization configuration
- React Native and common Android/iOS source configuration
- APK/IPA recovery of embedded secrets, cleartext URLs and selected metadata
- LLM output flowing into command, code or database execution
- GitHub Actions expression injection and common application misconfiguration

Other ecosystems receive baseline coverage when optional Opengrep, Gitleaks and
Trivy engines are installed. A report explicitly records `complete`, `partial`,
`not_run` or `failed` for every expected coverage domain.

## Quick start

Requires a maintained Node.js LTS release: Node.js 22 or 24. CI verifies
Ubuntu 24.04 x64 and macOS 15 arm64 with both Node versions. Other macOS/Linux
versions may work but are not part of the Beta acceptance matrix; Windows should
use WSL for the beta.

| Runner | CPU | Node.js |
| --- | --- | --- |
| Ubuntu 24.04 | x64 | 22, 24 |
| macOS 15 | arm64 | 22, 24 |

```bash
npm install
npm run build
node dist/src/cli.js doctor

# Fast, deterministic first-party checks only
node dist/src/cli.js scan /path/to/project --native-only

# Deployment scan with optional installed engines
node dist/src/cli.js scan /path/to/project \
  --artifact /path/to/app.apk \
  --format html --output aisec-report.html
```

Exit codes are stable: `0` means `no_blockers_found` or `review`, `1` means
`block`, `2` means `incomplete`, and `64` means invalid usage or execution
failure. A missing required scanner therefore cannot silently become a clean
result.

## Commands

```text
aisec inspect [path]
aisec scan [path] [--native-only] [--artifact app.apk]
aisec rescan [path] --baseline <scan-id|report.json>
aisec report <scan-id|report.json> --format terminal|json|html|sarif
aisec fix-contract --scan <scan-id> --finding <id> --format json
aisec verify-web --authorization authorization.yml --confirm
aisec doctor
aisec engines status
aisec engines prepare trivy [--timeout-ms 600000]
aisec engines install <name> --from <binary> --sha256 <digest>
aisec mcp
```

Reports are stored outside the scanned project. By default this is
`~/Library/Application Support/aisec` on macOS and
`$XDG_DATA_HOME/aisec` (or `~/.local/share/aisec`) on Linux. Override it with
`AISEC_DATA_DIR` in tests or automation.

### Optional scanner engines

AIsec searches, in order, for an explicit `AISEC_<ENGINE>_PATH`, a locally
managed and hash-pinned binary, then the normal `PATH`. It never downloads a
scanner or vulnerability database during `scan`. The Beta fails closed on
unknown engine versions instead of assuming output compatibility:

| Engine | Verified Beta version | Coverage |
| --- | --- | --- |
| Gitleaks | `8.30.1` | working tree and optional Git-history secrets |
| Opengrep | `1.26.0` | general SAST with AIsec-owned rules |
| Trivy | `0.73.0` | dependency vulnerabilities, IaC and secrets |

`doctor` reports the discovered command, exact version, compatibility and
managed-binary digest. A version upgrade must first extend the compatibility
fixtures and matrix.

To install an already downloaded release binary into AIsec's managed directory:

```bash
aisec engines install trivy \
  --from ./trivy \
  --sha256 <sha256-from-the-signed-release>
```

The digest is checked at installation and again before every execution.
Authenticate the release binary and checksum through the upstream project's
signed release process before installing it; a user-provided SHA-256 pins the
selected file but does not by itself prove provenance.

Trivy also requires a fresh schema-v2 vulnerability database in AIsec's data
directory. Preparing it is an explicit network/setup action:

```bash
aisec engines prepare trivy
aisec doctor
```

The normal Trivy scan uses that database in explicit offline mode. A missing, invalid or stale cache is
reported as failed coverage and yields `incomplete`, never a clean dependency
result. AIsec passes its own Trivy/Gitleaks/Opengrep configuration and ignore
files; target-controlled configuration, `gitleaks:allow` and `nosemgrep`
suppressions cannot weaken these adapters. A target `trivy:ignore` directive is
reported conservatively as partial coverage because Trivy has no equivalent
global disable switch.

Opengrep is LGPL-2.1, Gitleaks is MIT, and Trivy is Apache-2.0. MobSF is GPL-3.0
and remains a separately managed service; it is deliberately not bundled.

## MCP integration

Use the compiled CLI as a stdio MCP server:

```json
{
  "mcpServers": {
    "aisec": {
      "command": "node",
      "args": ["/absolute/path/to/aisec/dist/src/cli.js", "mcp"]
    }
  }
}
```

The MCP surface contains only local, read-oriented tools:
`inspect_project`, `run_predeploy_scan`, `get_report`,
`create_fix_contract`, and `verify_fix`. Web verification is intentionally not
available over MCP, so an agent cannot autonomously send probes to a target.
The stdio server supports the current stateless MCP `2026-07-28` discovery
envelope and legacy `initialize` negotiation through `2025-11-25`.

## Authorized passive web verification

`verify-web` currently sends only bounded, non-mutating GET requests and checks
baseline response headers and cookie flags. Redirects must retain the exact
authorized origin (scheme, hostname and port). Non-local DNS answers are
validated and pinned to the request socket to reduce SSRF and DNS-rebinding
risk; production, private, cloud-metadata and internal-only targets are refused.
Authentication, IDOR, injection and state changes are explicitly not claimed in
this beta.

Example manifest:

```yaml
schemaVersion: 1.0.0
targetBaseUrl: https://staging.example.test
environment: staging
ownedBy: Example team
allowedHosts:
  - staging.example.test
dataPrefix: aisec-example
maxRequests: 20
acknowledgment: I am authorized to test this target
```

Run only after reviewing the target:

```bash
aisec verify-web --authorization authorization.yml --confirm
```

## Findings, suppressions and fixes

Evidence is classified as:

- `verified`: observed against an explicitly authorized target;
- `static_confirmed`: a deterministic source/artifact fact or data-flow trace;
- `inferred`: context suggests risk but middleware or business semantics may
  change the conclusion.

Only evidence-backed high/critical findings block. Inferred findings require
review and cannot be promoted merely by an LLM.

Suppress a proven false positive in `.aisec.yml`; reason and expiry are required:

```yaml
version: 1
suppressions:
  - fingerprint: <stable-fingerprint-from-report>
    reason: Synthetic credential in a non-shipping parser fixture
    expires: 2026-12-31
```

`fix-contract` supplies evidence, constraints, required regression tests and a
baseline rescan command. A finding closes only when it is rechecked and listed
as resolved, with no new high/critical finding.

## Versioned data contracts

AIsec publishes JSON Schema Draft 2020-12 contracts for scan reports, fix
contracts and web authorization manifests in [`schemas/`](schemas/). Version
`1.0.0` is validated at runtime when a report is generated, serialized, saved
or loaded, when a fix contract is generated, and before authorization semantics
are evaluated. Unknown fields, unsupported schema versions and malformed nested
values fail closed instead of flowing into CLI or MCP output.

The package also exports `validateScanReport`, `validateFixContract` and
`validateAuthorizationManifestSchema` for integrations that consume these
objects directly. Fields declared optional may be omitted by `1.0.0` producers;
new fields or other contract changes require a new schema version.

## Scanner safety model

- Files are read without following symlinks; dependency, build and VCS output
  directories are excluded.
- AIsec never runs `npm install`, Gradle, CocoaPods, build scripts, repository
  binaries, or scanner configuration supplied by the target repository.
- External adapters override target-controlled scanner configuration and ignore
  files with AIsec-owned temporary inputs; inline scanner suppressions are also
  disabled where the engine exposes that control. If Trivy inline ignore
  directives are present, its coverage is conservatively reported as `partial`.
- Engine-specific environment variables are removed from scanner child
  processes so ambient Trivy/Gitleaks/Opengrep policy cannot weaken acceptance.
- Child processes use argument arrays with no shell, bounded time and bounded
  combined output. Managed engine binaries are hash-pinned.
- Default inventory limits are 20,000 selected text files, 2 MiB per file and
  64 MiB total inspected candidate bytes; hard ceilings prevent CLI or API
  callers from disabling all resource guards. Every detector or adapter emits
  at most 2,000 signals. Reaching a safety limit makes the affected required
  coverage `partial`, so it cannot produce a clean acceptance decision.
- Secret values are redacted from native and normalized third-party findings.
- AIsec supplies only local scanner rules/configuration, disables engine version
  and database updates, and runs Trivy in explicit offline mode. For a hard
  no-egress guarantee around third-party binaries, enforce it with an OS sandbox
  or CI network policy. AIsec's own network paths are explicit engine setup and
  `verify-web --confirm`.
- APK/IPA inspection validates entry names and reads a bounded set of resources;
  it never extracts an archive onto disk.

See [SECURITY.md](SECURITY.md) for the threat model and reporting process.

## Reproducible tests and benchmark

From a source checkout:

```bash
npm test
npm run benchmark
npm run benchmark:resources
npm run test:package
npm run test:release

# Requires the exact engine versions above and a prepared Trivy database
npm run test:engines
```

The public synthetic corpus contains 22 isolated cases: 11 positive/near-miss
pairs covering all 31 deterministic native Beta rules across secrets, data
flow, application configuration, BaaS, mobile source and mobile artifacts. The
benchmark reports each category separately and verifies the expected evidence
level as well as false positives and false negatives. Its perfect fixture score
is **not** a real-world efficacy claim; the corpus is deliberately small and
synthetic. A catalog-drift test fails when a native rule is added without both
fixture variants. The separate real-engine suite verifies Gitleaks, Opengrep and
Trivy against their own positive/near-miss fixtures and hostile target
configuration.

The resource benchmark creates synthetic 500-file, 5,000-file and deliberately
truncated projects at runtime. It records elapsed time and peak RSS in isolated
child processes and enforces broad cross-platform regression ceilings. These
measurements are guards against major performance or memory regressions, not a
promise for every repository or machine.

## Project status

This repository implements a usable beta foundation, not the entire long-term
roadmap. Not yet implemented: mobile runtime instrumentation, general-purpose
authenticated IDOR verification, automatic code modification, hosted services,
or a claim of broad multi-language semantic analysis.

The living [product requirements and progress tracker](docs/PRODUCT_PROGRESS.md)
records the verified implementation state, public-beta release gates, risks,
open decisions and next work in one place.

Apache-2.0. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The CI workflow runs the default tests, benchmark, dependency audit and package
smoke on all four supported OS/Node combinations. It uses commit-pinned GitHub
Actions, installs from the lockfile without lifecycle scripts, then installs the
generated tarball into an empty project and exercises the packaged CLI. The
optional real-engine suite remains a separate, explicitly prepared test.

## Release integrity

`npm run release:build` creates an npm tarball, a normalized CycloneDX 1.5 SBOM,
`release-manifest.json` and `SHA256SUMS` from a clean Git checkout. The manifest
records the exact source commit, package/runtime versions and every artifact
digest. `npm run release:verify -- release` rejects missing, unexpected or
modified files, checks the source commit, and checks the SBOM against the locked
production dependency graph. A downloaded bundle can be verified from its
matching source checkout even when `GITHUB_REF` is not present locally.

The release workflow uses a single Ubuntu 24.04 / Node.js 24.19.0 canonical builder.
It creates GitHub Sigstore attestations for build provenance and binds the SBOM
to the tarball. A manual workflow run only uploads a 14-day validation artifact;
only a tag exactly matching `v<package version>` creates a GitHub Release. Verify
a downloaded release with:

```bash
# Linux
sha256sum --check SHA256SUMS

# macOS
shasum -a 256 -c SHA256SUMS

gh attestation verify aisec-cli-0.1.0.tgz --repo du397332620/aisec

gh attestation verify aisec-cli-0.1.0.tgz \
  --repo du397332620/aisec \
  --predicate-type https://cyclonedx.org/bom
```

An npm publish is intentionally not part of this workflow until the long-term
package owner and trusted-publishing identity are decided.
