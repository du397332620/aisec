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
- Python/FastAPI route, authentication, object-authorization and focused data-flow analysis
- Express/NestJS route, authentication-boundary, object-authorization and privileged-operation analysis
- Supabase and Firebase authorization configuration
- React Native and common Android/iOS source configuration
- APK/IPA recovery of embedded secrets, cleartext URLs and selected metadata
- LLM output flowing into command, code or database execution
- GitHub Actions expression injection and common application misconfiguration

FastAPI coverage currently resolves common `FastAPI`/`APIRouter` declarations,
`include_router` prefixes, authentication middleware, exact/prefix whitelists,
router dependencies and route-level `Depends` or explicit identity guards. It
detects sensitive routes that a global whitelist makes public and separately
flags standalone services with no visible authentication boundary. It also
identifies authenticated object operations without a visible owner/tenant/role
constraint; request-derived URL, file-path and dynamic-SQL flows; and the
specific case where a caller-selected model base URL can receive a server API
key. CORS, raw exception responses, committed JWT signing keys, long-lived
access tokens and production Compose publication of unguarded services are
covered by focused configuration rules. These are lexical, bounded checks—not
a complete Python semantic analysis or proof of exploitability.

Express coverage resolves common ESM and CommonJS relative imports, nested and
chained `Router` mounts, route registrars that receive an app/router parameter,
and selected handlers or middleware exposed by locally constructed CommonJS or
ES-class instances. Bound methods such as
`controller.read.bind(controller)` retain their instance context, including
statically visible constructor arguments. Express also expands top-level local
`const` route arrays used by an inline `forEach` callback, capped at 128
entries per array and 512 expanded routes per scan; registration sites outside
that form are counted in the coverage reason rather than assigned invented
paths.
NestJS coverage recognizes common `CanActivate` guard implementations, composed
decorator factories such as `applyDecorators(UseGuards(...))`, same-controller
authorization helpers, static global prefixes and URI versions. Local
`@Inject(TOKEN)` dependencies can be mapped through `@Module` providers that
use `useClass`, `useExisting`, or a bounded `useFactory` with one statically
visible local `new Class(...)` result. Reachable injected dependencies outside
that form are counted in the coverage reason.

Both analyzers follow bounded local
controller/handler-to-service-to-repository calls for up to four edges and can
resolve repository methods through at most four statically visible local
`extends` edges. A common ORM owner predicate reached through these calls is
accepted only when its value can be traced from an authenticated subject such
as `request.user`, rather than from a route parameter that merely has an
owner-like name. This includes common object-literal predicates, literal
TypeORM named-parameter `where` / `andWhere` conditions, literal Knex
owner-column/value conditions, and the bounded Mongoose
`.where("ownerField").equals(identity)` form. Sequelize `findByPk` is recognized
as a single-object operation. A locally resolved function, arrow function or
class method may also return an owner filter when its body is exactly one direct
object-literal return. The result may be consumed directly, or pass through one
simple local `const` binding with exactly one use, as `where`, as the first
argument of a supported lookup, or as the final spread in such a filter.
`let`/`var`, reassignment, property mutation, another alias, multiple reads,
callback capture, unknown-call escape, returned-object spreads, conditional or
mutable returns, computed aliases, later spread/property overrides, response
objects and non-filter options do not count. An owner condition found only
inside MongoDB
`$or` / `$nor`, Sequelize `[Op.or]`, or a query widened by `.or()` / `orWhere*`
does not count as mandatory ownership; an owner field outside a nested
object-literal OR group still does. A local boolean policy such as
`canRead(actor, object)` is recognized from one direct owner/actor equality
return, independently of its name, and must have its result enforced by a
visible completed 403/forbidden branch. Enforcement may cross one local wrapper
whose entire body directly returns the policy call. Merely calling or logging a
result, merely evaluating an inline owner comparison, returning owner
inequality or a compound/constant expression, setting status 403 without ending
the response, continuing execution after sending 403, sending a dynamic object
as the 403 payload, relying on an access-shaped name, or adding another wrapper
does not count as authorization. Query fragments with interpolation, computed
parameter maps and unknown wrappers fail closed. The analyzers also distinguish
ownership or tenant constraints from role or permission checks on privileged
operations. Package aliases or package-provided/mixin base classes, imported or
mutable/generated route tables, `for...of`, chained collection transforms,
dynamic module metadata, `forwardRef`, arbitrary `useValue` objects,
providers/factories without a visible local class result, Sequelize scopes,
MongoDB aggregation pipelines, deeper ORM/control-flow wrappers and external
authorization engines remain partial static coverage and require review.

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

`0.1.0` is not published to npm. This project is currently distributed for
self-use from its source checkout; `npm install -g @aisec/cli` is not a
supported installation path.

```bash
git clone https://github.com/du397332620/aisec.git
cd aisec
npm ci --ignore-scripts --registry=https://registry.npmjs.org
npm run build
npm exec --no -- aisec doctor

# Fast, deterministic first-party checks only
npm exec --no -- aisec scan /path/to/project --profile native

# Deployment scan with all three verified external engines prepared
npm exec --no -- aisec scan /path/to/project \
  --artifact /path/to/app.apk \
  --format html --output aisec-report.html
```

`npm exec --no --` selects the locally built `aisec` binary and forbids npm
from downloading a missing package. The target path may be outside the AIsec
checkout. A source update uses `git pull`, then repeats `npm ci --ignore-scripts`
and `npm run build`. The remaining examples use `aisec` as shorthand; from a
source checkout, prefix those commands with `npm exec --no --`.

Exit codes are stable: `0` means `no_blockers_found` or `review`, `1` means
`block`, `2` means `incomplete`, and `64` means invalid usage or execution
failure. A missing required scanner therefore cannot silently become a clean
result.

### First-run check

The repository includes synthetic fixtures with no real credentials. These
commands verify both sides of the decision contract:

```bash
# Expected exit 0 and decision no_blockers_found
npm exec --no -- aisec scan test/fixtures/safe \
  --profile native --no-persist --format terminal

# Expected exit 1 and decision block
npm exec --no -- aisec scan test/fixtures/vulnerable \
  --profile native --no-persist --format terminal
```

The default `predeploy` profile requires all three verified engines, a ready
Trivy database and, when a mobile project is detected, an APK/IPA. Missing or
incompatible prerequisites produce exit `2` / `incomplete`; that is the
intended fail-closed result, not an installation failure. Run `aisec doctor`
before treating a pre-deploy result as complete.

## Commands

```text
aisec inspect [path]
aisec scan [path] [--profile predeploy|native] [--native-only] [--artifact app.apk]
aisec rescan [path] --baseline <scan-id|report.json>
aisec report <scan-id|report.json> --format terminal|json|html|sarif
aisec fix-contract --scan <scan-id> --finding <id> --format json
aisec draft-bola --scan <scan-id|report.json> --output bola-draft.json
aisec verify-web --authorization authorization.yml --confirm
aisec verify-bola --authorization bola-authorization.yml --confirm
aisec doctor
aisec engines status
aisec engines prepare trivy [--timeout-ms 600000]
aisec engines install <name> --from <binary> --sha256 <digest>
aisec mcp
```

Scan options include `--profile predeploy|native`, repeatable `--artifact`,
`--git-history`, `--native-only`, `--no-persist`, `--max-files`,
`--max-file-bytes`, `--max-total-bytes` and `--timeout-ms`. Run `aisec --help`
for defaults and hard-bound behavior.

Reports are stored outside the scanned project. By default this is
`~/Library/Application Support/aisec` on macOS and
`$XDG_DATA_HOME/aisec` (or `~/.local/share/aisec`) on Linux. Override it with
`AISEC_DATA_DIR` in tests or automation.

### External scanner engines

AIsec searches, in order, for an explicit `AISEC_<ENGINE>_PATH`, a locally
managed and hash-pinned binary, then the normal `PATH`. It never downloads a
scanner or vulnerability database during `scan`. The Beta fails closed on
unknown engine versions instead of assuming output compatibility:

| Engine | Verified Beta version | Coverage |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) | `8.30.1` | working tree and optional Git-history secrets |
| [Opengrep](https://github.com/opengrep/opengrep/releases/tag/v1.26.0) | `1.26.0` | general SAST with AIsec-owned rules |
| [Trivy](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0) | `0.73.0` | dependency vulnerabilities, IaC and secrets |

`doctor` reports the discovered command, exact version, compatibility and
managed-binary digest. A version upgrade must first extend the compatibility
fixtures and matrix.

Use the exact linked upstream release, authenticate its signature/checksum by
the upstream process, and avoid a floating `latest` download. AIsec accepts an
explicit executable path, a managed hash-pinned copy, or the exact compatible
version on `PATH`; it does not install these engines for you.

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

## CI integration

Until a tagged package exists, check out AIsec beside the target repository and
pin it to a reviewed 40-character commit. Keeping the directories separate
prevents the tool's own source from entering the target inventory:

```yaml
name: aisec-native
on: [pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - name: Check out the target
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          path: target
          persist-credentials: false
      - name: Check out reviewed AIsec source
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: du397332620/aisec
          ref: <40-character-reviewed-aisec-commit>
          path: aisec
          persist-credentials: false
      - name: Use Node.js 22
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020
        with:
          node-version: 22
          package-manager-cache: false
      - name: Install and build AIsec
        working-directory: aisec
        run: |
          npm ci --ignore-scripts --registry=https://registry.npmjs.org
          npm run build
      - name: Run the source-only gate
        working-directory: aisec
        run: npm exec --no -- aisec scan ../target --profile native --no-persist --format sarif --output ../aisec.sarif
```

Exit `1` or `2` fails the job. Replace the placeholder with a reviewed commit;
do not use a branch name as a security-tool pin. A full `predeploy` CI gate must
also provision the exact three compatible engine versions, authenticate their
binaries and prepare the Trivy database before scanning.

## Beta capability matrix

| Capability | Mode / engine | Beta behavior and boundary |
| --- | --- | --- |
| Project inventory and stack map | Native | Local read only; supported text candidates and manifests, no dependency installation or project execution |
| Secrets in selected source files | Native | Deterministic patterns; working tree only, not Git history |
| JS/TS request/model data flow | Native TypeScript parser | Narrow source-to-sink traces for SQL/command/SSRF/XSS and model-output sinks; not whole-program or general multi-language analysis |
| Next.js/app, Supabase/Firebase and mobile source checks | Native | Focused Beta rules; some findings are explicitly `inferred` and require review |
| FastAPI authentication and object authorization | Native Python analyzer | Resolves common router composition and guards; whitelist bypasses are static-confirmed, standalone unguarded services and missing object ownership/role checks are inferred |
| Express/NestJS authentication and authorization | Native TypeScript analyzer | Resolves relative modules, Express apps/routers, selected constructed handlers, bounded local-constant `forEach` route tables, NestJS controllers/guards/local token providers, up to four local call edges and bounded local repository inheritance; traces authenticated identity into object-literal, directly consumed or one-`const`/single-use local filter helpers and selected TypeORM, Knex, Sequelize and Mongoose owner predicates while rejecting owner-only OR branches; recognizes name-independent single-equality boolean policies only when denial is directly enforced or forwarded through one direct-return wrapper; reports missing ownership and privileged role/permission checks as inferred findings; dynamic queries/helpers, unsupported operators/scopes, unresolved providers/registration sites, package or mixin bases, complex wrappers and external policy engines still require review |
| Python API data flow | Native Python analyzer | Bounded interprocedural traces for request-derived URL, file-path and raw-SQL sinks, plus caller-selected model origins receiving server credentials; recognizes selected validation boundaries and reports partial coverage |
| FastAPI/JWT/Compose configuration | Native Python analyzer | Focused CORS, exception disclosure, JWT signing-key/lifetime and published unguarded service checks; deployment correlations can be inferred and require review |
| Working tree and optional Git-history secrets | Gitleaks `8.30.1` | Required in pre-deploy mode; history is scanned only with `--git-history` |
| General SAST | Opengrep `1.26.0` | Required in pre-deploy mode; uses AIsec-owned rules and suppression controls |
| Dependency, IaC and secondary secret checks | Trivy `0.73.0` | Required in pre-deploy mode; requires an explicitly prepared, fresh schema-v2 database and scans offline |
| APK/IPA static resources | Native archive adapter | Optional input; required for pre-deploy mobile artifact coverage when a mobile project/artifact is expected; no extraction or runtime instrumentation |
| Passive test/staging Web checks | `verify-web` | Explicit authorization plus `--confirm`; bounded GET/header/cookie checks only, no auth/IDOR/injection testing |
| Static-to-active BOLA planning | `draft-bola` | Converts open static BOLA/IDOR signals into a non-executable review worksheet; mutation routes are excluded and object IDs/markers remain placeholders |
| Two-account BOLA verification | `verify-bola` | Exact non-production target, two low-privilege test accounts and pre-created labeled objects; fixed read-only cases only, no ID enumeration or mutation |
| Agent integration | stdio MCP | Local read-oriented inspection, scans, stored reports, fix contracts and rescans; no Web verification or automatic code changes |
| Reports and release decisions | CLI / JSON / HTML / SARIF | Coverage-aware `block`, `incomplete`, `review`, or `no_blockers_found`; never certification |

`--profile native` is the deterministic source-only first pass: external and
artifact domains are non-required. The default `predeploy` profile is the
acceptance path: Gitleaks, Opengrep and Trivy are required, and APK/IPA coverage
is required when a mobile project is detected. `--native-only` explicitly
disables the three external engines without changing that artifact policy.
Missing, partial or failed required coverage prevents a clean result. APK/IPA
analysis examines selected static resources only; mobile runtime behavior
remains out of scope.

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

## Authorized two-account BOLA verification

Before preparing an authorization manifest, generate a review worksheet from a
stored scan:

```bash
aisec draft-bola \
  --scan <scan-id-or-report.json> \
  --output bola-draft.json
```

`draft-bola` performs no network requests. It considers only open findings
tagged `bola` or `idor`, preserves the originating rule and source location,
and classifies each route as `read_candidate`, `mutation_excluded`, or
`manual_review`. A read candidate contains placeholders for a pre-created owner
object ID and an object-evidence mode. When a supported response model/example
or explicit JavaScript/TypeScript response object exposes a distinct `user_id`,
`owner_id`, `tenant_id`, camel-case equivalent, or another recognized ownership field, the worksheet suggests
`ownerIdentity` and lists the candidate field; otherwise it retains the
primitive synthetic-marker template. The suggested JSON path remains a
non-executable review placeholder because static
source cannot reliably infer every response envelope. Fields also supplied as
request object IDs are excluded from owner-identity suggestions to reduce
echo-based false positives. The output is deliberately not accepted by
`verify-bola`: an operator must select at most nine cases, create dedicated test
fixtures, validate the suggestion, replace every placeholder, and copy the
reviewed cases into the strict authorization manifest.

`verify-bola` actively checks whether one low-privilege account can read an
object owned by a second low-privilege account. It is a separate, explicit
workflow from `scan` and `verify-web`: production is refused, `--confirm` is
required, and credentials are read only from named `AISEC_BOLA_` environment
variables. The tool sends at most two login requests, verifies that they resolve
to distinct identities, and sends a cross-account request only after the owner
baseline succeeds. It never guesses or enumerates object identifiers, creates
test data, follows redirects, or sends mutation methods.

Every case chooses one of two object-evidence modes:

- The default `testDataLabel` mode requires the owner response to contain an
  exact synthetic marker (for example
  `data.project_name: aisec-local-project-a`) equal to the case's
  `testDataLabel`.
- `match: ownerIdentity` is for read responses that expose a stable,
  server-derived object-owner or tenant field instead of a synthetic string.
  The owner baseline must return a field equal to the identity obtained from
  the owner's login response; the second account must then receive that same
  owner's identity. The identity value is never stored in the manifest or
  report. The evidence field must not be supplied in the request.

A high-severity verified BOLA signal is emitted only when the second account
receives the evidence established by the valid owner baseline. HTTP
401/403/404, or a different comparable value, is recorded as protected.
Ambiguous 200 error envelopes, missing owner fixtures, network failures and
non-comparable responses produce partial coverage and exit `2`; they are never
reported as a clean pass. Use `ownerIdentity` only for a field populated by the
server from the stored object—not a field that echoes request or caller data.

Start from [`examples/authorization.bola.local.yml`](examples/authorization.bola.local.yml).
The example shape matches APIs such as `POST /user/login` returning
`data.access_token` plus a stable `data.user_id`, and a read-only
`POST /project/detail` request. Replace the placeholder object ID with a
dedicated, pre-created fixture whose label starts with `dataPrefix`; do not use
real customer data.

For an endpoint such as `POST /session/get` whose response contains the stored
owner at `data.user_id`, its case can instead use:

```yaml
expected:
  match: ownerIdentity
  statusCodes: [200]
  jsonPath: data.user_id
```

```bash
export AISEC_BOLA_OWNER_USERNAME='aisec_fixture_owner'
export AISEC_BOLA_OWNER_PASSWORD='...'
export AISEC_BOLA_OTHER_USERNAME='aisec_fixture_other'
export AISEC_BOLA_OTHER_PASSWORD='...'

aisec verify-bola \
  --authorization examples/authorization.bola.local.yml \
  --confirm \
  --output bola-report.json
```

Exit `1` means verified cross-account access, exit `2` means at least one case
was inconclusive, exit `0` means every listed case was conclusively protected,
and exit `64` means the manifest, credentials or login setup was invalid. The
report contains account labels and case outcomes, but never usernames,
passwords, bearer tokens or response bodies.

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
contracts, passive-web authorization, BOLA draft plans and BOLA authorization
manifests in
[`schemas/`](schemas/). Version
`1.0.0` is validated at runtime when a report is generated, serialized, saved
or loaded, when a fix contract is generated, and before authorization semantics
are evaluated. Unknown fields, unsupported schema versions and malformed nested
values fail closed instead of flowing into CLI or MCP output.

The package also exports `validateScanReport`, `validateFixContract`,
`validateAuthorizationManifestSchema`, `validateBolaDraftPlan` and
`validateBolaAuthorizationManifestSchema` for integrations that consume these
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
  `verify-web --confirm` or the more restrictive `verify-bola --confirm`.
- APK/IPA inspection validates entry names and reads a bounded set of resources;
  it never extracts an archive onto disk.

See [SECURITY.md](SECURITY.md) for the threat model and reporting process.

## Reproducible tests and benchmark

From a source checkout:

```bash
npm test
npm run benchmark
npm run benchmark:resources
npm run test:docs
npm run test:package
npm run test:release

# Requires the exact engine versions above and a prepared Trivy database
npm run test:engines
```

The public synthetic corpus contains 32 isolated cases: 16 positive/near-miss
pairs covering all 49 deterministic native Beta rules across secrets, data
flow, application configuration, FastAPI authentication and object
authorization, Express/NestJS authentication and object authorization, Python API data flow/configuration, BaaS, mobile source and
mobile artifacts. The
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

### Fixed-commit Node API calibration

Maintainers can also repeat the reviewed static scans of Ghostfolio, RealWorld
Express and OWASP NodeGoat. This is intentionally excluded from the default
tests and the npm package because it needs network access and is a calibration
check, not a bundled benchmark:

```bash
# Explicitly downloads the three allowlisted repositories at fixed commits
npm run calibrate:node-api -- --confirm-download

# Download and scan only one target
npm run calibrate:node-api -- --confirm-download --target nodegoat

# Reuse an already available, clean worktree at the expected commit
npm run calibrate:node-api -- \
  --target nodegoat \
  --local nodegoat=/absolute/path/to/NodeGoat
```

Without `--confirm-download`, a target that has no `--local` source fails before
Git is invoked. Local worktrees must have the exact recorded `HEAD`, no tracked
or untracked changes, and no target-owned AIsec configuration. Downloads use
HTTPS into a temporary directory and are removed afterward. The harness only
runs AIsec's native static scanner: it does not install dependencies, build or
execute target code, start services, send target HTTP requests, or retain raw
reports. A passing result confirms the recorded route/finding expectations for
those commits; it is neither proof of exploitability nor proof that a project is
secure.

## Project status

This repository implements a usable beta foundation, not the entire long-term
roadmap. Not yet implemented: mobile runtime instrumentation, mutation or
identifier-enumeration security probes, arbitrary Python/Node framework
semantics, automatic code modification, hosted services, or a claim of broad
multi-language semantic analysis.

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

The local package metadata name remains `@aisec/cli`, but npm registry
publication is intentionally not planned. Use the source-checkout instructions
above.
