# AIsec

AIsec is a local-first security acceptance CLI and MCP server for applications
built with coding agents. It treats generated code as untrusted input, maps the
project's attack surface, correlates related evidence into attack paths, and
produces constrained repair contracts for an existing coding agent. An
optional operator-owned release policy can strengthen the acceptance gate
without trusting configuration from the repository being scanned. Explicit
operator-owned declarative rule packs can add bounded local checks without
loading or executing plugin code.

It does **not** try to guess whether code was written by a human or an AI. It
does **not** certify an application as secure.

The complete shipped-rule inventory is available as generated human-readable
documentation in [RULES.md](RULES.md) and as the versioned machine-readable
[rule catalog](rules/catalog.json), validated by
[its public schema](schemas/rule-catalog.schema.json). Each entry declares CWE,
default evidence, bounded applicability/version policy, known false-positive
modes and review guidance.

## Current beta scope

Depth is intentionally concentrated in:

- JavaScript/TypeScript, Next.js, React and Node.js
- Python/FastAPI route, authentication, object-authorization and focused data-flow analysis
- Express/NestJS route, authentication-boundary, object-authorization and privileged-operation analysis
- Supabase and Firebase authorization configuration
- React Native and common Android/iOS source configuration
- APK/IPA recovery of embedded secrets, cleartext URLs and selected metadata from prioritized text and bounded binary resources
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
key. Existing dangerous-flow findings receive exact FastAPI route metadata when
the source can be proven in the handler or through a uniquely resolved bounded
project-local call chain. Strict route provenance also follows parenthesized
multiline imports, directly invoked lexical helpers, captured route values and
the supported thread wrappers; comments, returned-only closures, fixed
arguments, conditional or duplicate definitions, dynamic object dispatch and
ambiguous imports are not route-attributed. CORS, raw exception
responses, committed JWT signing keys, long-lived
access tokens and production Compose publication of unguarded services are
covered by focused configuration rules. Route-local broad-exception signals
retain every statically resolved route alias and classify the handler, raw
exception serialization form and response sink. These are lexical, bounded
checks—not a complete Python semantic analysis or proof of exploitability.

Express coverage resolves common ESM and CommonJS relative imports, nested and
chained `Router` mounts, route registrars that receive an app/router parameter,
and selected handlers or middleware exposed by locally constructed CommonJS or
ES-class instances. Bound methods such as
`controller.read.bind(controller)` retain their instance context, including
statically visible constructor arguments. Express also expands top-level local
`const` route arrays, plus immutable arrays directly imported from one relative
ESM module through a named or default import. The producer must directly export
a file-level `const` array identifier; namespace imports, re-exports and a
second module hop are rejected. A table may pass through at most two direct
`filter`/`map` calls. Transform callbacks must be inline, synchronous and
single-parameter: filters accept only statically boolean literals, member
selections, negation, strict equality and boolean conjunction/disjunction;
maps must directly return an object literal whose unique fields select static
values without calls, spreads or mutation. If any entry cannot be evaluated,
the whole transformed table is rejected. Supported tables may be consumed by
an inline `forEach` callback or by a synchronous `for...of` with a `const`
identifier/object binding and only direct route registration statements. Path,
guard, handler and evidence resolution retain the producer file context. Both
forms are capped at 128 entries per array and 512 expanded routes per scan;
registration sites outside those forms are counted in the coverage reason
rather than assigned invented paths.
NestJS coverage recognizes common `CanActivate` guard implementations, composed
decorator factories such as `applyDecorators(UseGuards(...))`, same-controller
authorization helpers, static global prefixes and URI versions. Local
`@Inject(TOKEN)` dependencies are resolved only when the controller belongs to
exactly one visible local `@Module`. Resolution prefers that module's providers,
then exported tokens from direct imports and explicit local module re-exports;
private, conflicting and unreachable providers are not combined into a global
token map. Provider records may use `useClass`, `useExisting`, or a bounded
`useFactory` with one statically visible local `new Class(...)` result. Official
named/renamed or namespace `forwardRef(() => Token)` injections and module
imports are unwrapped only for a synchronous, zero-argument callback with one
direct local/relative result. A local dynamic-module static method is included
only when actually called from visible module metadata and when it directly
returns one static object for the same module class; its visible `imports`,
`providers`, `exports` and literal `global: true` metadata extend the base
module metadata. Actual `@Global()` exports and static or accepted dynamic
`APP_GUARD` records apply only when their host module is present in every
accepted application graph containing the controller. A static root is selected
only from `main`/`server`/`bootstrap`/`index` when a named, renamed or namespace
`NestFactory` imported directly from `@nestjs/core` makes a direct `.create`
call at source level or inside a directly invoked top-level function. Its first
argument must directly name a local `@Module` class or a named/default class
from one relative ESM module that exports it without a re-export hop. Multiple
selected roots retain graph-intersection semantics. Each accepted create call
also remains a distinct application instance. An imperative
`app.useGlobalGuards(...)` contributes only when that create result is directly
`await`ed into a `const` identifier and the non-optional property call is a
later direct expression statement in the same source or bootstrap-function
block. Guard semantics are intersected across every accepted application
instance whose bounded graph contains the controller, including repeated calls
for the same root; unsupported calls on a proven app binding are counted in
coverage. The same application binding and direct-statement boundary scopes
`app.setGlobalPrefix(...)` and URI `app.enableVersioning(...)` calls. Each
application keeps independent prefix, exclusion and version settings; a
controller reachable from multiple applications receives the union of those
routes without cross-combining their settings. Prefix exclusions support
literal paths and official named/renamed or namespace `RequestMethod` members,
including method-specific handling for `@All`. Version options accept only the
official `VersioningType.URI`, literal versions or official `VERSION_NEUTRAL`,
and a literal or `false` version prefix. A literal global prefix remains usable
when its exclusion array mixes static and dynamic entries: proven exclusions
are retained, unknown entries are not guessed, and the site is reported as
partial coverage. Other unsupported options or call shapes invalidate only
that application's routing configuration, emit its declared route as a
conservative fallback and are counted in coverage. A distinct setup application
is omitted only after a later direct, zero-argument `await app.close()` in the
same container; indirect close forms remain conservatively active. Separately,
declarative module paths can be composed from a direct official
named, renamed or namespace `RouterModule.register(...)` entry in real local
`@Module.imports`. Its route array must be inline, a file-level immutable local
binding or one directly imported relative-ESM binding; route records contain
only a literal `path`, an optional local/one-hop relative module class and
optional static `children`. Nested records concatenate parent paths, while a
direct module class in `children` inherits its parent's path. Registrations are
scoped to each bounded application graph, so a shared module can have different
paths in different roots without cross-combining global prefix/version settings.
Global-prefix exclusions are matched after module-path composition. Route trees
are capped at eight child edges and 256 entries; conflicting or otherwise
unsupported attributable registrations use the declared controller route for
the affected graph and are counted exactly in coverage. If no bootstrap root
is visible—or if even one official create site is dynamic, nested, conditional,
shadowed or otherwise unresolved—the analyzer falls back to all bounded inferred
roots and records unresolved sites in coverage; imperative guards and
application routing configuration are not trusted during that fallback. Module
traversal is capped at eight edges and 256 unique entries per resolution.
Reachable injected dependencies outside these forms are counted in the coverage
reason.

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
visible completed 403/forbidden branch. The result may pass through one simple
local `const` whose only reference is the complete denial condition, and
enforcement may also cross one local wrapper whose entire body directly returns
the policy call. `let`/`var`, reassignment, a second read or alias, callback
capture, coercion/comparison or a logical/ternary condition do not count.
Neither do merely calling or logging a result, merely evaluating or caching an
inline owner comparison, returning owner inequality or a compound/constant
expression, setting status 403 without ending the response, continuing
execution after sending 403, sending a dynamic object as the 403 payload,
relying on an access-shaped name, or adding another wrapper. Query fragments
with interpolation, computed parameter maps and unknown wrappers fail closed.
The analyzers also distinguish
ownership or tenant constraints from role or permission checks on privileged
operations. Package aliases or package-provided/mixin base classes,
package/namespace/re-exported or mutable/generated route tables,
asynchronous/conditional/nested or
mutation-bearing `for...of`, arbitrary or over-two-step collection transforms,
transform callbacks with runtime calls, spreads or mutation, dynamic module
metadata with async/branching/runtime configuration, non-direct or non-Nest
`forwardRef` callbacks, arbitrary `useValue` objects,
providers/factories without a visible local class result, ambiguous controller
module ownership, unsupported or over-limit module graphs, bootstrap wrappers,
non-entry create calls and runtime root selection, application aliases,
unawaited/mutable create results and optional, computed, chained, conditional or
nested imperative global-guard registrations, `RouterModule` wrappers,
`registerAsync`, dynamic/re-exported/second-hop route trees and runtime module
paths, Sequelize scopes,
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
result. For `rule-pack check`, `0` means the selector preview is complete and
`2` means it is partial; that command never returns a vulnerability decision.

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
aisec scan [path] [--profile predeploy|native] [--policy trusted-policy.yml] [--rule-pack trusted-rules.yml] [--native-only] [--artifact app.apk]
aisec rescan [path] --baseline <scan-id|report.json> [--policy trusted-policy.yml] [--rule-pack trusted-rules.yml]
aisec local-gate [path] --policy <trusted-policy.yml> --state-dir <private-directory>
aisec rule-pack check [path] --rule-pack <trusted-rules.yml> [--format terminal|json]
aisec report <scan-id|report.json> --format terminal|json|html|sarif|ci|github|markdown
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

Scan options include `--profile predeploy|native`, explicit `--policy`,
repeatable explicit `--rule-pack`,
`--confirm-policy-suppressions`, repeatable `--artifact`, `--git-history`,
`--native-only`, `--no-persist`, `--max-files`,
`--max-file-bytes`, `--max-total-bytes` and `--timeout-ms`. Run `aisec --help`
for defaults and hard-bound behavior.

Reports are stored outside the scanned project. By default this is
`~/Library/Application Support/aisec` on macOS and
`$XDG_DATA_HOME/aisec` (or `~/.local/share/aisec`) on Linux. Override it with
`AISEC_DATA_DIR` in tests or automation.

`rescan` also compares the evidence-only interface audit by stable
`framework + exact METHOD/path + category` identity. It reports route gaps as
newly observed, remaining, resolved, or not rechecked. “Newly observed” means
absent from the bounded baseline evidence; it does not prove when the
vulnerability was introduced. A route gap is resolved only when its responsible
detector coverage completed, while partial coverage and association bounds fail
closed as not rechecked. Suppression changes release disposition but does not
make detected route evidence appear resolved.

An operator-owned `SecurityPolicy 1.1.0` can additionally enable an additive
`routeSecurityBaseline` gate. It blocks newly observed open route/category
issues at the configured severity without making unchanged lower-severity debt
block through this gate. Approved suppressions remain visible but are excluded
unless the existing `requireNoSuppressions` gate is enabled. A configured gate
requires baseline evidence; its first scan can be retained as that baseline but
returns `incomplete` until `rescan` supplies a comparison unless another
confirmed finding already makes the decision `block`. With
`requireComplete: true`, not-rechecked or bounded comparison evidence also
fails closed as `incomplete`.

### Local source-use gate

`local-gate` is the safe convenience entry point for a fixed local baseline.
It requires an explicit `SecurityPolicy 1.1.0` with
`routeSecurityBaseline` enabled and a dedicated private state directory outside
the scanned target. It always runs the full `predeploy` profile and does not
persist a second copy in the normal report store.

From a source checkout:

```bash
npm run build

# Keep both paths outside ../target. Copy the example into operator-owned
# storage, review it, then uncomment its routeSecurityBaseline section.
mkdir -p ../trusted/keyan-gate
chmod 700 ../trusted/keyan-gate
cp examples/security-policy.example.yml ../trusted/security-policy.yml
# Edit ../trusted/security-policy.yml now; do not use the demonstration values
# without review.

node dist/src/cli.js local-gate ../target \
  --policy ../trusted/security-policy.yml \
  --state-dir ../trusted/keyan-gate
```

The first run writes owner-only `baseline.json` and `latest.json`. It is a
bootstrap run and therefore exits non-zero: normally `2` for the missing
comparison, or `1` when another confirmed policy blocker has higher priority.
After reviewing that baseline, run the same command after each code change.
Later runs automatically rescan the pinned baseline and return `0` for an
accepted/review result, `1` for `block`, `2` for `incomplete`, or `64` for
invalid usage/state.

`local-gate` intentionally does not accept `--output`: its canonical latest
report already lives at `<state-dir>/latest.json`, while stdout can be captured
by the caller. Render a separate HTML/SARIF/CI artifact with `aisec report`
afterward so an output path cannot overwrite the pinned state or trusted input.

The baseline is intentionally never advanced automatically—even after a clean
or repeated blocked run. Otherwise, rerunning a rejected change could turn its
new risk into accepted baseline debt. For a deliberate policy change or a
human-approved new baseline, choose a new empty private `--state-dir`, run the
bootstrap once, review it, then use that directory for later checks. Existing
state is bound to the canonical target and exact policy/rule-pack digests.
Symlinked, target-owned, shared-permission or unrelated non-empty state
directories are rejected.

### Trusted release policy

AIsec never discovers a release policy from the scanned repository. The
operator must pass a policy explicitly, and its resolved file path must be
outside the target root:

```bash
mkdir -p ../trusted
cp examples/security-policy.example.yml ../trusted/security-policy.yml
# Review the rule lists and replace the demonstration expiry first.
aisec scan ../target --policy ../trusted/security-policy.yml
```

The public [`SecurityPolicy 1.1.0` schema](schemas/security-policy.schema.json)
is strict and continues to read legacy `1.0.0` policies only when the new field
is absent. Version 1 fixes the profile to `predeploy`, requires Gitleaks,
Opengrep and Trivy, and has no fields for disabling engines, rules or coverage.
`gate.minimumSeverity` may retain `high` or strengthen it to `medium`, `low` or
`info`; `includeInferred: true` is an additional strengthening. IDs in
`rules.required` must exist in the shipped [rule catalog](rules/catalog.json),
and `rules.block` is a subset that elevates matching findings to blockers.
Narrow fingerprint suppressions require both a reason and expiry. The policy
itself also expires. A policy containing suppressions is rejected unless the
operator separately passes `--confirm-policy-suppressions` after reviewing the
exact file; the report records this approval.

Policy version 1.1 adds the optional baseline gate:

```yaml
schemaVersion: 1.1.0
# ...policy identity, engines, global gate and rules...
routeSecurityBaseline:
  minimumSeverity: high
  includeInferred: false
  requireComplete: true
```

This gate is additive: it cannot weaken the existing global finding gate. The
first scan under this policy records an incomplete baseline-gate evaluation
(or remains `block` when another confirmed gate already blocks). Retain its
report or scan ID, then evaluate subsequent changes with the exact
same policy digest:

```bash
aisec rescan ../target --baseline <scan-id-or-report.json> \
  --policy ../trusted/security-policy.yml
```

A policy cannot be combined with `--profile native` or `--native-only`. Missing,
partial or failed predeploy coverage remains `incomplete`. A target-owned
`.aisec.yml` is ignored and this disposition is recorded in JSON, terminal,
HTML, SARIF, CI JSON, GitHub annotation and Markdown output; it cannot suppress
a finding. Reports record the applied policy ID, expiry, effective gates and
SHA-256 digest but not its local path.
Rescanning an operator-policy baseline requires the same explicit policy
digest; a deliberate policy change starts a new baseline.

### Declarative operator rule packs

AIsec can add reviewed project-specific checks without executable plugins. A
rule pack is never discovered from the target; each pack must be passed
explicitly and resolve outside the target root:

```bash
mkdir -p ../trusted
cp examples/rule-pack.example.yml ../trusted/rule-pack.yml
# Review every literal, severity and evidence level before use.
aisec rule-pack check ../target \
  --rule-pack ../trusted/rule-pack.yml
aisec scan ../target --profile native \
  --rule-pack ../trusted/rule-pack.yml
```

The public [`RulePack 1.1.0` schema](schemas/rule-pack.schema.json) is strict and
continues to accept unchanged `1.0.0` packs. Rule IDs must use
`custom.<pack-id>.<rule>`. Rules match printable ASCII literals on one source
line using `containsAny`, optional `containsAll` and `excludes`; file selection
uses lowercase extensions and optional normalized path prefixes/suffixes. It
accepts no regex, JavaScript, Python, WASM, command, template, import or callback
field. Evidence may be `static_confirmed` or `inferred`, never `verified`.

RulePack 1.1 adds optional `match.emitWhen`. Omitting it, or setting it to
`present`, preserves 1.0 behavior and emits for each matching line. Setting
`emitWhen: absent` emits one `inferred`, path-only finding for each selected
existing file only after its complete bounded scan finds no matching line. If
an absent rule selects no files, or a work/output limit is reached before
absence can be established, AIsec emits no invented absence finding and marks
that pack's required coverage `partial`. This is a narrow source invariant—not
proof that middleware or another control is absent at runtime.

`rule-pack check` validates the explicit packs and previews their selectors
without evaluating `containsAny`, `containsAll` or `excludes`, so it never emits
a vulnerability finding. Its strict
[`RulePackPreview 1.0.0` contract](schemas/rule-pack-preview.schema.json) lists
only pack ID/digest, rule ID/title/mode and bounded selected relative paths; it
does not contain the local pack path or literal definitions. An absent rule
selecting no existing file makes the preview `partial`, while a present rule
with no selection remains a valid empty preview. Inventory, selector or path
output truncation also returns exit `2`.

At most 8 packs, 256 total rules and 256 KiB per pack are accepted. Per-rule
selectors/literals plus shared selector, byte, literal-work and line-evaluation
budgets are bounded; all packs share the normal 2,000-signal output ceiling. A
preview lists at most 100 selected paths per rule and 2,000 total, and shares
the 1,000,000 rule-file selector-work limit with scanning. A reached scan work
or output bound makes the affected required coverage `partial`. Incomplete
project inventory—such as an oversized, unreadable, binary or symlinked
candidate—also makes every active pack's required scan coverage `partial`,
because full selector reach cannot be established. Expected excluded
directories alone do not weaken coverage. Valid findings from inspected files
are retained. Reports record only pack ID, rule count and SHA-256—not the local
pack path or its literals—and expose this record in JSON, terminal, HTML,
SARIF, CI JSON and Markdown. A baseline rescan requires the same set of pack
IDs, counts and digests; a deliberate pack edit starts a new baseline.

Rule packs can add findings and required coverage but cannot disable shipped
rules or engines, change inventory limits, suppress findings or relax a release
policy. `SecurityPolicy.rules` remains limited to shipped catalog IDs in this
contract; custom findings still pass through the effective severity/evidence
gate.

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
global disable switch. Opengrep's trusted temporary ignore mirrors AIsec's
deterministic inventory exclusions such as `.venv`, `node_modules` and build
caches, so vendored/generated dependencies do not create unstable application
findings; it never imports target `.gitignore` or `.semgrepignore` content.

Trivy schema-v2 package records also feed a presentation-only dependency and
infrastructure review. Terminal and HTML output distinguish dependency
vulnerabilities, IaC misconfigurations and redacted secret signals; dependency
entries retain Trivy's recorded direct/indirect relationship, ecosystem and
fix availability, then group package/version context without merging canonical
signals or findings. `indirect` is displayed as `transitive`; missing or
ambiguous relationship data stays `unknown` instead of being guessed. Package
presence does not establish reachability or exploitability. Filesystem mode can
review Dockerfile/IaC configuration, but it does not download or evaluate the
vulnerability set of a referenced base image.

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
`inspect_project`, `run_predeploy_scan`, `preview_rule_packs`, `get_report`,
`create_fix_contract`, and `verify_fix`. Web verification is intentionally not
available over MCP, so an agent cannot autonomously send probes to a target.
`run_predeploy_scan` and `verify_fix` accept an optional explicit `policy` path
and a separate `confirmPolicySuppressions` boolean; the same outside-target and
baseline-digest checks used by the CLI apply. `preview_rule_packs` accepts one
to eight explicit outside-target packs and returns the same strict bounded
selector preview as `rule-pack check`, without evaluating literals.
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
      - name: Run the source-only gate and render CI outputs
        working-directory: aisec
        shell: bash
        run: |
          set +e
          npm exec --no -- aisec scan ../target --profile native --no-persist --format json --output ../aisec-report.json
          scan_status=$?
          set -e
          npm exec --no -- aisec report ../aisec-report.json --format github
          npm exec --no -- aisec report ../aisec-report.json --format markdown --output "$GITHUB_STEP_SUMMARY"
          npm exec --no -- aisec report ../aisec-report.json --format sarif --output ../aisec.sarif
          exit "$scan_status"
```

Exit `1` or `2` fails the job. Replace the placeholder with a reviewed commit;
do not use a branch name as a security-tool pin. A full `predeploy` CI gate must
also provision the exact three compatible engine versions, authenticate their
binaries and prepare the Trivy database before scanning.

`--format ci` emits the strict [`CiReport 1.4.0`](schemas/ci-report.schema.json)
JSON contract: decision and recommended exit code, open counts, required
coverage gaps, effective policy, declarative rule-pack digests, baseline counts
and bounded annotations. Baseline rescans add exact route/category comparison
counts plus a bounded entry window with explicit omissions. It also records FastAPI dangerous-dataflow route
attribution totals and stable fail-closed reason counts without changing the
canonical findings or release decision.
`--format github` converts that same contract to workflow commands, while
`--format markdown` creates a GitHub step summary. Output is deterministic and
bounded to one decision, 20 required-coverage gaps and 50 prioritized findings;
omitted counts remain explicit. Target-controlled text is reduced to one line,
workflow metacharacters are escaped, and only normalized relative paths can
become file annotations. These renderers read no environment variables, make
no network requests and upload nothing, so the example retains only
`contents: read`. The final `exit` deliberately preserves the original scan
decision after the non-gating `report` commands finish.

HTML and SARIF now carry the same decision reasons, required-coverage gaps,
effective policy and baseline comparison. Terminal and HTML additionally derive
a bounded Trivy dependency/infrastructure priority view while leaving canonical
evidence and decisions unchanged. SARIF records stable finding fingerprints and
accepted suppressions for compatible consumers.

## Beta capability matrix

| Capability | Mode / engine | Beta behavior and boundary |
| --- | --- | --- |
| Public rule catalog | JSON + generated Markdown | 58 shipped deterministic rules: 55 native and 3 bundled Opengrep; strict schema and drift checks tie detector IDs, corpus coverage, CWE/evidence metadata, Opengrep YAML/verified version and `RULES.md` to one catalog; `*` means syntax/config/artifact based without a dependency-semver gate, not complete framework support |
| Trusted release policy | Explicit operator-owned YAML | Strict public schema; policy must resolve outside the scanned target, retain the full predeploy engine boundary and may only keep or strengthen the default gate; shipped rule IDs are catalog-validated, narrow suppressions expire and require a second explicit confirmation, reports retain digest/gate/approval evidence, and policy baselines require the same digest; target-owned `.aisec.yml` is ignored |
| Local fixed-baseline gate | `local-gate` CLI | First run writes an owner-only baseline in a dedicated target-external state directory; later runs automatically rescan that immutable baseline and atomically refresh only the latest report. Target-owned/symlinked/shared/unrecognized state, target drift and policy/rule-pack digest drift fail closed; deliberate baseline changes use a new empty private directory |
| Declarative rule packs | Explicit operator-owned YAML/JSON | Strict `RulePack 1.1.0` with unchanged 1.0 compatibility; outside-target, digest-bound, bounded line-local present or required-literal-absent checks only; `rule-pack check`, Node API and MCP expose a strict bounded selector-only preview without literals/findings; absence findings are inferred and path-only, while an empty selection or reached bound makes coverage partial; no code, regex, target discovery, suppression or gate relaxation; ScanReport/CI/reporters retain pack ID, rule count and digest, and baselines require the same pack set |
| Project inventory and stack map | Native | Local read only; supported text candidates and manifests, no dependency installation or project execution |
| Secrets in selected source files | Native | Deterministic provider patterns plus fully redacted concrete sensitive-environment interpolation fallbacks; working tree only, not Git history |
| JS/TS request/model data flow | Native TypeScript parser | Narrow source-to-sink traces for SQL/command/SSRF/XSS and model-output sinks; not whole-program or general multi-language analysis |
| Next.js/app, Supabase/Firebase and mobile source checks | Native | Focused Beta rules; BaaS analysis recognizes bounded PostgreSQL RLS and Firebase Firestore/Storage authorization expressions, while unsupported helpers or syntax make coverage `partial`; some findings are explicitly `inferred` and require review |
| FastAPI authentication and object authorization | Native Python analyzer | Resolves common router composition and guards; whitelist bypasses are static-confirmed, standalone unguarded services and missing object ownership/role checks are inferred |
| Express/NestJS authentication and authorization | Native TypeScript analyzer | Resolves relative modules, Express apps/routers, selected constructed handlers, bounded local or one-hop directly imported immutable ESM route tables used by `forEach` and direct synchronous `for...of`, including at most two direct inline statically evaluable `filter`/`map` transforms, and NestJS controllers/guards/providers through local module imports, exports, re-exports and application-global visibility; accepts direct official `forwardRef` tokens/modules, visible synchronous static dynamic-module metadata, fully resolved direct official `NestFactory.create` roots from conventional runtime entry files, same-container direct `useGlobalGuards`, `setGlobalPrefix` and URI `enableVersioning` calls on their awaited `const` application instances, plus direct official static `RouterModule.register` trees from real module imports; composes independently scoped global/version/module/controller paths for shared controllers and otherwise retains bounded inferred-root routes without trusting imperative configuration, with both module and RouterModule traversal capped at eight edges and 256 entries; follows up to four local call edges and bounded local repository inheritance; traces authenticated identity into object-literal, directly consumed or one-`const`/single-use local filter helpers and selected TypeORM, Knex, Sequelize and Mongoose owner predicates while rejecting owner-only OR branches; recognizes name-independent single-equality boolean policies only when denial is directly enforced, consumed through one single-condition `const`, or forwarded through one direct-return wrapper; reports missing ownership and privileged role/permission checks as inferred findings; dynamic queries/helpers, arbitrary collection transforms, unsupported operators/scopes or bootstrap graphs, unresolved providers/registration/bootstrap/global-guard/application-routing/RouterModule sites, package or mixin bases, complex wrappers and external policy engines still require review |
| Python API data flow | Native Python analyzer | Bounded interprocedural traces for request-derived URL, file-path and raw-SQL sinks, plus caller-selected model origins receiving server credentials; exact FastAPI route origins propagate through direct handlers, unique local/relative imports and directly invoked lexical closures; comments, returned closures, ambiguous/dynamic dispatch and unproven request origins remain unattributed with stable machine-readable reasons in JSON/CI plus bounded terminal/Markdown/HTML summaries; recognizes selected validation boundaries and reports partial coverage |
| FastAPI/JWT/Compose configuration | Native Python analyzer | Focused CORS, global and broad route-local exception disclosure, JWT signing-key/lifetime and published unguarded service checks; deployment correlations can be inferred and require review |
| Working tree and optional Git-history secrets | Gitleaks `8.30.1` | Required in pre-deploy mode; history is scanned only with `--git-history` |
| General SAST | Opengrep `1.26.0` | Required in pre-deploy mode; uses AIsec-owned rules, suppression controls and deterministic inventory exclusions while rejecting target ignore files |
| Dependency, IaC and secondary secret checks | Trivy `0.73.0` | Required in pre-deploy mode; requires an explicitly prepared, fresh schema-v2 database and scans offline; canonical metadata retains recorded direct/indirect/unknown dependency relationship, ecosystem/class and fix availability, while terminal/HTML derive bounded package/version priority groups without claiming reachability or base-image package coverage |
| APK/IPA static resources | Native archive adapter | Optional input; required for pre-deploy mobile artifact coverage when a mobile project/artifact is expected; prioritizes app manifests/plists, DEX/resource tables, JS bundles and the iOS main executable, semantically decodes bounded binary plists, recovers bounded ASCII/UTF-16 strings in memory, and performs no installation, on-disk member extraction or runtime instrumentation |
| Passive test/staging Web checks | `verify-web` | Explicit authorization plus `--confirm`; bounded GET/header/cookie checks only, no auth/IDOR/injection testing |
| Static-to-active BOLA planning | `draft-bola` | Converts open static BOLA/IDOR signals into a non-executable review worksheet; mutation routes are excluded and object IDs/markers remain placeholders |
| Two-account BOLA verification | `verify-bola` | Exact non-production target, two low-privilege test accounts and pre-created labeled objects; fixed read-only cases only, no ID enumeration or mutation |
| Agent integration | stdio MCP | Local read-oriented inspection, bounded rule-pack selector previews, scans, stored reports, fix contracts and rescans; no Web verification or automatic code changes |
| Reports and release decisions | CLI / JSON / HTML / SARIF / CI JSON / GitHub / Markdown | Strict, bounded CI output plus coverage-aware `block`, `incomplete`, `review`, or `no_blockers_found`; terminal/HTML can group opted-in repeated evidence, derive exact-route security cards and summarize Trivy dependency/IaC/secret evidence by recorded relationship and fix context while retaining every canonical finding; terminal/HTML/CI Markdown keep unattributed FastAPI dataflow visible with bounded reason summaries, and rescans compare exact route/category gaps as newly observed, remaining, resolved or not rechecked without treating suppression as a fix; deployment exposure stays explicitly project-level unless service-to-route ownership is proven; workflow annotations use safe relative paths and escaped project-controlled text; never certification |

`--profile native` is the deterministic source-only first pass: external and
artifact domains are non-required. The default `predeploy` profile is the
acceptance path: Gitleaks, Opengrep and Trivy are required, and APK/IPA coverage
is required when a mobile project is detected. `--native-only` explicitly
disables the three external engines without changing that artifact policy.
Reports record these default-mode relaxations. An operator policy permits
neither relaxation and therefore rejects both `--profile native` and
`--native-only`.
Missing, partial or failed required coverage prevents a clean result. APK/IPA
analysis examines selected static resources only; mobile runtime behavior
remains out of scope.

Supabase policy analysis is static and migration-order agnostic. It recognizes
bounded top-level table, RLS and `CREATE POLICY` statements, client roles,
permissive versus restrictive policies, authentication-only grants and
authorization based on `auth.jwt()` user metadata. PostgreSQL combines
applicable permissive policies with `OR` and restrictive policies with `AND`;
the scanner therefore does not treat a restrictive authentication-only policy
as an independent grant. Supabase documents that `raw_user_meta_data` can be
updated by the authenticated user and should not be used as authorization data;
server-controlled `raw_app_meta_data` is the safer claim boundary.

Firebase analysis recognizes Firestore and Storage `allow` statements and
direct, single-return local helpers, including bounded parameter substitution.
It reports authentication-only grants even when another matching rule is
narrower because overlapping Firebase `allow` expressions grant with `OR`.
Storage write/create/update grants are also checked for a visible upper bound on
`request.resource.size`. Unknown services, malformed expressions, unsupported
helper bodies or resource limits produce `partial` coverage instead of a clean
result. See the official [Supabase RLS guide](https://supabase.com/docs/guides/database/postgres/row-level-security),
[PostgreSQL row-security policy documentation](https://www.postgresql.org/docs/17/ddl-rowsecurity.html),
[Firebase rule behavior](https://firebase.google.com/docs/rules/rules-behavior),
[Firestore conditions](https://firebase.google.com/docs/firestore/security/rules-conditions),
and [Storage validation](https://firebase.google.com/docs/storage/security/rules-conditions)
for the platform semantics. AIsec does not determine which rules or migrations
are actually deployed.

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

Canonical findings, fingerprints and signal IDs remain independent of report
layout so baselines, suppressions, JSON and SARIF stay stable. When a detector
marks repeated evidence as presentation-groupable, terminal output summarizes
it by file and shows representative route/handler entries; HTML uses expandable
groups containing every occurrence, finding ID, route, location and classified
pattern. Terminal and HTML also derive evidence-only route security cards for
recognized FastAPI, Express and NestJS authentication, object-authorization,
privileged-authorization and exception-disclosure gaps, plus FastAPI routes
with proven SQL-injection, SSRF, untrusted-file-path or server-credential-
forwarding flows. Cards join exact route aliases without changing canonical
results. Baseline rescans compare each observed card category by framework and
exact route; source-line or finding-fingerprint drift therefore does not create
a false route regression. Published-service evidence remains
project-level deployment context because static co-occurrence does not prove
that a specific route is externally reachable. A category absent from a card is
not a passed control. Single occurrences and all rules keep the normal finding
views.

Without an operator policy, only evidence-backed high/critical findings block.
Inferred findings require review and cannot be promoted merely by an LLM. A
trusted policy can deterministically strengthen the severity/evidence gate or
elevate catalogued rule IDs.

Suppress a proven false positive only in the explicit operator-owned policy;
reason and expiry are required:

```yaml
schemaVersion: 1.0.0
# ...required policy identity, engines, gate and rules...
suppressions:
  - fingerprint: <stable-fingerprint-from-report>
    reason: Synthetic credential in a non-shipping parser fixture
    expires: 2026-12-31
```

The complete shape is in
[`examples/security-policy.example.yml`](examples/security-policy.example.yml).
The target repository cannot opt into, edit or discover this policy on AIsec's
behalf. A matched suppression is visible in the finding and report summary;
`requireNoSuppressions: true` turns any applied suppression into a blocker.
Run a policy that intentionally contains reviewed exceptions with both
`--policy <file>` and `--confirm-policy-suppressions`; the confirmation flag is
invalid without a policy and is never inferred from target content.

`fix-contract` supplies evidence, constraints, required regression tests and a
baseline rescan command. A finding closes only when it is rechecked and listed
as resolved, with no new high/critical finding.

## Versioned data contracts

AIsec publishes JSON Schema Draft 2020-12 contracts for scan reports, CI
reports, fix contracts, the rule catalog, declarative rule packs and their selector previews, trusted security policies, passive-web
authorization, BOLA draft plans and BOLA authorization manifests in
[`schemas/`](schemas/). `SecurityPolicy 1.1.0` adds the optional additive
route-security baseline gate and strictly preserves legacy `1.0.0` policies.
`RulePack 1.1.0` adds bounded required-literal absence
assertions and continues to accept legacy `1.0.0` packs only when the new field
is absent. `RulePackPreview 1.0.0` is the strict bounded output of the CLI,
Node API and MCP selector-preview operation. Other unchanged contracts remain at `1.0.0`.
`CiReport 1.1.0` added rule-pack records, `CiReport 1.2.0` added the required
FastAPI route-attribution summary, `CiReport 1.3.0` added a required bounded
route-security comparison whenever baseline counts are present, and `CiReport
1.4.0` records the effective route-security baseline gate. `ScanReport
1.1.0` added the required machine-readable policy record, `ScanReport 1.2.0`
added the required rule-pack record array, `ScanReport 1.3.0` added complete
bounded route-security comparison evidence whenever a baseline is present, and
`ScanReport 1.4.0` records the effective route-security baseline gate. The
validators continue to accept legacy `1.0.0`-`1.3.0` inputs only when fields
introduced by later versions are absent. Contracts are validated at runtime when a report is generated,
serialized, saved or loaded, when a rule-pack preview or fix contract is generated, and before
authorization semantics are evaluated. Unknown fields, unsupported schema
versions and malformed nested values fail closed instead of flowing into CLI
or MCP output.

The package also exports `validateScanReport`, `validateCiReport`,
`buildCiReport`, `renderGithubAnnotations`, `renderMarkdownSummary`,
`validateFixContract`,
`validateRuleCatalog`, `validateRulePack`, `validateRulePackPreview`, `validateSecurityPolicy`, `loadRuleCatalog`,
`renderRuleCatalog`, `parseRulePack`, `loadTrustedRulePack`,
`loadTrustedRulePacks`, `previewRulePacks`, `renderRulePackPreview`, `parseSecurityPolicy`, `loadTrustedPolicy`,
`validateAuthorizationManifestSchema`, `validateBolaDraftPlan` and
`validateBolaAuthorizationManifestSchema` for integrations that consume these
objects directly. The JSON catalog is also exported at
`@aisec/cli/rules/catalog.json`. Fields declared optional may be omitted by
their declared producers; new fields or other contract changes require a new
schema version. `validateSecurityPolicy` checks schema and catalog
relationships; `parseSecurityPolicy` and `loadTrustedPolicy` additionally
enforce policy/suppression expiry, and loading enforces the outside-target path
boundary.

## Scanner safety model

- Files are read without following symlinks; dependency, build and VCS output
  directories are excluded.
- AIsec never runs `npm install`, Gradle, CocoaPods, build scripts, repository
  binaries, or scanner configuration supplied by the target repository.
- Release policy is accepted only through an explicit path whose real file is
  outside the target. A target `.aisec.yml` is ignored and recorded as such;
  symlinks resolving back into the target are rejected.
- Declarative rule packs follow the same explicit outside-target path boundary.
  They are parsed as data and never dynamically imported or executed; regex,
  command and script fields are rejected. Required-literal absence rules only
  inspect selected existing files, emit inferred path-only evidence, and make
  coverage partial instead of claiming a vulnerability when no file is
  selected or a safety bound interrupts evaluation. Reports retain their digest
  but not their local path or literal definitions.
- Rule-pack preview uses that same loader, inventory and selector predicate. It
  does not evaluate matching literals or create findings; it exposes only
  bounded selected relative paths through a validated contract. Unsafe or
  excessive paths, incomplete inventory and selector exhaustion make the
  preview partial rather than silently claiming complete selector reach.
- External adapters override target-controlled scanner configuration and ignore
  files with AIsec-owned temporary inputs; inline scanner suppressions are also
  disabled where the engine exposes that control. If Trivy inline ignore
  directives are present, its coverage is conservatively reported as `partial`.
  Opengrep's temporary ignore contains only AIsec's fixed inventory exclusions;
  target `.gitignore` and `.semgrepignore` files are not copied or consulted.
- Credential-shaped ambient variables are removed from every scanner child
  process. Engine-specific variables are also removed so ambient
  Trivy/Gitleaks/Opengrep policy cannot weaken acceptance.
- Child processes use argument arrays with no shell, bounded time and bounded
  combined output. Managed engine binaries are hash-pinned.
- Default inventory limits are 20,000 selected text files, 2 MiB per file and
  64 MiB total inspected candidate bytes; hard ceilings prevent CLI or API
  callers from disabling all resource guards. Every detector or adapter emits
  at most 2,000 signals. Reaching a safety limit makes the affected required
  coverage `partial`, so it cannot produce a clean acceptance decision.
- Secret values are redacted from native and normalized third-party findings.
  Concrete environment-interpolation fallback findings retain only the variable
  name and a fully redacted placeholder; the fallback value is excluded from
  snippets, metadata and fingerprints.
- The Trivy priority view consumes only canonical normalized signals. Package,
  version, ecosystem, target and advisory text is single-line, escaped and
  bounded at presentation time; raw secret matches are never included. Grouping
  never removes a signal/finding or changes fingerprints, baseline state,
  suppression, severity or the release decision.
- CI, GitHub and Markdown renderers validate a strict bounded intermediate
  contract. Project-controlled text cannot create extra workflow commands,
  unsafe absolute/traversal paths cannot become annotations, and Markdown links
  are defanged. Rendering does not read ambient CI credentials or upload data.
- AIsec supplies only local scanner rules/configuration, disables engine version
  and database updates, and runs Trivy in explicit offline mode. For a hard
  no-egress guarantee around third-party binaries, enforce it with an OS sandbox
  or CI network policy. AIsec's own network paths are explicit engine setup and
  `verify-web --confirm` or the more restrictive `verify-bola --confirm`.
- APK/IPA inspection validates every listed path, prioritizes at most 25 supported
  members, and streams each selected member through `unzip` without extracting it
  onto disk. Binary recovery is capped at 8 MiB per member and 16 MiB aggregate
  input, with at most 8 MiB of recovered text; reaching any bound makes coverage
  `partial` rather than clean. A binary plist that cannot be decoded within its
  semantic limits also makes coverage `partial`.

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
npm run rules:check

# Requires the exact engine versions above and a prepared Trivy database
npm run test:engines
```

The public synthetic corpus contains 32 isolated cases: 16 positive/near-miss
pairs covering all 55 deterministic native Beta rules across secrets, data
flow, application configuration, FastAPI authentication and object
authorization, Express/NestJS authentication and object authorization, Python
API data flow/configuration, BaaS, mobile source and mobile artifacts. Together
with the 3 bundled Opengrep rules, these form the 58 entries in the public rule
catalog. The benchmark reports each category separately and verifies expected
evidence and CWE metadata as well as false positives and false negatives. Its
perfect fixture score is **not** a real-world efficacy claim; the corpus is
deliberately small and synthetic. Drift tests fail when a native rule lacks both
fixture variants, detector metadata differs from the catalog, bundled Opengrep
YAML/version metadata changes independently, or `RULES.md` is stale. The
separate real-engine suite verifies Gitleaks, Opengrep and Trivy against their
own positive/near-miss fixtures and hostile target configuration.

The resource benchmark creates synthetic 500-file, 5,000-file and deliberately
truncated projects at runtime. It records elapsed time and peak RSS in isolated
child processes and enforces broad cross-platform regression ceilings. These
measurements are guards against major performance or memory regressions, not a
promise for every repository or machine.

### Fixed-commit BaaS authorization calibration

Maintainers can repeat rule-specific scans of the Firebase Web Quickstart and
the Supabase Next.js user-management example. The manifest pins both upstream
repositories to exact commits and expected BaaS findings:

```bash
# Explicitly downloads sparse worktrees at the two allowlisted commits
npm run calibrate:baas -- --confirm-download

# Download and scan only the Firebase target
npm run calibrate:baas -- --confirm-download --target firebase-quickstart-js

# Reuse a clean local repository at the exact manifest commit
npm run calibrate:baas -- \
  --target supabase-nextjs-user-management \
  --local supabase-nextjs-user-management=/absolute/path/to/supabase
```

The runner defaults to no network access. Downloads use HTTPS, sparse checkout
and a temporary directory; local repositories must have the exact recorded
`HEAD`, a clean worktree and no target-owned AIsec policy. Only AIsec's native
scanner runs: dependencies are not installed, project code is not executed,
rules and migrations are not deployed, backend requests are not sent, and raw
reports are not retained.

At the pinned revisions, the Firebase sample deliberately contains public and
authenticated-only quickstart rules, while its Storage starter rule is public
and has no upload-size ceiling. The Supabase sample deliberately makes profiles
publicly readable. These expected matches test rule behavior and syntax against
real source; they are not claims that the examples are accidentally vulnerable
or that either repository is insecure overall. The runner and fixed-target
manifest are excluded from the npm package.

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

### Fixed-asset mobile artifact calibration

Maintainers can repeat rule-specific static checks against immutable open-source
APK/IPA assets from PIVAA, OWASP MASTG Hacking Playground and Fossify Calculator.
The assets are GPL-3.0 and remain on their upstream projects; AIsec records exact
versions, byte sizes, SHA-256 values and license links but does not redistribute
the binaries. The runner and manifest are excluded from the npm package.

```bash
# Explicitly downloads all pinned assets, verifies them, scans, then deletes them
npm run calibrate:mobile-artifacts -- --confirm-download

# Download and check one asset
npm run calibrate:mobile-artifacts -- \
  --confirm-download \
  --target mastg-jwt-ios-positive

# Reuse a local file only when its size and SHA-256 match the manifest
npm run calibrate:mobile-artifacts -- \
  --target pivaa-android-positive \
  --local pivaa-android-positive=/absolute/path/to/pivaa.apk
```

Without `--confirm-download`, any selected target without `--local` fails before
network access. Downloads accept only fixed GitHub release assets or raw files at
a 40-character commit. Release assets use GitHub CLI when it is available and a
bounded HTTPS stream otherwise; raw assets use the bounded stream, whose redirects
are restricted to approved GitHub asset hosts. Every path is accepted only after
exact byte-size and SHA-256 verification, lives in a temporary directory and is
deleted after scanning. The harness does not install, launch, sign, build or
decompile an app; send requests to an app endpoint; extract archive members onto
disk; or persist raw reports.

The fixed expectations are exact artifact-rule counts: a PIVAA APK and the MASTG
JWT IPA are positives for recoverable cleartext endpoints, while an MASTG Android
APK and Fossify Calculator are near misses for the currently supported artifact
rules. “Near miss” is rule-specific and is not a statement that either app is
secure. This iteration has one real iOS positive; the iOS near-miss remains in the
synthetic public corpus, so the calibration makes no real cross-app iOS specificity
claim.

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
