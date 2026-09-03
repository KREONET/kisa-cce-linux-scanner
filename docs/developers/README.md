# Contributor guide

This page is the entry point for contributors to the KISA CCE Linux Scanner. It summarizes the development workflow and links to the documents that define behavior. Keep detailed subsystem rules in their existing authoritative documents instead of duplicating them here.

## Sources of truth

| Concern | Authoritative document |
|---|---|
| Repository structure, check contract, validation, and release gates | [Development](development.md) |
| Components, execution flow, resolvers, caches, and report pipeline | [Architecture](../design/architecture.md) |
| Trust boundaries, evidence handling, and residual risks | [Security model](../design/security-model.md) |
| Platform-specific KISA and native subsystem behavior | [KISA platform semantics](../reference/kisa-platform-semantics.md) |
| Supported product and version matrix | [Platform support](../reference/platform-support.md) |
| Scan epochs, dependency propagation, and benchmarking | [Performance](../design/performance.md) |
| Korean and English report catalogs | [Localization](../operators/localization.md) |
| Staged installation and Debian/RPM integration | [Packaging](../packaging/README.md) |
| Apple `container` distribution-matrix workflow | [macOS container testing](macos-container-testing.md) |
| Operator-visible CLI behavior | [Usage](../operators/usage.md) and `kisa-cce-scan(8)` |

When implementation and prose disagree, inspect the relevant code and tests, then update both in one change. Do not weaken a conservative result solely to make a fixture pass.

## Choose the change path

| Change | Start with | Update together |
|---|---|---|
| One KISA criterion | Owning `check_u_nn` function and its current fixture | Platform semantics when the decision boundary changes |
| Shared configuration behavior | `lib/resolvers.sh` and the relevant subsystem parser | Focused cache test, architecture, and every affected criterion fixture |
| Scan epoch or cache invalidation | `lib/scan_epoch.sh` and `docs/design/performance.md` | Dependency and parse-count regressions |
| CLI option or terminal output | `lib/kisa-cce-scan-main.sh` and `lib/core.sh` | Usage guide, security model, man page, and installed-layout test |
| Report text | Owning check and both PO catalogs | Korean and English report golden paths |
| Evidence bundle | `lib/evidence.sh` or `lib/kisa-cce-collect-main.sh` | Bundle schema documentation and positive and negative validation fixtures |
| Packaging | `Makefile` and `docs/packaging/README.md` | Staged install, upgrade, removal, and command smoke tests |

Begin with the narrowest focused test that can reproduce the behavior. Expand to shared consumers before changing a resolver or collection primitive.

## Repository setup and prerequisites

Use a Linux environment with:

- GNU Bash 4.3 or newer;
- GNU findutils and compatible core utilities, including the `find`, `stat`, `readlink`, and `sha256sum` behavior used by the scanner;
- standard `awk`, `grep`, `sed`, `sort`, `tr`, and related base-system utilities;
- `make` for validation and staged installation;
- ShellCheck for `make lint`;
- `mandoc` when changing a manual page;
- a container runtime for the distribution matrix.

The public launcher executes `/bin/bash`. The stock macOS Bash 3.2 runtime is not a valid target environment; use a Linux container or virtual machine for the required test suite.

The project has no generated source and no third-party production dependency. It uses Bash, base-system utilities, and a dependency-free PO parser instead of a separate language runtime or gettext installation. Do not add a production dependency without prior review. Native subsystem tools may be used through the existing trusted-command boundary, and unavailable optional tools must retain conservative result handling.

Start from a protected checkout and inspect its state before making changes:

```bash
git status --short --branch
git diff
```

Preserve unrelated changes. Do not reformat or move files outside the requested scope.

## Change workflow

1. Read the relevant source, tests, and authoritative documents.
2. Identify every in-scope consumer of the behavior being changed.
3. Add or update a fixture that demonstrates the old failure or the new contract.
4. Implement the smallest subsystem-specific change.
5. Run the focused test first, then the complete correctness and lint gates.
6. Review the final diff for result-state drift, evidence disclosure, path escapes, and unrelated edits.
7. Update operator documentation and the section 8 manual when CLI behavior changes.

Do not create a new KISA result for an implementation diagnostic. A selected catalog row must still produce exactly one `GOOD`, `VULNERABLE`, `MANUAL`, `NOT_APPLICABLE`, or `ERROR` result.

## Check ownership

| Criteria | Primary module | Scope |
|---|---|---|
| U-01 through U-33 | `lib/checks_account_file.sh` | Accounts, authentication, and filesystem controls |
| U-34 through U-63 | `lib/checks_service.sh` | Network services and service configuration |
| U-64 through U-67 | `lib/checks_system.sh` | Patch, time, logging, and system controls |

Shared precedence and reusable collection logic belongs in `lib/resolvers.sh`. Rooted filesystem, result, report, and trusted-command primitives belong in `lib/core.sh`. Scan-epoch and reverse-dependency state belongs in `lib/scan_epoch.sh`. Keep criterion policy in the owning check module.

## Rooted paths and recursive records

Treat an offline image as an untrusted filesystem boundary.

- Pass logical absolute paths through the rooted path helpers.
- Resolve symlinks within `SCAN_ROOT`; an unsafe escape or unresolved existing path is an error.
- Preserve logical target paths in evidence instead of host-side staging paths.
- Never write assessed configuration into `SCAN_ROOT`.
- Use NUL-delimited records for recursive path inventories. Newline and tab are valid pathname bytes and cannot delimit a general filesystem traversal.
- Use protected scratch files for large intermediate records, and reset run-scoped caches in tests after mutating a fixture.

See [Development: Filesystem access](development.md#filesystem-access), [Architecture: Shared filesystem collection](../design/architecture.md#shared-filesystem-collection), and [Security model: Offline-root confinement](../design/security-model.md#offline-root-confinement).

## Resolver semantics

Do not replace subsystem behavior with a generic `*.d` merge or last-match search. Preserve each format's native rules, including directory priority, equal-basename replacement, lexical order, masks, includes, recursion boundaries, first- or last-obtained directives, aliases, templates, drop-ins, and manager-normalized state.

Resolvers must distinguish an established value, an established absence, ambiguity, and collection or interpretation failure. A scan epoch memoizes all of those states. A cache must not convert unreadable, incomplete, or malformed evidence into `GOOD`, and runtime state must be recollected for a new invocation.

See [Architecture: Configuration resolution](../design/architecture.md#configuration-resolution) and [Performance](../design/performance.md).

## Debug events

Use the central `debug_emit` API for `--debug` instrumentation. Do not use `set -x`, `BASH_XTRACEFD`, direct writes to standard error, retained scratch data, or a separate debug file.

Debug records use this stable envelope:

```text
DEBUG: schema=1 event=NAME key=value
```

Event and key names match `[a-z][a-z0-9_]*`. Field keys are unique within an event, while `schema`, `event`, and `truncated` are reserved for the envelope. Values are percent-encoded outside `[A-Za-z0-9._~:/@+-]`; rendered fields and complete events are bounded. Emit normalized states such as subsystem, cache action, status, count, or exit status.

Never pass configuration lines, command arguments, raw stdout or stderr, result summaries, evidence, policy content, review IDs, evidence-bundle digests, credentials, tokens, hashes, keys, or report paths to a debug event. Debug output remains sensitive assessment data despite these exclusions. Every new event requires tests for its schema, state transition, stderr-only dmesg framing, disabled behavior, and noninterference with reports and exit status.

See [Development: Debug event contract](development.md#debug-event-contract) and [Security model: Debug diagnostics](../design/security-model.md#debug-diagnostics).

## Localization

Terminal help, progress, warnings, errors, and debug events are always English. Markdown report labels, criterion titles, and summaries are Korean by default; an English `LANG` selects the English report catalog.

When adding or changing a localized report string:

1. Add the exact Korean source string as `msgid` in both PO files.
2. Map it to itself in the Korean catalog and provide the English translation in the English catalog.
3. Keep the dependency-free restricted PO format: one single-line `msgid`, one single-line `msgstr`, and no plural, context, fuzzy, or multiline entry.
4. Do not translate machine-readable evidence keys, enum values, paths, commands, or configuration keys.

See [Localization](../operators/localization.md) for the catalog layout and validation rules.

## Validation

Run the complete correctness and lint gates:

```bash
make check
make lint
```

When manual pages change, lint each changed page:

```bash
mandoc -T lint man/kisa-cce-scan.8
mandoc -T lint man/kisa-cce-collect.8
```

Run containerized userspace validation on the maintained matrix:

| Family | Releases |
|---|---|
| Debian | 12, 13 |
| Ubuntu | 22.04 LTS, 24.04 LTS, 26.04 LTS |
| Rocky Linux | 8.10, 9.8, 10.2 |

Use the distribution-provided Bash and ShellCheck versions. Run permission-sensitive fixture tests as a non-root user, then perform the installed-layout and scanner smoke checks with the privileges they require. For each matrix target, verify `make check`, `make lint`, staged installation, one 67-result scan, Markdown and JSONL cardinality, report modes, and JSONL parsing when `jq` is available.

Containerized userspace coverage does not replace acceptance testing on a booted host with systemd, active listeners, real mount topology, and native validators. Record only tests that were actually run.

The project-specific Apple `container` procedure is documented in [macOS container testing](macos-container-testing.md).

## Preparing a review

Provide enough evidence for another maintainer to reproduce the result:

- state the observed problem and root cause;
- list affected criteria, platforms, resolver namespaces, and result-state changes;
- describe the trust, confidentiality, and offline-root implications;
- list every changed file and the reason it changed;
- record exact validation commands and their pass or failure results;
- distinguish generated fixtures, containerized userspace tests, and booted-host acceptance;
- identify remaining limitations without presenting untested behavior as complete.

Review the complete working-tree diff before staging. Keep unrelated changes unstaged, and use one logical Conventional Commit when a maintainer requests a commit. Every AI-assisted change still requires human review and validation.

## Licensing and authorship

Contributions must be available under the repository's dual-license expression:

```text
LGPL-3.0-or-later OR BSD-3-Clause
```

Contributors must have the right to submit their work under both alternatives. KISA guide material and other third-party content retain their original terms. See [Development: Contribution licensing](development.md#contribution-licensing), [`LICENSE`](../../LICENSE), [`NOTICE`](../../NOTICE), and [`LICENSES/`](../../LICENSES/).

Do not add a `Signed-off-by` trailer on behalf of another person. A contributor who must certify a sign-off adds it personally under the applicable project policy. Preserve any required AI-assistance disclosure separately; it does not substitute for human review or sign-off.

## Review checklist

- [ ] The change is limited to the requested subsystem and preserves unrelated work.
- [ ] Every affected criterion and shared consumer was identified.
- [ ] Result-state and error precedence remain conservative.
- [ ] Rooted paths remain confined, and recursive records remain NUL-delimited.
- [ ] Resolver precedence, provenance, and cache invalidation are covered by fixtures.
- [ ] Reports contain minimal evidence and no raw secrets.
- [ ] Debug events contain only approved metadata and do not alter reports or exit status.
- [ ] Korean and English catalogs are complete when report text changes.
- [ ] CLI changes are reflected in usage documentation and the man page.
- [ ] `make check`, `make lint`, relevant `mandoc` checks, and the required container matrix were run and recorded accurately.
- [ ] Staged `/usr/lib/kisa-cce-linux-scanner` and supported `/usr/libexec` layouts still work.
- [ ] The contribution is valid under both project license alternatives.
- [ ] No `Signed-off-by` trailer was added on behalf of another person.
