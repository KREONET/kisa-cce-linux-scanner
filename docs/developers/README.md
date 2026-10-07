# Contributor guide

Use this guide to prepare, test, and submit changes to the KISA CCE Linux Scanner. The documents below define subsystem behavior. Maintain detailed rules in those documents rather than duplicating them here.

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
| Ubuntu 26.04 rust-coreutils capability gate | [Development](development.md#ubuntu-2604-coreutils-compatibility) and `tests/uutils_compatibility.sh` |
| Operator-visible CLI behavior | [Usage](../operators/usage.md) and `kisa-cce-scan(8)` |
| Patch rules and transaction safety | [Autopatcher](https://github.com/KREONET/kisa-cce-linux-patcher/blob/main/docs/design/autopatcher.md) and `kisa-cce-patch(8)` |

When code and documentation disagree, inspect the relevant implementation and tests, then correct both in the same change. Do not weaken a conservative result solely to make a fixture pass.

## Choose the change path

| Change | Start with | Update together |
|---|---|---|
| One KISA criterion | Owning `check_u_nn` function and its current fixture | Platform semantics when the decision boundary changes |
| Shared configuration behavior | `lib/kisa-cce-resolvers/_resolvers.sh` and the relevant subsystem parser | Focused cache test, architecture, and every affected criterion fixture |
| Scan epoch or cache invalidation | `lib/kisa-cce-core/_scan-epoch.sh` and `docs/design/performance.md` | Dependency and parse-count regressions |
| CLI option or terminal output | `lib/kisa-cce-cli/_scan-main.sh` and `lib/kisa-cce-core/_core.sh` | Usage guide, security model, man page, and installed-layout test |
| Report text | Owning check and both PO catalogs | Korean and English report golden paths |
| Evidence bundle | `lib/kisa-cce-runtime/_evidence.sh` or `lib/kisa-cce-cli/_collect-main.sh` | Bundle schema documentation and positive and negative validation fixtures |
| Policy YAML compiler | `lib/kisa-cce-policy/_policy-yaml.sh` or `lib/kisa-cce-cli/_policy-compile-main.sh` | Policy format, parser rejection fixtures, installed-layout test, and compiler man page |
| Packaging | `Makefile` and `docs/packaging/README.md` | Staged install, upgrade, removal, and command smoke tests |

Start with the smallest test that reproduces the behavior. Test shared consumers before changing a resolver or collection primitive.

## Repository setup and prerequisites

Use a Linux environment with:

- GNU Bash 4.3 or newer;
- GNU findutils and compatible core utilities, including the `find`, `stat`, `readlink`, and `sha256sum` behavior used by the scanner;
- standard `awk`, `grep`, `sed`, `sort`, `tr`, and related base-system utilities;
- `make` for validation and staged installation;
- ShellCheck for `make lint`;
- `mandoc` when changing a manual page;
- Apple `container` or QEMU for the distribution matrix.

The public launcher executes `/bin/bash`. The required test suite needs a Linux container or virtual machine; the Bash 3.2 supplied with macOS is not a supported runtime.

The project has no generated source or third-party production dependency. It uses Bash, base-system utilities, and a PO parser that requires no separate runtime or gettext installation. Do not add a production dependency without prior review. Native subsystem tools may run through the existing trusted-command boundary. Results must remain conservative when optional tools are unavailable.

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

Each selected catalog row must produce exactly one `GOOD`, `VULNERABLE`, `MANUAL`, `NOT_APPLICABLE`, or `ERROR` result. Do not add KISA results for implementation diagnostics.

Every result declares a `technical`, `policy`, `runtime`, or `external`
resolution class. Only a technical `VULNERABLE` result with a registered,
versioned rule ID can be eligible for remediation. In scanner automation mode,
an unattested policy-class result may become `VULNERABLE`, but it must remain
ineligible for remediation.

## Check ownership

| Criteria | Primary module | Scope |
|---|---|---|
| U-01 through U-33 | `lib/kisa-cce-checks/_account-file.sh` | Accounts, authentication, and filesystem controls |
| U-34 through U-63 | `lib/kisa-cce-checks/_service.sh` | Network services and service configuration |
| U-64 through U-67 | `lib/kisa-cce-checks/_system.sh` | Patch, time, logging, and system controls |

Keep shared precedence and reusable collection logic in `lib/kisa-cce-resolvers/_resolvers.sh`; rooted filesystem, result, report, and trusted-command primitives in `lib/kisa-cce-core/_core.sh`; and scan-epoch and reverse-dependency state in `lib/kisa-cce-core/_scan-epoch.sh`. Criterion policy belongs in the check module that owns it.

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

Follow each subsystem's native configuration rules: directory priority, equal-basename replacement, lexical order, masks, includes, recursion boundaries, first- or last-obtained directives, aliases, templates, drop-ins, and manager-normalized state. A generic `*.d` merge or last-match search must not replace those rules.

Resolvers must distinguish a confirmed value, confirmed absence, ambiguity, and collection or interpretation failure. A scan epoch caches each of these states. Cached evidence that is unreadable, incomplete, or malformed must never produce `GOOD`. Collect runtime state again for each invocation.

See [Architecture: Configuration resolution](../design/architecture.md#configuration-resolution) and [Performance](../design/performance.md).

## Debug events

Use the central `debug_emit` API for `--debug` instrumentation. Do not use `set -x`, `BASH_XTRACEFD`, direct writes to standard error, retained scratch data, or a separate debug file.

Debug records use this stable envelope:

```text
DEBUG: schema=1 event=NAME key=value
```

Event and key names match `[a-z][a-z0-9_]*`. Each field key is unique within its event; `schema`, `event`, and `truncated` are reserved for the envelope. Bytes outside `[A-Za-z0-9._~:/@+-]` are percent-encoded, and size limits apply to rendered fields and complete events. Emit normalized states such as subsystem, cache action, status, count, or exit status.

Never pass configuration lines, command arguments, raw stdout or stderr, result summaries, evidence, policy content, review IDs, evidence-bundle digests, credentials, tokens, hashes, keys, or report paths to a debug event. Even with these exclusions, debug output is sensitive assessment data. For every new event, test its schema and state transition, verify dmesg framing on standard error only, and check that disabling debug suppresses the event. Also verify that debug mode leaves reports and exit status unchanged.

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
mandoc -T lint man/kisa-cce-policy-compile.8
```

Run containerized userspace validation on the matrix reviewed on 2026-09-08:

| Family | Releases |
|---|---|
| Debian | 12, 13 |
| Ubuntu | 22.04 LTS, 24.04 LTS, 26.04 LTS |
| Rocky Linux | 8.10, 9.8, 10.2 |
| Fedora | 43, 44 |

Use the distribution's Bash and ShellCheck versions. Run fixtures that test permissions as a non-root user. Then run the installed-layout and scanner smoke checks with the required privileges. On each matrix target, verify `make check`, `make lint`, staged installation, one 67-result scan, Markdown and JSONL result counts, report modes, and JSONL parsing when `jq` is available.

Select these releases with `--matrix supported --prepare`. Fedora smoke checks
first verify that the scanner rejects the platform by default, then run an
exploratory `--allow-unsupported` scan. These tests do not expand production
platform support. See the
[automated test guide](test-automation.md) for lifecycle scope and snapshot updates.

Containerized userspace coverage does not replace acceptance testing on a booted host with systemd, active listeners, real mount topology, and native validators. Record only tests that were actually run.

Use [automated Linux guest tests](test-automation.md) for Apple `container` or QEMU. For manual Apple runs, follow [macOS container testing](macos-container-testing.md).

## Preparing a review

Provide enough evidence for another maintainer to reproduce the result:

- state the observed problem and root cause;
- list affected criteria, platforms, resolver namespaces, and result-state changes;
- describe the trust, confidentiality, and offline-root implications;
- list every changed file and the reason it changed;
- record exact validation commands and their pass or failure results;
- distinguish generated fixtures, containerized userspace tests, and booted-host acceptance;
- identify remaining limitations without presenting untested behavior as complete.

Review the complete working-tree diff before staging, and leave unrelated changes unstaged. When a maintainer requests a commit, use one Conventional Commit for the logical change. Every AI-assisted change requires human review and validation.

## Licensing and authorship

Contributions must be available under the repository's dual-license expression:

```text
LGPL-3.0-or-later OR BSD-3-Clause
```

Contributors must have the right to submit their work under both alternatives. KISA guide material and other third-party content retain their original terms. See [Development: Contribution licensing](development.md#contribution-licensing), [`LICENSING.md`](../../LICENSING.md), [`NOTICE`](../../NOTICE), and [`LICENSES/`](../../LICENSES/).

Do not add a `Signed-off-by` trailer on behalf of another person. Contributors must add their own sign-off when project policy requires it. Keep any required AI-assistance disclosure separate; it does not replace human review or sign-off.

## Review checklist

- [ ] The change is limited to the requested subsystem and preserves unrelated work.
- [ ] Every affected criterion and shared consumer was identified.
- [ ] Result-state and error precedence remain conservative.
- [ ] Resolution class, remediation eligibility, and versioned rule ID are
      consistent with the result and review schema 2.
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
