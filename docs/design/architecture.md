# Architecture

## Purpose

The scanner converts host configuration and runtime observations into one conservative result for each selected KISA CCE 2026 Unix criterion. It is an assessment tool, not a remediation engine.

The implementation separates collection from policy interpretation wherever the effective state depends on multiple configuration files, a service manager, or runtime state. An incomplete collection path must not become a `GOOD` result.

## Component map

| Component | Responsibility |
|---|---|
| `bin/kisa-cce-scan` | Public POSIX launcher. Locates the private main file and starts Bash through a clean environment. |
| `bin/kisa-cce-collect` | Public launcher for the live-runtime evidence collector. |
| `lib/kisa-cce-scan-main.sh` | Resolves source/installed paths, parses options, validates the catalog, selects the platform, dispatches checks, and finalizes reports. |
| `lib/kisa-cce-collect-main.sh` | Root-only live evidence collection and bundle finalization. |
| `lib/core.sh` | Rooted filesystem access, trusted-command selection, platform detection, structured debug output, result normalization, report writing, and exit status. |
| `lib/policy.sh` | Strict policy-directory loader, typed fact lookup, and review-ID-bound attestation lookup. |
| `lib/evidence.sh` | Evidence bundle validation, identity binding, and runtime state helpers. |
| `lib/i18n.sh` | Dependency-free strict PO parsing and localized report string lookup. |
| `lib/scan_epoch.sh` | Run-scoped snapshot lifecycle, reverse dependencies, dirtiness, and normalized-output propagation. |
| `lib/resolvers.sh` | Shared configuration precedence, include traversal, path confinement, sysctl resolution, and systemd state helpers. |
| `lib/checks_account_file.sh` | U-01 through U-33 account and filesystem checks. |
| `lib/checks_service.sh` | U-34 through U-63 service checks. |
| `lib/checks_system.sh` | U-64 through U-67 patch, time, and logging checks. |
| `data/criteria.tsv` | Ordered 67-row criterion catalog and report metadata. |
| `data/VERSION` | Runtime and package version source. |
| `share/kisa-cce-linux-scanner/locale` | Korean and English report catalogs in a package-specific data path. |
| `tests/run.sh` | Generated-fixture regression suite and staged-installation checks. |
| `Makefile` | Syntax, test, lint, and `DESTDIR` installation entry points. |

## Source and installed layouts

The public launcher supports the development tree directly:

```text
bin/kisa-cce-scan
lib/kisa-cce-scan-main.sh
lib/*.sh
data/criteria.tsv
data/VERSION
share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po
```

With `prefix=/usr`, the default installed layout is:

```text
/usr/bin/kisa-cce-scan
/usr/lib/kisa-cce-linux-scanner/*.sh
/usr/share/kisa-cce-linux-scanner/criteria.tsv
/usr/share/kisa-cce-linux-scanner/VERSION
/usr/share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po
/usr/share/man/man8/kisa-cce-scan.8
/usr/share/man/man8/kisa-cce-collect.8
```

The main file derives the data directory from its own private-library location. It does not accept a caller-controlled module path. The same relative-prefix rule allows a command inside a `DESTDIR` staging tree to execute before the package is built, provided the command, private library, and data retain one of the supported relative layouts.

## Execution flow

1. The POSIX launcher locates the private Bash main file in the source, private-lib, or supported libexec layout.
2. The launcher selects English reports only for an English `LANG`, otherwise selects the default Korean report catalog, then invokes `/bin/bash` through `/usr/bin/env -i` with a fixed system `PATH`.
3. The main file resolves its data directory and loads the version, strict PO catalog, core, resolvers, and check modules.
4. CLI arguments and `data/criteria.tsv` are validated before collection begins.
5. `/etc/os-release` inside the selected scan root determines the product identity, configuration family, and upstream base release.
6. An offline root disables runtime collection. A live-root scan requires UID 0.
7. Normal scans validate the output path, pin the output directory by file descriptor, create protected report and scratch files through that descriptor, and start one immutable scan epoch. Sysctl explanation mode creates only a protected temporary workspace and its own epoch.
8. Catalog rows are read in order. Each `U-NN` row dispatches to `check_u_nn` and produces exactly one result when selected.
9. The scanner appends a summary, verifies report ownership, permissions, record counts, and the pinned output-directory binding, prints both report paths, and returns the aggregate exit status.

When `--debug` is active, the main flow and subsystem resolvers emit schema-versioned events through the central debug API. The option also enables normal verbose progress. Debug records go only to the standard-error descriptor captured when `--debug` is accepted during option parsing; result reports and the standard-output report-path protocol are unchanged. The API percent-encodes dynamic field values and applies per-field and per-event limits before using the normal dmesg-framed console writer. It intentionally exposes normalized operational states rather than shell execution, assessed content, result evidence, or native-command output.

In complete mode, `record_result` computes a SHA-256 review ID over the full redacted technical basis before the display-size limit. The review basis includes scanner and platform identity, bundle identity and digest, criterion metadata, technical summary, and evidence. A matching unexpired attestation can resolve only that exact `MANUAL` basis. Other technical states are never overridden.

An offline evidence bundle is validated and bound to the root by exact `machine-id` and `os-release` matches. Central service, activation, listener, mount, and normalized time-source helpers consume validated bundle state without enabling host command execution against the analysis machine. The validator accepts legacy schema version 1 bundles, while the current collector writes schema version 2 with strict time-synchronization records.

## Platform profiles

Platform authorization uses an explicit product and version allowlist. `ID_LIKE` is recorded but never authorizes an arbitrary derivative. Approved Ubuntu derivatives must also expose the expected `UBUNTU_CODENAME`; CentOS must identify itself as CentOS Stream. The exact lifecycle snapshot is documented in [Platform support](../reference/platform-support.md). The rendered-guide family branches and versioned native adapters are recorded in [KISA platform semantics](../reference/kisa-platform-semantics.md).

The detector assigns `PLATFORM_FAMILY`, `PLATFORM_BASE_ID`, and `PLATFORM_BASE_VERSION` independently from the product's own `ID` and `VERSION_ID`. Checks branch on the configuration family or a versioned capability instead of treating every non-Ubuntu target as RHEL.

## Criterion dispatch contract

The catalog is validated as a tab-separated file with this exact header:

```text
code	category	severity	title
```

The main file requires the exact ordered code range `U-01` through `U-67`. A row such as `U-01` maps to the Bash function `check_u_01`. A missing function, invalid status, or missing result becomes an `ERROR` rather than silently omitting a criterion. A report write failure sets a process-level report error and produces exit status `2`; it does not synthesize another criterion record.

Each check returns through `set_result` with four logical fields:

```text
status, summary, evidence, applicable
```

Allowed statuses are `GOOD`, `VULNERABLE`, `MANUAL`, `NOT_APPLICABLE`, and `ERROR`. Applicability is the JSON boolean `true` or `false`.

## Evidence model

The scanner distinguishes four layers when the subsystem exposes them:

| Layer | Meaning |
|---|---|
| Persistent source | Files intended to survive reboot. |
| Manager-normalized state | The effective interpretation produced by a trusted native parser or service manager. |
| Runtime state | Active units, listeners, loaded kernel values, exported resources, or synchronization state. |
| Typed organization fact | A bounded approved value, owner, ticket, and expiry used as an evaluator input. |

A check may return `GOOD` only when the evidence required by that criterion is conclusive. Ambiguous include graphs, unsupported native syntax, unavailable runtime state, external policy, and approved exceptions are represented as `MANUAL` or `ERROR` according to whether collection completed reliably.

## Shared filesystem collection

U-15, U-23, U-25, and U-33 share one lazy filesystem snapshot for each scan root, runtime mode, scratch workspace, and criterion selection. The collector resolves the local filesystem roots once and runs one `find -xdev` traversal per root. Live-root scans retain the trusted `findmnt` topology query in static-only mode because mount boundaries define the filesystem evidence scope rather than service or kernel security state. It prunes the current scratch directory and the two report-file inodes so scanner-created artifacts cannot become findings in the same run. Subsequent checks consume cached counts and the first 20 evidence paths without repeating the traversal.

Live collection retains host NSS behavior for U-15 by evaluating `-nouser` and `-nogroup` inside GNU `find`. Offline collection reads numeric UID, GID, type, and mode fields from a NUL-delimited GNU `find -P` metadata stream and compares them with the selected root's validated account databases. Symbolic-link records therefore use the link's own metadata instead of dereferencing the target, and a dangling target does not make the shared inventory incomplete.

All collector records terminate every field with NUL, so whitespace, control characters, and shell metacharacters in pathnames cannot change record boundaries. Evidence paths still pass through the normal display sanitizer. Tests that mutate a fixture after collection call `scanner_reset_full_filesystem_cache` before requesting a new snapshot.

U-67 uses a separate single-pass tagged traversal because its `/var/log` mount scope differs from the general local-filesystem scope. Regular-file and directory metadata comes from the same traversal, while symbolic-link targets retain rooted resolution and their existing policy treatment.

## Execution-cost controls

Hot path helpers return values through caller-supplied variables, avoiding command-substitution subshells while retaining compatibility wrappers for non-hot paths. The scanner caches the canonical scan root and validated native-command locations for one run. Layered sysctl files and PAM files are parsed once per scan epoch. Service facts use an epoch-scoped systemd snapshot, and every listener query shares one mixed transport snapshot until the next epoch.

Report normalization expands evidence separators and normalizes the title, summary, and evidence in one framed external conversion. Evidence without a sensitive-keyword marker bypasses the external redaction pass. Metadata-heavy checks use NUL-delimited GNU `find` records, so one traversal supplies multiple fields without a per-file `stat` process. These choices follow the process model described by the [Bash command-substitution](https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html) and [builtin-command](https://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html) documentation and the batching facilities in the [GNU find format directives](https://www.gnu.org/software/findutils/manual/html_node/find_html/Format-Directives.html).

Source-to-resolver and resolver-to-criterion reverse maps retain successful, absent, ambiguous, and failed states. A source change dirties its resolver; only a changed normalized resolver output propagates dirtiness to a criterion. See [Scan performance architecture](performance.md).

## Configuration resolution

Configuration formats do not share a universal merge algorithm. Shared helpers provide path safety and ordered file discovery, while each subsystem defines its own precedence and parsing rules.

### Layered files

`select_layered_files` accepts directories in descending priority. For equal basenames, the first directory wins. Selected basenames are then processed in bytewise lexical order. Unreadable directories and unsafe symlink resolution are errors, not absence.

This primitive is used only where the subsystem follows compatible drop-in semantics. It is not a general substitute for a native parser.

### sysctl

The filesystem model selects `.conf` files from these directories:

```text
/etc/sysctl.d
/run/sysctl.d
/usr/local/lib/sysctl.d
/usr/lib/sysctl.d
```

It implements same-basename priority, lexical application order, `/dev/null` masks, explicit assignments, exclusion directives, glob assignments, and dot/slash key normalization. During a live systemd-based scan, the resolver also requests the loader's `--cat-config` stream and compares that interpretation with the filesystem model and current kernel value. Both `/lib/systemd/systemd-sysctl` and `/usr/lib/systemd/systemd-sysctl` are accepted after ownership, mode, and parent-path validation.

Unexpected loader commands, unsupported service overrides, or supplied `sysctl.extra` credential material prevent a conclusive result. A stock unit declaration that can load `sysctl.extra` is not itself evidence that a credential was supplied. On Debian-family targets, an active UFW `IPT_SYSCTL` source is resolved as an additional network-sysctl layer. `/etc/sysctl.conf.d` is reported as nonstandard and inactive; it is not treated as a standard source directory.

References: [systemd `sysctl.d(5)`](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html), [RHEL 10 kernel parameter management](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

### Other subsystem adapters

- OpenSSH prefers trusted `sshd -T` output and accounts for include position, first-obtained values, `Match` context, units, sockets, and listeners.
- PAM follows recursive `include` and `substack` relationships within the requested PAM facility, Debian-family `common-*` stacks, and Enterprise Linux authselect-managed stacks.
- Password quality combines `pwquality.conf.d`, `pwquality.conf`, and PAM module arguments in their implemented precedence.
- Password history reads `pwhistory.conf` only on platform versions whose PAM implementation supports that file; older supported Debian-family versions require module arguments.
- Password hash assessment combines active shadow identifiers, `login.defs`, and explicit `pam_unix` password-facility hash options.
- General login-default consumers use legacy last-match semantics on Debian-family and Enterprise Linux 8/9 targets. Enterprise Linux 10 uses libeconf's first main-file value and merged `login.defs.d/*.defs` overrides, including the last duplicate inside a merged drop-in. The `pam_umask` and PAM password-hash paths use their separately versioned native precedence: Enterprise Linux 9 reads libeconf roots from `/usr/share` and `/etc`, while Enterprise Linux 10 reads `/etc` only. PAM hash checks use the selected native value rather than rejecting duplicate definitions as a separate condition.
- systemd inspection includes unit aliases, masks, template and type drop-ins, socket activation, and manager properties.
- sudo inspection detects sudo-rs or traditional sudo. U-63 applies the rendered guide's exact owner and mode requirement to `/etc/sudoers`; provider-specific syntax validation is supplemental and cannot replace that criterion.
- Chrony follows `include`, `confdir`, and `sourcedir`, then checks selected runtime sources when available. NTPsec follows bounded `includefile` graphs and Debian-family `/etc/ntpsec/ntp.d/*.conf` package drop-ins. An active `*` network peer establishes synchronization evidence; PPS/reference-clock and dynamic-only sources remain `MANUAL`. U-65 compares the selected provider and source with `facts/time-sources.tsv`; an unexpired exact match can complete the technical `GOOD` path.
- NFS combines `/etc/exports`, `/etc/exports.d/*.exports`, and the active export table when available.
- BIND, Samba, mail, FTP, Net-SNMP, rsyslog, and journald use trusted native validation where implemented and otherwise preserve ambiguity.

Ubuntu 26.04 uses sudo-rs as its default sudo provider, while the traditional implementation is exposed separately. See the [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/).

## Report pipeline

`set_result` validates and retains the four logical fields until dispatch. `record_result` expands evidence separators and builds control-byte-normalized, UTF-8-normalized working values through one framed `iconv` call when available. The Markdown serializer escapes normalized titles and summaries before placing them in headings or prose. Evidence receives targeted credential redaction and an 8192-byte limit, renders tab and carriage return as visible escapes, maps remaining unsafe controls, and indents every line as code so assessed content cannot create Markdown structure. The JSONL copy retains the unprefixed normalized value and additionally removes an incomplete UTF-8 suffix created at the byte boundary. The Markdown evidence section is omitted when its value is empty. Counters increment only after both report writes succeed.

Before success, `validate_reports` verifies:

- both files are non-empty;
- both files belong to the invoking UID;
- both files have mode `0600`;
- JSONL line count equals result count plus one summary line;
- Markdown result headings match the JSONL criterion codes and recorded result count;
- the Markdown header and status-summary rows occur exactly once with the recorded counts.
- complete mode contains exactly 67 results and zero final `MANUAL` states.

JSON schema validation is not currently part of the runtime finalization path. The test suite optionally parses JSONL with `jq` when it is installed.

## Design boundaries

- The scanner reads configuration and runtime state but does not remediate it.
- It does not reload sysctl, firewall, NFS, or service configuration.
- It does not refresh package metadata or run network-fetch commands. Live U-15 owner lookup uses host NSS, which may consult a configured external identity backend.
- It does not turn organizational policy or approved exceptions into automatic decisions.
- It does not claim support outside the explicit product matrix and its two configuration families.
- It does not replace a platform acceptance test or a qualified security review.

See [Security model](security-model.md) for trust assumptions and residual risks.
