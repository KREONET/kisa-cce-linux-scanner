# Architecture

## Purpose

The scanner converts host configuration and runtime observations into one conservative result for each selected KISA CCE 2026 Unix criterion. It is an assessment tool, not a remediation engine.

The implementation separates collection from policy interpretation wherever the effective state depends on multiple configuration files, a service manager, or runtime state. An incomplete collection path must not become a `GOOD` result.

## Component map

| Component | Responsibility |
|---|---|
| `bin/kisa-cce-scan` | Public POSIX launcher. Locates the private main file and starts Bash through a clean environment. |
| `lib/kisa-cce-scan-main.sh` | Resolves source/installed paths, parses options, validates the catalog, selects the platform, dispatches checks, and finalizes reports. |
| `lib/core.sh` | Rooted filesystem access, trusted-command selection, platform detection, result normalization, report writing, and exit status. |
| `lib/resolvers.sh` | Shared configuration precedence, include traversal, path confinement, sysctl resolution, and systemd state helpers. |
| `lib/checks_account_file.sh` | U-01 through U-33 account and filesystem checks. |
| `lib/checks_service.sh` | U-34 through U-63 service checks. |
| `lib/checks_system.sh` | U-64 through U-67 patch, time, and logging checks. |
| `data/criteria.tsv` | Ordered 67-row criterion catalog and report metadata. |
| `data/VERSION` | Runtime and package version source. |
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
```

With `prefix=/usr`, the default installed layout is:

```text
/usr/bin/kisa-cce-scan
/usr/lib/kisa-cce-linux-scanner/*.sh
/usr/share/kisa-cce-linux-scanner/criteria.tsv
/usr/share/kisa-cce-linux-scanner/VERSION
```

The main file derives the data directory from its own private-library location. It does not accept a caller-controlled module path. The same relative-prefix rule allows a command inside a `DESTDIR` staging tree to execute before the package is built, provided the command, private library, and data retain one of the supported relative layouts.

## Execution flow

1. The POSIX launcher locates the private Bash main file in the source, private-lib, or supported libexec layout.
2. The launcher invokes `/bin/bash` through `/usr/bin/env -i` with a fixed system `PATH`.
3. The main file resolves its data directory and loads the version, core, resolvers, and check modules.
4. CLI arguments and `data/criteria.tsv` are validated before collection begins.
5. `/etc/os-release` inside the selected scan root determines platform support.
6. An offline root disables runtime collection. A live-root scan requires UID 0.
7. Normal scans create protected report and scratch files. Sysctl explanation mode creates only a protected temporary workspace.
8. Catalog rows are read in order. Each `U-NN` row dispatches to `check_u_nn` and produces exactly one result when selected.
9. The scanner appends a summary, verifies report ownership, permissions, and record counts, prints both report paths, and returns the aggregate exit status.

## Criterion dispatch contract

The catalog is validated as a tab-separated file with this exact header:

```text
code	category	severity	title
```

The main file requires 67 unique codes matching `U-[0-9][0-9]`. A row such as `U-01` maps to the Bash function `check_u_01`. A missing function, invalid status, or missing result becomes an `ERROR` rather than silently omitting a criterion. A report write failure sets a process-level report error and produces exit status `2`; it does not synthesize another criterion record.

Each check returns through `set_result` with four logical fields:

```text
status, summary, evidence, applicable
```

Allowed statuses are `GOOD`, `VULNERABLE`, `MANUAL`, `NOT_APPLICABLE`, and `ERROR`. Applicability is the JSON boolean `true` or `false`.

## Evidence model

The scanner distinguishes three layers when the subsystem exposes them:

| Layer | Meaning |
|---|---|
| Persistent source | Files intended to survive reboot. |
| Manager-normalized state | The effective interpretation produced by a trusted native parser or service manager. |
| Runtime state | Active units, listeners, loaded kernel values, exported resources, or synchronization state. |

A check may return `GOOD` only when the evidence required by that criterion is conclusive. Ambiguous include graphs, unsupported native syntax, unavailable runtime state, external policy, and approved exceptions are represented as `MANUAL` or `ERROR` according to whether collection completed reliably.

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

It implements same-basename priority, lexical application order, `/dev/null` masks, explicit assignments, exclusion directives, glob assignments, and dot/slash key normalization. During a live systemd-based scan, the resolver also requests the loader's `--cat-config` stream and compares that interpretation with the filesystem model and current kernel value.

Unexpected loader commands, unsupported service overrides, or observed `sysctl.extra` credentials prevent a conclusive result. `/etc/sysctl.conf.d` is reported as nonstandard and inactive; it is not treated as a standard source directory.

References: [systemd `sysctl.d(5)`](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html), [RHEL 10 kernel parameter management](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

### Other subsystem adapters

- OpenSSH prefers trusted `sshd -T` output and accounts for include position, first-obtained values, `Match` context, units, sockets, and listeners.
- PAM follows recursive `include` and `substack` relationships, Ubuntu `common-*` stacks, and RHEL authselect-managed stacks.
- Password quality combines `pwquality.conf.d`, `pwquality.conf`, and PAM module arguments in their implemented precedence.
- Login defaults use Ubuntu legacy semantics and RHEL 10 `login.defs.d/*.defs` behavior separately.
- systemd inspection includes unit aliases, masks, template and type drop-ins, socket activation, and manager properties.
- sudo inspection detects sudo-rs or traditional sudo and follows the active provider's include graph.
- Chrony follows `include`, `confdir`, and `sourcedir`, then checks selected runtime sources when available.
- NFS combines `/etc/exports`, `/etc/exports.d/*.exports`, and the active export table when available.
- BIND, Samba, mail, FTP, Net-SNMP, rsyslog, and journald use trusted native validation where implemented and otherwise preserve ambiguity.

Ubuntu 26.04 uses sudo-rs as its default sudo provider, while the traditional implementation is exposed separately. See the [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/).

## Report pipeline

`set_result` removes unsafe control bytes, normalizes valid UTF-8 when `iconv` is present, applies targeted credential redaction, and limits evidence to approximately 8 KiB. `record_result` serializes the same logical result to text and JSONL and increments counters only after both writes succeed.

Before success, `validate_reports` verifies:

- both files are non-empty;
- both files belong to the invoking UID;
- both files have mode `0600`;
- JSONL line count equals result count plus one summary line;
- text result markers equal the recorded result count.

JSON schema validation is not currently part of the runtime finalization path. The test suite optionally parses JSONL with `jq` when it is installed.

## Design boundaries

- The scanner reads configuration and runtime state but does not remediate it.
- It does not reload sysctl, firewall, NFS, or service configuration.
- It does not refresh package metadata or access the network.
- It does not turn organizational policy or approved exceptions into automatic decisions.
- It does not claim support outside the two detected platform families.
- It does not replace a platform acceptance test or a qualified security review.

See [Security model](security-model.md) for trust assumptions and residual risks.
