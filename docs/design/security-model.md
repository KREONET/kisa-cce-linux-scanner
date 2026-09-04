# Security model

## Context

A live scan runs as root and reads security-sensitive system state. The scanner therefore treats the execution environment, executable lookup, offline path traversal, report permissions, and evidence content as security boundaries.

This document describes controls implemented by the current code. It is not a claim that the scanner itself has completed an independent security audit.

## Protected assets

- Integrity of the host being assessed.
- Confidentiality of password hashes, authentication material, community strings, tokens, keys, and sensitive configuration.
- Integrity and completeness of each criterion result.
- Integrity of the scanner code, criterion catalog, and report destination.
- Confinement of reads to an explicitly selected offline root.

## Trust boundaries

| Boundary | Trusted side | Untrusted or variable side |
|---|---|---|
| Installation | Root-owned package files and directories. | A modified or user-writable source checkout. |
| Process startup | Direct launcher path and fixed system interpreter paths. | Caller environment, exported functions, and caller `PATH`. |
| Live command execution | Root-owned commands and parent directories without group/other write permission. | Commands found only through a mutable `PATH` or writable path. |
| Offline scan | Canonical paths confined below `--root`. | Absolute symlinks, traversal, loops, and paths escaping the root. |
| Reporting | Invoking-user-owned, no-symlink-component, owner-only output directory reached through trusted ancestors and pinned by file descriptor. | Shared, group-accessible, world-accessible, replaceable, or redirected output paths. |
| Evidence | Minimal normalized summaries and selected values. | Raw files and command output that may contain secrets or control characters. |

## Implemented controls

### Startup environment

The public `#!/bin/sh` launcher locates only known relative module layouts. It starts the private Bash main file through `/usr/bin/env -i`, supplies a fixed `/usr/sbin:/usr/bin:/sbin:/bin` path, and passes only CLI arguments. The Bash process unsets imported functions for commands used by the scanner and sets `umask 077`.

Regression tests set hostile `BASH_ENV` and `ENV` values and verify that the private main file does not load them.

### Trusted host commands

Runtime collection does not use arbitrary caller `PATH` entries. `trusted_command` searches fixed system directories, resolves the candidate where supported, and requires:

- root ownership of the executable;
- no group or other write permission on the executable;
- root ownership of every parent directory;
- no group or other write permission on the parent chain.

Unavailable or untrusted native tools produce conservative collection states instead of invoking another executable with the same name.

On a live Linux root, the fallback runtime collector reads only the current process namespace under `/proc`. It retains bounded PID, command-name, executable-path, socket-address, port, and inode facts; process command lines are neither read nor stored. TCP facts require the kernel LISTEN state, and UDP facts require an unconnected bound socket. Missing or malformed socket tables and persistent process-metadata failures make negative results indeterminate instead of proving service absence.

Static-only live-root scans retain one narrower host query: `trusted_findmnt_command` resolves only `findmnt` through the same ownership, mode, and parent-chain checks. Mount topology defines the scope of `find -xdev` filesystem evidence and does not enable service, listener, kernel-value, or native-validator collection. Offline roots never use this host command.

The sysctl loader adapter is a narrower special case. It accepts the distribution paths `/lib/systemd/systemd-sysctl` and `/usr/lib/systemd/systemd-sysctl` only after validating root ownership, write mode, and the complete parent chain.

### Offline-root confinement

Logical paths must be absolute and reject newline, carriage-return, tab, and explicit `.` or `..` components. Canonical parent paths must remain below the selected root. Symlink traversal is bounded, absolute symlink targets are interpreted inside the offline root, and escapes or unresolved links fail collection.

Drop-in directory symlinks are also confined. A `/dev/null` link is accepted only where the corresponding subsystem uses it as an explicit mask.

### Complete-mode policy and runtime evidence

Policy files are parsed as strict TSV data and are never sourced as shell code. The policy directory and files reject symbolic links and untrusted write permissions. Each attestation is bound to one criterion's full redacted technical basis through a SHA-256 review ID and expires on an explicit date. Typed facts use separately versioned schemas below `facts/`; unknown fact files, ambiguous matches, invalid values, and expired approvals fail closed. Both attestations and typed facts contribute to the scan-epoch policy digest.

The optional policy compiler accepts only a documented YAML subset and never sources or evaluates input. Its launcher clears the caller environment. The compiler pins the input and output parent by file descriptor, rejects untrusted paths and existing output targets, writes an owner-only staging directory, reloads generated TSV through the canonical policy validator, and publishes with a no-replace rename. General YAML anchors, aliases, tags, merges, flow collections, and block scalars are outside this trust boundary and are rejected.

Evidence bundles are fixed-inventory directories rather than extracted archives. Validation requires owner-only permissions, regular single-link files, exact schemas, SHA-256 checksums, and matching offline-root `machine-id` and `os-release`. Schema version 2 normalizes time synchronization before storage, and criteria consume only validated fields. Complete mode rejects bundles older than its configured maximum age.

Bundle checksums detect changes after capture but do not authenticate the capture host or transfer channel. Protect bundle provenance with trusted transport or a detached-signature process appropriate to the deployment.

### Read-only assessment

The scanner does not apply fixes, reload daemons, alter firewall rules, export NFS filesystems, refresh package indexes, or modify assessed configuration. Normal scans write only reports and temporary workspace files in the selected output location. If `--output-dir` is deliberately placed below an offline root, those report files are consequently written inside that root. The public launcher clears caller environment variables, so sysctl explanation mode creates its temporary workspace below `/tmp` and removes it at exit.

### Report protection

For a normal scan, the output path must be absolute and contain no symbolic-link component. The output directory must belong to the invoking UID, provide owner read/write/search access, and expose no group or other permissions. Existing ancestors may not be group- or other-writable unless they are trusted sticky directories; `/tmp` and `/var/tmp` are handled as the standard shared temporary roots. New directories and scratch directories use mode `0700`; reports use mode `0600` and randomized names.

After validation, the scanner opens the output directory and creates its scratch directory and reports through `/proc/self/fd`. It records the directory device and inode, compares the pinned descriptor with the lexical path at finalization, and withholds report paths if that binding changed. Sysctl explanation mode validates only the absolute-path syntax and does not use the directory.

Runtime finalization rejects empty reports, wrong ownership, wrong modes, and mismatched result counts.

### Evidence handling

Evidence passes through control-character normalization, UTF-8 normalization when available, targeted secret redaction, and an approximately 8 KiB limit. Markdown titles and summaries are escaped. Evidence maps tab and carriage return to visible escapes, replaces or removes remaining unsafe control bytes, and is HTML-escaped inside an inert `pre/code` container under a `details` disclosure. Assessed content therefore cannot create headings, links, images, tables, or raw HTML. The implemented filters cover common password/hash, SNMP, secret, token, and passphrase forms. Credential keys require a field boundary, so metadata for paths such as `/usr/bin/passwd:mode=4755` remains intact. Checks are expected to collect the minimum evidence needed for review rather than entire sensitive files.

Verbose mode writes only platform context, check identifiers, statuses, titles, and aggregate counters to standard error. It never writes result summaries or evidence to the terminal.

### Debug diagnostics

`--debug` extends verbose progress with structured scanner lifecycle, resolver, cache, collection, and report-validation events on standard error. It does not enable Bash execution tracing, preserve the scratch workspace, or create a separate debug file. Debug instrumentation uses a saved copy of the original standard-error descriptor so diagnostics remain visible when an internal operation suppresses its own standard error. If the process cannot allocate that descriptor, the scanner warns and falls back to the current standard error without changing assessment results or exit status; events inside locally suppressed operations may then be unavailable.

Debug event names and field names are fixed implementation identifiers. Dynamic values are percent-encoded outside a small safe byte set, each rendered `key=value` field is limited to 256 bytes, and one event is limited to 2048 bytes. Events do not contain result summaries, evidence, configuration lines, command arguments, native-command output, policy contents, review identifiers, evidence-bundle digests, or report paths. The debug API is not a general-purpose logging function, and callers must pass only the minimum enumerated state needed to diagnose collection and cache behavior.

The remaining event metadata is still sensitive assessment data. It identifies the selected root and platform, criteria being evaluated, subsystem availability, cache behavior, and failure state. Standard error is not opened or protected by the scanner. An operator who redirects it must create the destination under an owner-only `umask`, protect it like the reports, and review it before transfer.

Bash 4.3 has no built-in interface for applying `FD_CLOEXEC` to the saved diagnostic descriptor. Child processes therefore inherit that descriptor, although its number is not passed through arguments or environment and scanner call sites write to it only through `debug_emit`. Debug mode relies on the same root-owned native-command trust boundary as normal live collection; it is not an isolation mechanism for a compromised native utility.

## Failure policy

Security-relevant uncertainty is explicit:

- `MANUAL` means collection produced useful evidence but intent, policy, an exception, or unavailable context requires a reviewer.
- `ERROR` means required evidence was not collected or interpreted reliably.
- Neither state may be converted to `GOOD` because a file or command was unavailable.
- On normal completion, any `ERROR` makes the process exit with status `2`, even when vulnerable results also exist. SIGINT and SIGTERM use their documented signal statuses instead.

## Residual risks and limitations

### Installation integrity is assumed

The launcher and main file verify readability and expected relative layout, but they do not verify package signatures, file hashes, ownership, or write permissions for their own modules and `criteria.tsv` before sourcing or reading them. The package manager and filesystem permissions must protect the installation tree.

Do not run the source checkout as root unless the checkout and every parent directory are trusted and protected from untrusted modification.

### Redaction is not data-loss prevention

Targeted patterns cannot identify every possible secret format or sensitive organization-specific value. Review both reports before transferring them outside the assessed environment. Store and transmit reports as sensitive security data.

### A live root process has broad read access

The root requirement enables complete inspection but increases impact if scanner code or a trusted native utility is compromised. Install from a reviewed package or immutable deployment artifact. Do not add runtime plugins or caller-controlled module paths.

Live U-15 collection evaluates GNU `find -nouser` and `-nogroup` with the host's NSS configuration. An NSS module such as SSS or LDAP can consult an external identity service even though the scanner itself does not run a network-fetch command.

### Native parser output remains an input

Trusted commands can still fail, change output across versions, or parse hostile local configuration. The scanner limits command selection and output use, but distribution updates require regression and target-host testing.

### Platform identity is declarative

The target controls `/etc/os-release`. Explicit product, version, and base-codename checks prevent accidental authorization through `ID_LIKE`, but they do not attest that an image is genuine or still enrolled in a vendor support service. Validate image provenance and lifecycle status independently.

### Offline images are snapshots

An offline root may be incomplete, inconsistent, or captured while files were changing. Runtime-disabled results cannot establish the active service or kernel state. Prefer a quiescent snapshot and retain its provenance.

## Deployment requirements

- Install the public launcher and private files as root-owned package content.
- Keep `/usr/lib/kisa-cce-linux-scanner` and `/usr/share/kisa-cce-linux-scanner` non-writable by unprivileged users.
- Use a local owner-only output directory.
- Review reports before sharing them.
- Run full scans from a controlled administrative session.
- Validate package installation and live behavior on every listed product and release.

Package signature policy, target-host acceptance, and an independent security review remain outside the current fixture suite.
