# Security model

## Context

A live scan runs as root and reads security-sensitive system state. An apply or
rollback operation also runs as root and changes security-relevant file
metadata. The tools therefore treat the execution environment, executable
lookup, offline path traversal, output permissions, evidence content,
transaction integrity, lifecycle state, and target identity as security
boundaries.

This document describes controls implemented by the current code. It is not a claim that the scanner itself has completed an independent security audit.

## Protected assets

- Integrity of the host being assessed.
- Confidentiality of password hashes, authentication material, community strings, tokens, keys, and sensitive configuration.
- Integrity and completeness of each criterion result.
- Integrity of the scanner code, criterion catalog, and report destination.
- Confinement of reads to an explicitly selected offline root.
- Integrity and recoverability of file metadata selected for remediation.
- Confidentiality and integrity of remediation plans and transactions.

## Trust boundaries

| Boundary | Trusted side | Untrusted or variable side |
|---|---|---|
| Installation | Root-owned package files and directories. | A modified or user-writable source checkout. |
| Process startup | Direct launcher path and fixed system interpreter paths. | Caller environment, exported functions, and caller `PATH`. |
| Live command execution | Root-owned commands and parent directories without group/other write permission. | Commands found only through a mutable `PATH` or writable path. |
| Offline scan | Canonical paths confined below `--root`. | Absolute symlinks, traversal, loops, and paths escaping the root. |
| Reporting | Invoking-user-owned, no-symlink-component, owner-only output directory reached through trusted ancestors and pinned by file descriptor. | Shared, group-accessible, world-accessible, replaceable, or redirected output paths. |
| Evidence | Minimal normalized summaries and selected values. | Raw files and command output that may contain secrets or control characters. |
| Configuration and metadata remediation | Fixed rule paths and payloads, root-confined objects, and device/inode-bound snapshots. | Operator-supplied arbitrary content or paths, symbolic links, replaced inodes, and concurrent drift. |
| Transactions | Exclusively created owner-only artifacts validated against the current root and rule registry. | Modified, loosely permissioned, stale, or cross-root transaction data. |

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

### Complete and automation policy and runtime evidence

Policy files are parsed as strict TSV data and are never sourced as shell code.
The policy directory and files reject symbolic links and untrusted write
permissions. Review schema 2 binds each attestation to one policy-class
criterion basis, including its resolution class, through a SHA-256 review ID
and explicit expiration date. Attestations cannot resolve technical, runtime,
or external evidence gaps. Typed facts use separately versioned schemas below
`facts/`; unknown fact files, ambiguous matches, invalid values, and expired
approvals fail closed. Both attestations and typed facts contribute to the
scan-epoch policy digest.

In automation mode, an absent policy-class attestation becomes
`VULNERABLE` with `decision_basis=fail_closed_policy`. It remains
`remediation_eligible=false` and carries no rule ID. This state closes the
machine-readable result set without turning missing approval into authority to
change the host. Incomplete technical, runtime, or external evidence becomes
`ERROR` and blocks report publication.

The optional policy compiler accepts only a documented YAML subset and never sources or evaluates input. Its launcher clears the caller environment. The compiler pins the input and output parent by file descriptor, rejects untrusted paths and existing output targets, writes an owner-only staging directory, reloads generated TSV through the canonical policy validator, and publishes with a no-replace rename. General YAML anchors, aliases, tags, merges, flow collections, and block scalars are outside this trust boundary and are rejected.

Evidence bundles are fixed-inventory directories rather than extracted archives. Validation requires owner-only permissions, regular single-link files, exact schemas, SHA-256 checksums, and matching offline-root `machine-id` and `os-release`. Schema version 2 normalizes time synchronization before storage, and criteria consume only validated fields. Complete mode rejects bundles older than its configured maximum age.

Bundle checksums detect changes after capture but do not authenticate the capture host or transfer channel. Protect bundle provenance with trusted transport or a detached-signature process appropriate to the deployment.

### Read-only assessment

The scanner does not apply fixes, reload daemons, alter firewall rules, export NFS filesystems, refresh package indexes, or modify assessed configuration. Normal scans write only reports and temporary workspace files in the selected output location. If `--output-dir` is deliberately placed below an offline root, those report files are consequently written inside that root. The public launcher clears caller environment variables, so sysctl explanation mode creates its temporary workspace below `/tmp` and removes it at exit.

### Configuration and metadata remediation

The separate `kisa-cce-patch` command publicly supports U-12, U-16, U-18,
U-19, U-22, U-29, U-37, U-62, and U-67. U-12 and U-62 use fixed managed
content with fingerprinted backups and payloads. Five metadata rules use fixed
logical paths. U-37 and U-67 use bounded, single-filesystem inventories with one
fingerprint and rollback row per target. The registry fixes every content,
allowed path scope, owner UID, group policy, and mode rule. The CLI cannot
supply arbitrary content, a target, or desired metadata. It does not reload a
service or apply runtime configuration.

Dry-run is the default. Apply requires `--apply` and effective UID 0. The
patcher requires the scanner to produce a conclusive result for every selected
criterion and completes configuration, path, and metadata preflight for every
change before the first mutation. It rejects symbolic-link components, any object type not
supported by the selected rule, hard-linked regular files, a changed root
identity, and a changed target type, device, inode, UID, GID, or mode.

The patcher also requires each vulnerable scanner record to declare
`resolution_class=technical`, `remediation_eligible=true`, and the exact
versioned rule ID expected for that criterion. A policy fail-closed
vulnerability, attested policy decision, or result without a rule ID cannot be
converted into a patch operation.

Fully automatic mode is an explicit root-only all-67 mutation request. It
requires a complete desired-state v2 profile, rejects `--checks`, and implies
apply. The ordinary fixed-rule default remains seven and is not reused by
automatic mode. Without an explicit output path, automatic mode creates
root-owned, non-group-writable parent directories and a
unique mode-`0700` transaction below
`/var/lib/kisa-cce-patcher/transactions`. It does not weaken preflight,
post-scan, or rollback behavior.

The complete configuration and metadata rollback material is written with mode
`0600` before apply. A
stable capture binds each target to its type, size, mtime, and ctime as well as
its filesystem identity and metadata. Regular files are additionally bound to
a SHA-256 content digest; directory rows use a no-content sentinel. Ctime is
required before the first mutation and then ignored because metadata changes
update it; size and mtime remain invariant, as does regular-file content. Each change
preserves the current GID and masks the current mode with the fixed rule
maximum, so remediation cannot grant a permission bit. A new scanner process
performs post-change verification. Failure after mutation triggers a guarded
reverse-order rollback.

Manual rollback accepts only an eligible apply or recovery state for the same
canonical root. It rejects a dry-run, completed rollback, or non-recoverable
failed state. The immutable payload is checksum-verified, while the lifecycle
state is advanced using an atomic file replacement. Configuration recovery
validates the fixed payload, fingerprinted original backup, and apply journal.
Metadata rollback restores an
unchanged target type and inode only when size and mtime also match. Regular
files must remain single-linked and match their content digest. A normal
completed apply requires the full recorded before or after metadata state.
Interrupted recovery permits only per-field before or after
UID, GID, and mode combinations. Any other drift fails closed. These
comparisons reduce substitution and stale rollback risk, but they cannot make
several inode metadata operations atomic. See
[Autopatcher](autopatcher.md) for the transaction and recovery
contract.

Rollback performs an all-target preflight and repeats each check immediately
before restoration. A concurrent change after preflight can still cause a
partially restored transaction and `rollback_failed` state. Rollback verifies
configuration and metadata restoration but does not create a post-rollback
scanner report.

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
- The patcher completes preflight for every selected target before mutation.
  Any apply or post-scan failure initiates rollback; a rollback failure remains
  a process error and requires operator inspection.

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

### Metadata transactions are not crash-atomic

The patcher writes rollback metadata before apply and handles ordinary detected
failures, but it does not provide a filesystem-wide atomic commit or stable
storage synchronization after every operation. `SIGKILL`, a kernel or storage
failure, or power loss can leave a partial apply. Retain the protected
transaction and run guarded manual rollback only after inspecting current inode
identity and metadata.

POSIX ACLs, extended attributes, capabilities, security labels, timestamps,
file content, and replacement inodes are outside the rollback record. A
platform can clear set-ID bits or file capabilities during `chown`, and `chmod`
can change the effective POSIX ACL mask. The UID/GID/mode transaction cannot
reconstruct those side effects. Operators must review auxiliary metadata before
applying a rule where a target uses it.

The SHA-256 inventory detects an immutable transaction-payload change only
while filesystem ownership and write restrictions remain trustworthy. It is
not an external signature; a writer that can replace both an artifact and the
checksum file is outside this boundary.
The per-file content digest prevents a metadata transaction from being applied
to changed regular-file content, but it is sensitive correlation data and does
not authenticate the file's origin. Directory contents are not hashed.

### Conditional remediation libraries

The private coverage contract contains 9 fixed, 58 conditional, and 0 gated
criteria. Conditional account, PAM, inventory, filesystem, service,
network-service, edge-service, and system engines are dispatched only by the
public `--automatic --desired-state FILE` path. The absence of gated rows means
the typed adapter and rollback contracts exist; it does not remove their policy,
evidence, provider, privilege, or runtime prerequisites.

Desired-state v2 input is parsed as a restricted scalar-only YAML subset. The
compiler derives risk, resolution, domain, postcondition, validator, and
rollback fields from the coverage registry. A profile cannot lower a risk,
change a domain, replace a validator, or inject a command. Fixed rules accept no
value; conditional rules require the exact registered input type.

Complex conditional values reference root-owned, mode-`0600` absolute domain
input TSV files. Symlinks, repeated separators, explicit dot or parent
components, invalid records, and untrusted callback paths fail closed.

Native, runtime, protocol, firewall, credential, snapshot, and external-state
operations use narrow callback boundaries. Callback files and parent chains are
checked for root ownership and untrusted write access where the owning adapter
requires an external executable. Plans store secret references or digests, not
plaintext credentials. An adapter returns `external_action_required` when it
cannot perform or prove an external action; that state is never equivalent to
`verified`.

### System adapter callback boundary

The private U-64 through U-66 system adapter requires absolute root-owned
callback executables whose complete parent chain is root-owned and not writable
by group or other users. Typed policy, native validation, fresh runtime,
signature verification, immutable snapshot verification, and package simulation
use distinct callback roles. Callback paths are revalidated before execution.

U-64 never invokes package mutation. It verifies signed repository and advisory
evidence, hashes rather than stores raw snapshot and rollback tokens, records a
bounded package simulation, and returns `external_action_required`. U-65 and
U-66 back up secret-screened configuration, apply an atomic replacement, record
prior unit state, and automatically restore configuration and unit state after
verification failure. The full automatic domain bridge dispatches these private
adapters after validating their typed inputs and callbacks.

Recoverable U-65 and U-66 plans bind the canonical root device and inode, fixed
rule target and payload, optional backup, and plan through protected checksums.
A completed apply adds the exact target fingerprint and observed unit state.
Cross-process strict rollback requires that applied state. Transition rollback
is limited to retrying an interrupted recovery whose configuration and unit are
each still in a recorded before or after state. Artifact tampering, target
content or inode drift, root drift, and any unrecognized intermediate state
fail closed. U-64 has no rollback entry because the adapter performs no package
mutation.

The checksum inventory is not an external signature, and configuration
replacement plus unit-manager actions are not atomic as one operation. A root
writer can replace both data and checksums, and an interruption or race between
the repeated checks can leave a partial state. The transaction therefore keeps
`rollback_failed` recoverable through an explicit transition retry rather than
claiming crash atomicity.

### Full-profile orchestration boundary

Patcher `--automatic --desired-state FILE` evaluates and orchestrates the
complete 67-criterion profile. Ordinary fixed-rule operations still default to
seven and can select U-62 or U-67 explicitly.

The installed private orchestrator requires a complete 67-row desired-state
profile, complete 67-result pre-scan, canonical root identity, and registered
plan/apply/verify/rollback callback set for every actionable domain. Domain
apply success reaches `awaiting_post_scan`. Only a fresh, different-inode report
containing each U-01 through U-67 result once and only `GOOD` or
`NOT_APPLICABLE` statuses can reach `verified`. Every other result or malformed
report triggers reverse-order rollback.

The orchestrator and domain engines support strict and transition
cross-process rollback. Their checksums and root/object identities reduce stale
or substituted recovery, but do not create a crash-atomic transaction across
account databases, filesystems, service managers, firewalls, and external
systems. A writer able to replace both an artifact and its checksum remains
outside this boundary.

Runtime and external facts must be collected again after the corresponding
change. A pre-patch offline evidence bundle cannot prove post-change listeners,
service activation, package advisory state, running kernel, or reboot state.
A full-67 success claim therefore requires fresh live or post-boot evidence and
a new scan. Missing evidence remains an error rather than an attested `GOOD`.
An external prerequisite stops before mutation with exit status 3 and cannot
become `verified` without a new run.

## Deployment requirements

- Install the public launcher and private files as root-owned package content.
- Keep `/usr/lib/kisa-cce-linux-scanner` and `/usr/share/kisa-cce-linux-scanner` non-writable by unprivileged users.
- Use a local owner-only output directory. Keep automatic transaction parents
  below `/var/lib/kisa-cce-patcher` root-owned and non-writable by group or
  other users.
- Retain patch transactions until post-change verification and the applicable
  rollback window are complete.
- Coordinate patch operations with package managers and configuration
  management to avoid concurrent target replacement or metadata changes.
- Review reports before sharing them.
- Run full scans from a controlled administrative session.
- Validate package installation and live behavior on every listed product and release.

Package signature policy, target-host acceptance, and an independent security review remain outside the current fixture suite.
