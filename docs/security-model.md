# Security model

## Context

A complete live scan runs as root and reads security-sensitive system state. The scanner therefore treats the execution environment, executable lookup, offline path traversal, report permissions, and evidence content as security boundaries.

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
| Reporting | Invoking-user-owned, non-symlink, owner-only output directory. | Shared, group-accessible, world-accessible, or redirected output paths. |
| Evidence | Minimal normalized summaries and selected values. | Raw files and command output that may contain secrets or control characters. |

## Implemented controls

### Startup environment

The public `#!/bin/sh` launcher locates only known relative module layouts. It starts the private Bash main file through `/usr/bin/env -i`, supplies a fixed `/usr/sbin:/usr/bin:/sbin:/bin` path, and passes only CLI arguments. The Bash process unsets imported functions for commands used by the scanner and sets `umask 077`.

Regression tests set hostile `BASH_ENV` and `ENV` values and verify that the private main file does not load them.

### Trusted live commands

Runtime collection does not use arbitrary caller `PATH` entries. `trusted_command` searches fixed system directories, resolves the candidate where supported, and requires:

- root ownership of the executable;
- no group or other write permission on the executable;
- root ownership of every parent directory;
- no group or other write permission on the parent chain.

Unavailable or untrusted native tools produce conservative collection states instead of invoking another executable with the same name.

The sysctl loader adapter is a narrower special case. It uses the fixed `/usr/lib/systemd/systemd-sysctl` path and validates the executable's root ownership and write mode, but it does not apply `trusted_command`'s complete parent-chain check.

### Offline-root confinement

Logical paths must be absolute and reject newline, carriage-return, tab, and explicit `.` or `..` components. Canonical parent paths must remain below the selected root. Symlink traversal is bounded, absolute symlink targets are interpreted inside the offline root, and escapes or unresolved links fail collection.

Drop-in directory symlinks are also confined. A `/dev/null` link is accepted only where the corresponding subsystem uses it as an explicit mask.

### Read-only assessment

The scanner does not apply fixes, reload daemons, alter firewall rules, export NFS filesystems, refresh package indexes, or modify assessed configuration. Normal scans write only reports and temporary workspace files in the selected output location. If `--output-dir` is deliberately placed below an offline root, those report files are consequently written inside that root. Sysctl explanation mode creates a temporary workspace below `${TMPDIR:-/tmp}` and removes it at exit.

### Report protection

The output parent must not be a symlink. An existing parent must belong to the invoking UID and expose no group or other permissions. New directories and scratch directories use mode `0700`; reports use mode `0600` and randomized names.

Runtime finalization rejects empty reports, wrong ownership, wrong modes, and mismatched result counts.

### Evidence handling

Evidence passes through control-character removal, UTF-8 normalization when available, targeted secret redaction, and an approximately 8 KiB limit. The implemented filters cover common password/hash, SNMP, secret, token, and passphrase forms. Checks are expected to collect the minimum evidence needed for review rather than entire sensitive files.

## Failure policy

Security-relevant uncertainty is explicit:

- `MANUAL` means collection produced useful evidence but intent, policy, an exception, or unavailable context requires a reviewer.
- `ERROR` means required evidence was not collected or interpreted reliably.
- Neither state may be converted to `GOOD` because a file or command was unavailable.
- Any `ERROR` makes the process exit with status `2`, even when vulnerable results also exist.

## Residual risks and limitations

### Installation integrity is assumed

The launcher and main file verify readability and expected relative layout, but they do not verify package signatures, file hashes, ownership, or write permissions for their own modules and `criteria.tsv` before sourcing or reading them. The package manager and filesystem permissions must protect the installation tree.

Do not run the source checkout as root unless the checkout and every parent directory are trusted and protected from untrusted modification.

### Redaction is not data-loss prevention

Targeted patterns cannot identify every possible secret format or sensitive organization-specific value. Review both reports before transferring them outside the assessed environment. Store and transmit reports as sensitive security data.

### A live root process has broad read access

The root requirement enables complete inspection but increases impact if scanner code or a trusted native utility is compromised. Install from a reviewed package or immutable deployment artifact. Do not add runtime plugins or caller-controlled module paths.

### Native parser output remains an input

Trusted commands can still fail, change output across versions, or parse hostile local configuration. The scanner limits command selection and output use, but distribution updates require regression and target-host testing.

### Offline images are snapshots

An offline root may be incomplete, inconsistent, or captured while files were changing. Runtime-disabled results cannot establish the active service or kernel state. Prefer a quiescent snapshot and retain its provenance.

## Deployment requirements

- Install the public launcher and private files as root-owned package content.
- Keep `/usr/lib/kisa-cce-linux-scanner` and `/usr/share/kisa-cce-linux-scanner` non-writable by unprivileged users.
- Use a local owner-only output directory.
- Review reports before sharing them.
- Run full scans from a controlled administrative session.
- Validate package installation and live behavior on both supported platforms.

Package signature policy, target-host acceptance, and an independent security review remain outside the current fixture suite.
