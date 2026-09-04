# Autopatcher

## Purpose

`kisa-cce-patch` is a narrowly scoped remediation command for deterministic
configuration and file-metadata criteria whose target state does not require
organization policy. It complements `kisa-cce-scan`; it does not replace the
scanner or turn every assessment result into an automatic change.

The remediation coverage contract has 9 `fixed`, 58 `conditional`, and 0
`gated` criteria. This means every U-01 through U-67 row has a typed adapter
contract and validator. Ordinary dry-run, `--apply`, and `--checks` use the nine
fixed rules. The separate public `--automatic --desired-state FILE` path
requires all 67 profile rows and dispatches the conditional domain engines
through the all-domain orchestrator.

Of the nine public rules, U-12 and U-62 install fixed managed
content through a configuration transaction. Five metadata rules use one fixed
file; U-37 and U-67 enumerate bounded target sets. This public path never
changes a group, follows a symbolic link, reloads a service, or applies a
runtime setting.

## Supported rules

| Criterion | Target | Converged state | Absence |
|---|---|---|---|
| U-12 | `/etc/profile.d/99-kisa-cce-session-timeout.sh` | Fixed `TMOUT=600`, readonly and exported; root-owned mode no broader than `0644` | Managed file is created. |
| U-16 | `/etc/passwd` | owner UID 0; mode no broader than `0644` | Preflight error. |
| U-18 | `/etc/shadow` | owner UID 0; mode no broader than `0400` | Scanner reports `VULNERABLE`, but the patcher does not create the file. |
| U-19 | `/etc/hosts` | owner UID 0; mode no broader than `0644` | Preflight error. |
| U-22 | `/etc/services` | root, `bin`, or `sys` owner; vulnerable owners converge to UID 0; mode no broader than `0644` | `NOT_APPLICABLE`; no change. |
| U-29 | `/etc/hosts.lpd` | owner UID 0; mode no broader than `0600` | `GOOD`; no change. |
| U-37 | Cron and at commands and configuration | owner UID 0; commands no broader than `0750` with no set-ID bit; related files no broader than `0640` | No discovered component is `NOT_APPLICABLE`. |
| U-62 | `/etc/issue`, `/etc/issue.net`, `/etc/motd` | Fixed authorization warning; root-owned mode no broader than `0644` | Managed files are created. |
| U-67 | `/var/log` files and directories | owner UID 0; files no broader than `0644`; group and other write removed from directories | Requires an explicit live-root selection. |

The scanner accepts the `bin` and `sys` owners for U-22. A scanner result that
is already `GOOD` is excluded from the transaction and remains unchanged. If a
vulnerable U-22 target is selected, the patch rule converges its owner to root,
which is a stricter scanner-conforming state.
The patch engine resolves the accepted names from the target root's strict
`/etc/passwd` records instead of consulting host NSS. Duplicate or malformed
account records block preflight.

U-37 enumerates the supported cron and at commands, policy files, job
directories, and spool paths without crossing filesystems. U-67 performs a
single-filesystem `/var/log` inventory and can include both files and
directories. Each discovered target receives its own fingerprint and rollback
row. Any enumeration, symlink, hard-link, mount-boundary, or fingerprint error
blocks the whole criterion transaction before mutation.

U-12 and U-62 use a separate configuration manifest inside the same public
transaction. Original files are copied to owner-only backups, fixed payloads
are hashed before use, and each replacement is journaled. Apply verifies the
configuration transaction before the metadata phase. Automatic or manual
rollback restores both domains.

The ordinary fixed-rule default includes U-12 and U-37 and excludes U-62 and
U-67. Those two rules require an explicit fixed-rule live-root selection because
U-62 needs the active banner surface and U-67 needs complete log mount topology.
The full automatic path selects all 67 criteria from its required profile.

Mode remediation is monotonic. The patcher calculates the new mode by masking
the current mode with the rule maximum. It removes excessive permission bits
but never grants a permission that the file did not already have. The existing
group ID is preserved.

## Scanner decision boundary

Scanner JSONL records classify unresolved evidence as `technical`, `policy`,
`runtime`, or `external`. A patchable result must have all of these values:

```text
status=VULNERABLE
resolution_class=technical
remediation_eligible=true
remediation_rule_id=metadata.uNN.v1
```

The rule ID must exactly match the fixed rule registered for the criterion.
The current IDs are `configuration.u12.v1`, `metadata.u16.v1`, `metadata.u18.v1`,
`metadata.u19.v1`, `metadata.u22.v1`, `metadata.u29.v1`,
`metadata.u37.v1`, `configuration.u62.v1`, and `metadata.u67.v1`.
`GOOD` and `NOT_APPLICABLE` records require `remediation_eligible=false` and an
empty rule ID.

Scanner automation mode treats an unattested policy-class manual result as
`VULNERABLE` with `decision_basis=fail_closed_policy`. That result deliberately
remains non-actionable. Technical, runtime, and external manual results become
`ERROR` and block the automation report. The patcher never interprets either
case as permission to mutate the host.

Conditional planning uses a separate desired-state v2 boundary. Each of the 58
conditional rows requires the exact registered `input_type`, a nonempty value,
and the criterion's evidence or approval checks. The protected compiler derives
risk, domain, validator, and rollback fields from `_coverage.sh`; YAML cannot
override them. A typed profile supplies intent, but it does not turn incomplete
technical, runtime, or vendor evidence into `GOOD`.

The
[`desired-state-policy-v2-full.yml`](../../examples/desired-state-policy-v2-full.yml)
file is a compile-valid 67-row template. Its shared domain-input path is a
placeholder for reviewed criterion-specific records, not authorization to
apply the listed remediations.

## Command modes

Manual planning and apply require a new transaction output directory. Without
`--apply`, the command performs a dry run:

```bash
sudo kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/change-20260904
```

Apply the complete validated plan only after reviewing it:

```bash
sudo kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/change-20260904 \
  --apply
```

Fully automatic mode implies apply and runs all 67 criteria from a complete
schema-version-2 desired-state profile:

```bash
sudo kisa-cce-patch \
  --automatic \
  --desired-state /etc/kisa-cce-patcher/desired-state.yml
```

This mode requires effective UID 0, including for an offline `--root`. It does
not accept `--checks` or `--rollback`; `--desired-state` is valid only with
`--automatic`. The profile must contain exactly one row for every U-01 through
U-67 criterion. When `--output-dir` is omitted, the patcher atomically creates
a unique mode-`0700` transaction directory with this shape:

```text
/var/lib/kisa-cce-patcher/transactions/transaction-YYYYMMDDTHHMMSSZ.RANDOM
```

Both parent directories must be physical root-owned directories without group
or other write permission. Missing parents are created with mode `0700`.
`--output-dir` can still select another new trusted path while retaining all
automatic-mode safety gates.

The command emits `automatic_status=started transaction=PATH` after binding the
transaction directory. It performs a complete audit, compiles the profile,
plans and applies the required domains, and runs a second complete audit.
Success requires all 67 post-scan statuses to be `GOOD` or `NOT_APPLICABLE` and
emits `automatic_status=verified transaction=PATH`.

A normal failure emits `automatic_status=failed` and returns status 2. Failure
after mutation invokes guarded reverse-domain rollback. Successful rollback
records `rolled_back`; incomplete rollback records `rollback_failed`. A
verified external prerequisite stops before mutation, emits
`automatic_status=external_action_required prerequisite=VALUE`, and returns
status 3. That state requires a new run after the prerequisite is satisfied.

The `started` and `failed` lifecycle records are diagnostics on standard error.
The final `verified` or `external_action_required` record is written to standard
output with the validated transaction path.

Automatic mode describes one explicitly started command invocation. It does
not install a daemon, watcher, timer, scheduled task, or unattended retry loop.

Restrict the plan to supported criteria with `--checks`:

```bash
sudo kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/passwd-shadow-20260904 \
  --checks U-16,U-18 \
  --apply
```

An absolute `--root` other than `/` selects an offline filesystem. Logical
paths in plans and terminal output remain rooted at `/`; host-side staging paths
are not treated as target identities.

Rollback consumes an eligible transaction directory produced by an apply:

```bash
sudo kisa-cce-patch \
  --root /srv/images/ubuntu-26.04 \
  --rollback /var/lib/kisa-cce-patcher/change-20260904
```

Dry-run and apply are separate invocations. A dry-run directory is not later
promoted in place. This keeps each invocation's preflight snapshot and output
immutable and prevents an operator from applying a stale plan.

## Fixed-rule transaction flow

### Preflight

The command completes all checks before making the first target change:

1. Validate the requested root, new output directory, criterion list, command
   privileges, and fixed rule registry.
2. Run the scanner for the selected criteria and accept only conclusive
   `GOOD`, `VULNERABLE`, and `NOT_APPLICABLE` results with valid resolution and
   remediation fields.
3. Build a plan only from supported rules. `GOOD` and `NOT_APPLICABLE` results
   remain visible but do not become change records.
4. Resolve every target strictly below the selected root. Reject any symbolic
   link component, unsupported object type, hard-linked regular file, unsafe
   parent, or inaccessible metadata.
5. Snapshot the root identity and each target's type, device, inode, link count,
   UID, GID, mode, size, mtime, and ctime. Regular files also receive a SHA-256
   content digest; directories use a fixed no-content sentinel. Capture compares
   stat results around file hashing and rejects any change during collection.
   Recheck every change target immediately before the apply phase.
6. Write the protected plan and, for apply mode, the complete immutable
   transaction payload before changing configuration or metadata.

Preflight is all-or-nothing. An unsupported criterion, unresolved scanner
result, nontechnical or noneligible vulnerability, rule-ID mismatch,
path-safety failure, configuration or metadata drift during planning, or output
failure prevents every target mutation.

### Apply and verification

The apply phase uses compare-before-change semantics. Selected configuration
rules first install only their fixed hashed payloads after validating the
fingerprinted original state. Each metadata target must still match the
recorded type, device, inode, UID, GID, mode, size, mtime, and ctime.
Regular-file content must also match its digest. Metadata rules change the
owner UID while retaining the GID, apply the reduced mode, and verify the exact
final metadata and unchanged file content. Ctime is required to match before
the first metadata mutation; later checks ignore its recorded value because
`chown` and `chmod` update ctime.

After all configuration and metadata operations succeed, the command runs a new scanner process
for the selected criteria. The new invocation provides an independent scan
epoch, so its filesystem facts cannot come from the preflight cache. Every
criterion selected for remediation must reach a scanner-conforming state.

### Automatic rollback

If a precondition, configuration or metadata operation, immediate verification, or post-scan
verification fails after the first mutation, the command attempts to restore
every changed target from the transaction record in reverse order. Automatic
rollback is itself verified. A rollback failure is reported as an error and
requires operator review.

### Manual rollback

Manual rollback validates the transaction schema, scanner version, checksums,
file ownership and mode, eligible recovery state, root identity, fixed rule
mapping, and every recorded target before restoring configuration and metadata. It accepts
`verified`, `applying`, `applied`, `rollback_in_progress`, and
`rollback_failed` so an interrupted apply or rollback remains recoverable. It
rejects `planned`, `rolled_back`, and `failed`.

Configuration recovery validates the configuration manifest, desired payload,
original backup, and apply journal before restoring the fixed U-12 or U-62
managed files. Metadata recovery uses the target checks below.

When `--root` is omitted, the manifest's canonical root is used. An explicit
root must match the recorded path, device, and inode. A target is restorable
only when it has the same target type, device, inode, size, and mtime. Regular
files must also remain single-linked and match their content digest. `applied`
and `verified` transactions additionally require the complete recorded before
or after metadata state. An interrupted transition
can contain a mix of recorded before and after UID, GID, and mode values; only
those bounded combinations are accepted for recovery. A complete before state
is treated as already restored. Any other drift blocks the rollback instead of
overwriting a later administrator or content change.

Rollback repeats target checks while restoring in reverse order. A race after
the all-target preflight can therefore stop a rollback after an earlier target
was restored; the transaction enters `rollback_failed` for operator recovery.
Manual rollback verifies restored metadata but does not run a new scanner.
Run `kisa-cce-scan` after rollback when a fresh assessment record is required.

Configuration rollback restores the fixed-rule files from their fingerprinted
original state, including recorded owner and mode. Metadata-rule rollback
restores only UID, GID, and mode. It does not reconstruct replacement inodes,
timestamps, extended attributes, POSIX ACLs, security labels, or capabilities.
The kernel or filesystem can clear set-ID bits or file capabilities during
`chown`, and `chmod` can change the effective POSIX ACL mask. Those platform
side effects are outside the rollback guarantee.

## Transaction artifacts

The output directory is one transaction generation and must not exist before
the command starts. Its physical parent chain must be trusted and contain no
symbolic-link component. Directories use mode `0700`, and regular artifacts use
mode `0600`. The generation can contain:

| Path | Purpose |
|---|---|
| `manifest.tsv` | Transaction schema, scanner version, selected criteria, and canonical root identity. |
| `plan.tsv` | Every selected rule state, including compliant and non-applicable targets. |
| `metadata.tsv` | Immutable before/after records for targets that can change. |
| `state` | Mutable transaction lifecycle state. |
| `checksums.sha256` | SHA-256 digests for the main manifest, metadata plan and snapshot, and any configuration plan and manifest. |
| `pre-scan/` | Protected Markdown and JSONL reports from the conclusive preflight scan. |
| `post-scan/` | Protected reports from the independent verification scan after apply. |
| `configuration-plan.tsv` | Public U-12/U-62 create-or-replace plan. |
| `configuration/manifest.tsv` | Fingerprinted original state, desired payload, backups, and rollback journal identities. |
| `configuration/{backups,payloads,journal}/` | Owner-only configuration transaction material. |

`metadata.tsv` contains only rows that can change metadata and uses this fixed
TSV schema:

```text
schema criterion state action path root_device root_inode device inode before_uid before_gid before_mode after_uid after_gid after_mode size mtime ctime content_sha256
```

The separators in the actual file are literal tab characters. Change rows use
schema version 2, `state=ready`, and `action=set_metadata`. Size, mtime, ctime,
and `content_sha256` bind a regular-file metadata operation to the content
observed during preflight without storing that content in the transaction.
Directory rows use the all-zero digest sentinel and remain bound by type,
device, inode, size, and mtime. The immutable
payload and its checksums are created before the first mutation. The `state`
value is excluded from those checksums and is replaced atomically as the
transaction progresses through `planned`, `applying`, `applied`, `verified`,
`rollback_in_progress`, `rolled_back`, `failed`, or `rollback_failed`. Only
`verified` is a successfully applied state; `planned` records a dry run.
Automatic rollback success records `rolled_back` while the failed patch command
still exits with status 2. An unsuccessful restoration records
`rollback_failed`. The directory is an input to recovery, not merely an
execution log, and must be protected and retained according to the site's
change-management policy.

The implementation does not claim an atomic multi-file filesystem transaction.
It also does not claim power-loss durability because it does not synchronize
every metadata operation and transaction write to stable storage. A catchable
failure can trigger automatic rollback; `SIGKILL`, kernel failure, storage
failure, or host power loss can leave a partial apply. The prewritten
transaction enables a later guarded manual rollback when inode and metadata
preconditions still match.

## Public fixed-path security properties and tradeoffs

- A dry run is the default. Mutation requires the explicit `--apply` option.
- `--automatic --desired-state FILE` is a separate root-only all-67 mutation
  request. It does not reuse the ordinary seven-rule default.
- Live-root dry runs, all apply operations, and all rollback operations require
  effective UID 0. A readable offline root can be planned without root.
- Target identities are fixed by the rule registry. The command does not accept
  an arbitrary path, UID, GID, or mode from the operator or transaction file.
- Symlinks are rejected rather than followed. Device and inode checks reduce
  time-of-check/time-of-use substitution risk.
- Removing read or execute permission can disrupt software whose undocumented
  behavior relied on excessive access. A scanner-conforming mode is not proof
  that every local integration will continue to work.
- Changing an owner can affect package verification and administrator
  workflows. U-22 deliberately converges a vulnerable owner to root even though
  the scanner also accepts `bin` and `sys` as already conforming owners.
- The transaction contains sensitive filesystem metadata. It uses owner-only
  permissions but is not encrypted or authenticated independently of local
  filesystem controls.
- The transaction checksum detects immutable-payload changes only while the
  owner-only directory remains trusted. A writer that can replace both a file
  and its checksum is outside this integrity boundary.
- Rollback requires the running scanner version to match `scanner_version` in
  the manifest. Complete or expire rollback windows before upgrading, or retain
  a trusted matching package artifact for controlled recovery.
- UID/GID/mode rollback does not preserve an unusual extended ACL, file
  capability, security label, or other auxiliary inode metadata. Review those
  properties separately before applying a rule in an environment that uses
  them on a target file or directory.
- The patcher does not lock package managers or configuration-management tools.
  Snapshot comparison detects observed drift, but cooperating maintenance
  windows remain an operational requirement.

Run the patcher from a trusted, package-managed installation. Protect the
output parent from unprivileged replacement, retain transaction artifacts until
post-change review is complete, and test rollback in the same filesystem and
mount namespace as the original apply.

## Scope boundaries

Ordinary dry-run, `--checks`, and `--apply` do not dispatch conditional account,
PAM, filesystem, inventory, service, firewall, mail, DNS, NFS, SNMP, time,
logging, or package adapters. They remain the nine-rule fixed interface.
Conditional dispatch is available only through `--automatic` with a complete
desired-state v2 profile. The command does not execute policy values as shell
code, schedule remediation, or infer missing organization intent.

No adapter may treat policy input as shell code. Package installation, removal,
and update remain outside direct mutation even in the private U-64 boundary.

## Conditional transaction libraries

The 58 conditional criteria are split by failure domain:

| Private module | Criteria | Primary boundary |
|---|---:|---|
| `_account-transaction.sh` | 10 | Account/group decisions and credential-reset delegation. |
| `_pam-transaction.sh` | 3 | Debian PAM and RHEL authselect-aware changes. |
| `_inventory-transaction.sh` | 6 | Evidence-bound path and object disposition. |
| `_filesystem-transaction.sh` | 8 | File metadata, removal, and managed content. |
| `_service-transaction.sh` | 9 | Explicit service disable with activation and listener checks. |
| `_network-service-transaction.sh` | 11 | NFS, RPC, mail, and DNS provider policy. |
| `_edge-service-transaction.sh` | 8 | OpenSSH/Telnet, firewall, FTP, and SNMPv3 policy. |
| `_system-transaction.sh` | 3 | Package simulation, time synchronization, and logging. |

Together with the nine fixed rules, these rows produce the complete
fixed=9/conditional=58/gated=0 coverage contract. Provider absence can be
`NOT_APPLICABLE`; complex invocation, include, evidence, or runtime state fails
closed before mutation. High-impact operations require typed decisions and,
where applicable, absolute root-owned callback executables with root-owned
non-writable parent chains.

The private `lib/kisa-cce-patcher/_system-transaction.sh` adapter includes these
system boundaries and is dispatched only by the full automatic orchestrator:

- U-64 verifies signed repository and advisory evidence, an external immutable
  snapshot and rollback token, and a trusted package-manager simulation. It
  stops at `external_action_required`; package apply remains an external API.
- U-65 accepts a typed approved source for Chrony, NTPsec,
  systemd-timesyncd, or ntpd-rs, plans persistent configuration and unit
  activation, requires native validation and a fresh runtime probe, and rolls
  back configuration and prior unit state on failure.
- U-66 accepts typed journald persistence or an rsyslog route, uses native
  validation and unit-state verification, and retains configuration and unit
  rollback state.
- U-67 returns the existing `metadata.u67.v1` delegation rather than creating a
  second log-metadata implementation.

All executable callbacks must be absolute root-owned files beneath a root-owned
parent chain without group or other write permission. Raw snapshot and rollback
tokens are not written to plans or artifacts; only their digests are exposed.
The orchestrator copies approved callbacks into the protected transaction before
mutation, so apply and rollback do not reopen the original domain-input path.
Each domain writes `callbacks.tsv`; its digest and each immutable child-plan
digest are bound into the domain plan, which is itself bound into the top-level
manifest. Apply, transaction reload, and rollback recompute those digests before
invoking a callback. U-64 additionally binds the package simulation digest.

The ntpd-rs U-65 payload configures an observable pool with four peers and the
`/run/ntpd-rs/observe` control socket. A single `server` payload is not emitted,
because ntpd-rs requires three agreeing sources by default.

U-65 and U-66 plans write a protected `system/manifest.tsv`, `plan.tsv`, fixed
payload, optional original backup, checksum inventory, and mutable state. A
successful apply also records the exact applied file fingerprint and observed
unit state. `patch_system_load_transaction` validates those artifacts, the
canonical root path and device/inode, and the rule-derived target and payload
before exposing recovery state to another process.

`patch_system_rollback_transaction ROOT DIR strict` accepts only the exact
recorded applied file and unit state. The `transition` mode is reserved for
retrying an interrupted rollback; it accepts only bounded combinations of the
recorded applied and restored configuration and unit states. Drift outside
those states blocks mutation. Restoration is verified, a failed attempt records
`rollback_failed`, and a later transition retry can finish at `rolled_back`.
U-64 is never a rollback target because it stops before package mutation.
Configuration replacement and unit-manager operations are not one atomic
filesystem transaction, so a concurrent change or uncatchable interruption can
still require transition recovery.

The edge-service adapter stages provider-specific OpenSSH, Telnet, nftables,
UFW, firewalld, FTP, and SNMPv3 operations. Firewall changes require a typed
CIDR/port/protocol allowlist, native syntax validation, live protocol checks,
and an out-of-band rollback callback. SNMPv3 plans require `authPriv`, VACM,
source restrictions, and a secret reference; plaintext credentials and the raw
reference are not stored in the transaction. Network-service version criteria
and account credential resets can likewise stop at
`external_action_required` instead of pretending an external action completed.

Every conditional domain exposes a transaction loader and guarded
cross-process rollback. Strict rollback requires the recorded applied state.
Transition rollback exists only for bounded interrupted recovery. Domain
callbacks and transaction artifacts are revalidated before use; unexpected
root, inode, content, provider, runtime, or callback state blocks recovery.

## Full-67 convergence boundary

`kisa-cce-patch --automatic --desired-state FILE` is the public all-67 path.
The earlier seven-rule shortcut no longer exists. Ordinary fixed-rule planning
and apply still default to seven rules and can select U-62 or U-67 explicitly.

Full-67 convergence requires additional typed account, group, path, service,
network-peer, logging, time-source, banner, and patch-lifecycle inputs. The CLI
compiles and dispatches those inputs through the private domain engines and
orchestrator.

`patch_orchestrator_plan` requires a complete 67-row compiled profile and a
complete 67-result pre-scan JSONL file. It binds those inputs, the root identity,
domain requests, and plan digests, then applies registered domain callbacks in
a fixed order. A domain failure rolls back already-applied domains in reverse
order. U-64 returns `external_action_required` after signed evidence and
package-manager simulation; package mutation is never reported as verified by
the adapter.

After a full apply reaches post-scan, the transaction root contains `pre-scan/`,
`post-scan/`, and an
`orchestrator/` directory. The latter contains `manifest.tsv`,
`manifest.sha256`, mutable `state`, `applied.tsv`, protected input copies, and
one request/plan/child-transaction tree per actionable domain. Manual
`--rollback TRANSACTION_DIR` detects this layout and performs reverse-domain
cross-process rollback.

Simple desired-state values use the restricted scalar grammar. Complex domain
input values are absolute paths to root-owned, mode-`0600` TSV files. The
loader rejects symbolic links, repeated separators, explicit dot or parent
components, invalid records, and untrusted callback paths.

Successful domain verification reaches `awaiting_post_scan`. Only a fresh
67-result post-scan in which every criterion is `GOOD` or `NOT_APPLICABLE` can
advance the transaction to `verified`. A remaining `VULNERABLE`, `MANUAL`, or
`ERROR`, or a duplicate, missing, malformed, or reused report, triggers guarded
rollback. Runtime and vendor evidence must be recollected after reload, restart,
package update, or reboot. An offline transaction needs a fresh post-boot scan
before live-state criteria can satisfy the final gate.

An approved exception is not a technical `GOOD`. If an exception leaves a
criterion vulnerable, the full-67 success condition remains unmet.

The conditional profile and evidence boundary is subsystem-specific:

| Domain | Required policy or evidence | Separate action boundary |
|---|---|---|
| Accounts and groups | Name and numeric ID, required disposition, privileged membership, review ticket, approver, and expiry | Locking, membership removal, and deletion require identity-aware rollback and explicit approval. |
| SUID, world-writable, and hidden paths | Exact path, package and content provenance, approved mode or disposition, and expiry | Permission removal, quarantine, or deletion requires one fingerprinted row per path. |
| Root environment and UMASK | Effective shell/PAM/FTP scope and required value | Shell-specific serializers and a fresh session verification are required. |
| Services and network peers | Service necessity, units and sockets, listener scope, approved clients, and health check | Stop, disable, mask, firewall, reload, and restart operations require an availability transaction. |
| Packages and U-64 | Trusted repository snapshot, vendor advisories, lifecycle status, SLA, running kernel, and reboot state | Update, removal, dependency changes, and reboot require a package or host orchestrator. |
| Logging, time, and banners | Required destinations and retention, approved time sources, and approved warning profile | Service reload and live output verification are required. |

Policy states desired intent; it does not manufacture runtime or vendor facts.
Action approval must be bound to the exact plan, profile digest, target identity,
maintenance window, and rollback requirements. These profile schemas and action
engines are private libraries behind the automatic command. Site-specific input
files, trusted callback executables, external actions, and production acceptance
remain operator responsibilities.

## Adding rules

Rule expansion is intentionally code-reviewed rather than data-driven. A new
fixed rule is eligible for the public automatic path only when all of these
conditions hold:

1. The scanner establishes a conclusive vulnerable state from deterministic
   local evidence.
2. The JSONL result is technical, remediation-eligible, and bound to the new
   versioned rule ID.
3. The target object and desired state are fixed by the criterion and platform
   profile; no business intent or free-form value is required.
4. The mutation can be represented in a typed subsystem operation with strict
   preconditions, postconditions, and a bounded rollback record.
5. The operation never interprets policy data as shell code or accepts an
   arbitrary path or command.
6. Fixture tests cover compliant, vulnerable, absent, malformed, symlink,
   hard-link, non-regular, content-drift, concurrent-drift, partial-failure,
   post-scan failure, and both
   automatic and manual rollback paths.
7. The rule is validated in every supported distribution and version
   container, followed by a booted-host test when runtime behavior is involved.

Content edits and service operations require separate subsystem-specific
parsers, serializers, transactional boundaries, and rollback designs. They
must not be added to the metadata engine as untyped text replacement or command
templates.

A conditional rule additionally needs a registered typed input, risk ceiling,
resolution and evidence requirement, domain validator, protected transaction
schema, strict and transition rollback, and focused provider/runtime tests. A
zero-`gated` contract means these registrations exist for the current 67 rows;
it does not waive their inputs or make conditional rows available to ordinary
fixed-rule `--checks`.
