# Autopatcher coverage contract

`lib/kisa-cce-patcher/_coverage.sh` contains exactly one remediation record for
each criterion from U-01 through U-67. The validated contract currently has:

| Implementation status | Criteria | Meaning |
|---|---:|---|
| `fixed` | 9 | The target state is deterministic and needs no organization-supplied value. |
| `conditional` | 58 | A typed adapter boundary exists, but planning requires the declared input and evidence; every mutating path requires rollback. |
| `gated` | 0 | No criterion is waiting only for an adapter contract. |
| **Total** | **67** | Every scanner criterion has a registered remediation domain and validator. |

The public command has two distinct surfaces. Ordinary dry-run, `--apply`, and
`--checks` dispatch the nine fixed rules; their default selection contains seven
of those rules. `--automatic --desired-state FILE` compiles a complete profile
and dispatches the full 67-row contract through the installed private domain
libraries and orchestrator.

Each coverage row binds a criterion to its adapter, risk level, resolution
requirement, transaction domain, permitted postcondition, implementation
status, typed input, validator, and rollback domain. Validation rejects a
missing or duplicate criterion, duplicate or unknown adapter, invalid enum, or
status that disagrees with the fixed/conditional registry.

## Transaction domains

| Domain module | Criteria | Boundary |
|---|---|---|
| `_configuration-transaction.sh`, `_engine.sh`, `_metadata-rules.sh` | Fixed U-12, U-16, U-18, U-19, U-22, U-29, U-37, U-62, U-67 | Deterministic managed content and bounded metadata changes. |
| `_account-transaction.sh` | U-04, U-05, U-07 through U-11, U-13, U-32, U-55 | Typed account/group decisions, credential-reset boundary, and account-database rollback. |
| `_pam-transaction.sh` | U-02, U-03, U-06 | Debian PAM and RHEL authselect-aware configuration transactions. |
| `_inventory-transaction.sh` | U-14, U-15, U-23, U-26, U-30, U-33 | Evidence-bound path decisions and one-record-per-object recovery. |
| `_filesystem-transaction.sh` | U-17, U-20, U-21, U-24, U-25, U-27, U-31, U-63 | Typed filesystem inventory, metadata/content actions, and guarded rollback. |
| `_service-transaction.sh` | U-34, U-36, U-38, U-41, U-43, U-44, U-52, U-54, U-58 | Explicit legacy-service disable decisions with unit, socket, process, and endpoint verification. |
| `_network-service-transaction.sh` | U-35, U-39, U-40, U-42, U-45 through U-51 | Provider-specific NFS, RPC, mail, and DNS policy; vendor actions remain external where required. |
| `_edge-service-transaction.sh` | U-01, U-28, U-53, U-56, U-57, U-59, U-60, U-61 | OpenSSH/Telnet, firewall, FTP, and SNMPv3 policy with trusted native/runtime callbacks. |
| `_system-transaction.sh` | U-64, U-65, U-66; U-67 delegates to metadata | Signed package simulation, time-provider configuration, and logging configuration. |

An implemented conditional adapter is not unconditional authorization. It can
still return `NOT_APPLICABLE`, reject an incomplete or structurally complex
provider, require live runtime evidence, or stop at
`external_action_required`. In particular, U-64 verifies signed repository and
advisory evidence plus an immutable snapshot/rollback token, then produces a
package-manager simulation. It does not perform a package update.

## Risk and approval boundary

| Level | Mutation boundary |
|---|---|
| R0 | Observation or attestation only. |
| R1 | Bounded deterministic file content or monotonic metadata changes. |
| R2 | Authentication-adjacent or multi-object changes with deterministic rollback. |
| R3 | Service, authorization, or bounded bulk-state changes with operational impact. |
| R4 | Account, package, firewall, or filesystem changes that can remove access or data. |

A desired-state profile sets `max_risk`. Compilation rejects a selected row
above that ceiling. The ceiling constrains a profile; it does not approve a
change. Conditional inputs still need the criterion-specific approval,
evidence, provider, callback, or external-action boundary named by the adapter.

## Desired-state profile schema version 2

Schema version 2 uses a restricted YAML subset:

```yaml
schema_version: 2
profile_id: site-baseline
max_risk: R4
desired_states:
  - code: U-12
    adapter: session_timeout
    postcondition: GOOD
    input_type: none
    input_value: -
  - code: U-28
    adapter: network_access
    postcondition: GOOD
    input_type: network_service_allowlist
    input_value: ssh@192.0.2.0/24
```

The parser accepts ASCII plain scalars only. It rejects aliases, anchors, tags,
quoted values, flow collections, multiline values, control bytes, duplicate
keys, duplicate criteria, and unregistered fields. Values cannot contain
whitespace, tabs, newlines, or shell metacharacters. Fixed adapters require
`input_type: none` and `input_value: -`; each conditional adapter requires its
exact registered input type and a nonempty value.

For the root-only automatic command, the YAML input must use an absolute path
to a readable root-owned, single-linked, non-symlink regular file. Its parent
chain cannot be replaceable by a non-root writer, and the file cannot have a
group or other write bit.

`patch_desired_state_policy_compile` emits a protected TSV whose remaining
fields come from the coverage contract rather than YAML input. Compilation does
not execute the input or invoke an adapter. `kisa-cce-patch --automatic
--desired-state FILE` invokes this compiler internally. The separate
`kisa-cce-policy-compile` command still
compiles scanner policy schema version 1.

The shipped [`desired-state-policy-v2.yml`](../../examples/desired-state-policy-v2.yml)
demonstrates the nine fixed rows and is not by itself a valid automatic
profile. The
[`desired-state-policy-v2-full.yml`](../../examples/desired-state-policy-v2-full.yml)
template contains all 67 coverage rows. Its conditional rows point to one
placeholder domain-input TSV; operators must replace that placeholder with
reviewed, criterion-specific records. The template does not authorize changes
and is not a turnkey remediation policy. Automatic mode also requires a
complete 67-result scanner JSONL input.

## Automatic all-domain orchestration

`kisa-cce-patch --automatic --desired-state FILE` requires effective UID 0,
rejects `--checks` and `--rollback`, and implies apply. The output directory is
optional; omission creates a protected transaction below
`/var/lib/kisa-cce-patcher/transactions`.

The CLI compiles the full profile, runs a fresh 67-result audit, registers the
built-in domain callbacks, and invokes `_orchestrator.sh`. The orchestrator
binds the compiled profile, pre-scan JSONL, canonical root device/inode, domain
order, requests, and plan digests before mutation. Apply runs domains in a fixed
order and rolls back applied domains in reverse order on failure.

After domain verification, the state is `awaiting_post_scan`, not `verified`.
`patch_orchestrator_accept_post_scan` accepts only a fresh, different-inode
JSONL result containing exactly U-01 through U-67 once, with every status equal
to `GOOD` or `NOT_APPLICABLE`. Any `VULNERABLE`, `MANUAL`, `ERROR`, duplicate,
missing, or malformed result triggers guarded rollback. Only that full post-scan
gate reaches `verified`.

The orchestrator and domain engines support protected transaction loading and
cross-process rollback. Strict rollback uses recorded applied state; transition
rollback is limited to bounded interrupted-recovery states. A checksum, root,
target, callback, content, runtime, or provider-state disagreement fails closed.
This is recoverability, not a crash-atomic multi-subsystem commit.

Complex `input_value` entries are absolute paths to root-owned, mode-0600 domain
input TSV files. The loader rejects symbolic links, repeated separators, dot or
parent components, wrong ownership/mode, invalid record types, and callbacks
that fail the owning adapter's trust checks. Simple scalar inputs remain
restricted by the schema-version-2 grammar.

Domain input uses this exact tab-separated header:

```text
schema	criterion	record_type	value_one	value_two	value_three	value_four	value_five	value_six	value_seven	approval
```

Rows use schema `1`. The bridge selects only rows whose criterion matches the
current request and then applies the criterion-specific record cardinality and
field validators. Referenced inventory/evidence files and callback executables
are validated independently; the TSV is never sourced.

If U-64 or another domain prerequisite needs an external action, planning stops
before mutation, emits `automatic_status=external_action_required`, and returns
status 3. The operator must satisfy the prerequisite and start a new full run;
the incomplete transaction is not `verified`.

Full coverage remains conditional. The command must obtain every required
typed input and live or vendor fact, run trusted native callbacks, and use a
fresh post-boot scan when needed. A zero-`gated` table alone is not a convergence
claim.

## Fail-closed filesystem boundaries

The current Bash implementation rejects several object topologies instead of
performing an unsafe pathname mutation:

- U-24 and U-27 targets below a user-writable home directory require a future
  descriptor-based mutation helper.
- U-25 independently verifies the selected root filesystem. A separate
  `/home` or `/var` mount requires a mount-scoped inventory adapter before it
  can be changed automatically.
- U-15 and U-33 automatically handle regular files and directories. Symlinks,
  sockets, devices, and other special objects remain external decisions.
- U-15, U-23, and U-33 require complete mount and filesystem evidence. A
  caller-supplied completeness token cannot authorize an omitted mount root.

These cases return a prerequisite or validation failure before mutation. They
retain typed coverage records so operators can identify the required input
boundary, but they are not unconditional remediation support.
