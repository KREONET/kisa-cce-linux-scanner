# Architecture

## Purpose

The scanner converts host configuration and runtime observations into one
conservative result for each selected KISA CCE 2026 Unix criterion. The scanner
is read-only. The separate configuration and metadata patcher consumes fresh
scanner results and implements a small, explicitly typed remediation boundary.

The implementation separates collection from policy interpretation wherever the effective state depends on multiple configuration files, a service manager, or runtime state. An incomplete collection path must not become a `GOOD` result.

## Component map

| Component | Responsibility |
|---|---|
| `bin/kisa-cce-scan` | Public POSIX launcher. Locates the private main file and starts Bash through a clean environment. |
| `bin/kisa-cce-collect` | Public launcher for the live-runtime evidence collector. |
| `bin/kisa-cce-policy-compile` | Public launcher for strict YAML-to-TSV policy compilation. |
| `bin/kisa-cce-patch` | Public launcher for dry-run, configuration and metadata apply, and guarded rollback operations. |
| `lib/kisa-cce-cli/_scan-main.sh` | Resolves source/installed paths, parses options, validates the catalog, selects the platform, dispatches checks, and finalizes reports. |
| `lib/kisa-cce-cli/_collect-main.sh` | Root-only live evidence collection and bundle finalization. |
| `lib/kisa-cce-cli/_policy-compile-main.sh` | Policy compiler CLI, trusted path handling, canonical validation, and atomic publication. |
| `lib/kisa-cce-cli/_patch-main.sh` | Patcher option parsing, scanner preflight and postflight, transaction publication, and rollback orchestration. |
| `lib/kisa-cce-core/_core.sh` | Rooted filesystem access, trusted-command selection, platform detection, structured debug output, result normalization, report writing, and exit status. |
| `lib/kisa-cce-policy/_policy.sh` | Strict policy-directory loader, typed fact lookup, and review-ID-bound attestation lookup. |
| `lib/kisa-cce-policy/_policy-yaml.sh` | Single-pass parser for the restricted policy YAML authoring schema. |
| `lib/kisa-cce-runtime/_runtime-fallback.sh` | Epoch-scoped procfs process, listener, and PID 1 manager facts for Linux environments without native service tools. |
| `lib/kisa-cce-runtime/_evidence.sh` | Evidence bundle validation, identity binding, and runtime state helpers. |
| `lib/kisa-cce-patcher/_metadata-rules.sh` | Fixed-path and bounded multi-target metadata rule registry. |
| `lib/kisa-cce-patcher/_engine.sh` | Root-confined planning, compare-before-change apply, verification, and metadata rollback engine. |
| `lib/kisa-cce-patcher/_configuration-transaction.sh` | Fixed U-12 and U-62 content payloads, backups, atomic replacement, verification, and rollback. |
| `lib/kisa-cce-patcher/_coverage.sh` | Complete fixed=9, conditional=58, gated=0 remediation contract. |
| `lib/kisa-cce-patcher/_desired-state-policy.sh` | Restricted desired-state v2 YAML compiler and coverage binding. |
| `lib/kisa-cce-patcher/_account-transaction.sh` | Typed account/group and credential-delegation transactions. |
| `lib/kisa-cce-patcher/_pam-transaction.sh` | Debian PAM and RHEL authselect-aware transactions. |
| `lib/kisa-cce-patcher/_inventory-transaction.sh` | Evidence-bound inventory and path-disposition transactions. |
| `lib/kisa-cce-patcher/_filesystem-transaction.sh` | Typed filesystem metadata, content, and removal transactions. |
| `lib/kisa-cce-patcher/_service-transaction.sh` | Unit, socket, process, endpoint, and legacy-service disable transactions. |
| `lib/kisa-cce-patcher/_network-service-transaction.sh` | NFS, RPC, mail, and DNS provider transactions. |
| `lib/kisa-cce-patcher/_edge-service-transaction.sh` | OpenSSH/Telnet, firewall, FTP, and SNMPv3 transactions. |
| `lib/kisa-cce-patcher/_system-transaction.sh` | U-64 package simulation, U-65 time-provider, U-66 logging, and U-67 delegation boundaries. |
| `lib/kisa-cce-patcher/_orchestrator.sh` | Private full-profile domain ordering, verification, post-scan gate, and cross-process rollback. |
| `lib/kisa-cce-patcher/_orchestrator-domains.sh` | Built-in mapping from all-67 requests and domain-input TSV records to child transactions and callbacks. |
| `lib/kisa-cce-core/_i18n.sh` | Dependency-free strict PO parsing and localized report string lookup. |
| `lib/kisa-cce-core/_scan-epoch.sh` | Run-scoped snapshot lifecycle, reverse dependencies, dirtiness, and normalized-output propagation. |
| `lib/kisa-cce-resolvers/_resolvers.sh` | Shared configuration precedence, include traversal, path confinement, sysctl resolution, and systemd state helpers. |
| `lib/kisa-cce-checks/_account-file.sh` | U-01 through U-33 account and filesystem checks. |
| `lib/kisa-cce-checks/_service.sh` | U-34 through U-63 service checks. |
| `lib/kisa-cce-checks/_system.sh` | U-64 through U-67 patch, time, and logging checks. |
| `data/criteria.tsv` | Ordered 67-row criterion catalog and report metadata. |
| `data/VERSION` | Runtime and package version source. |
| `etc/kisa-cce-scanner/policy.d` | Header-only default policy skeleton installed as root-owned configuration. |
| `share/kisa-cce-linux-scanner/locale` | Korean and English report catalogs in a package-specific data path. |
| `tests/run.sh` | Generated-fixture regression suite and staged-installation checks. |
| `Makefile` | Syntax, test, lint, and `DESTDIR` installation entry points. |

## Source and installed layouts

The public launcher supports the development tree directly:

```text
bin/kisa-cce-scan
bin/kisa-cce-collect
bin/kisa-cce-policy-compile
bin/kisa-cce-patch
lib/kisa-cce-checks/_*.sh
lib/kisa-cce-cli/_*.sh
lib/kisa-cce-core/_*.sh
lib/kisa-cce-policy/_*.sh
lib/kisa-cce-resolvers/_*.sh
lib/kisa-cce-runtime/_*.sh
lib/kisa-cce-patcher/_*.sh
data/criteria.tsv
data/VERSION
share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po
etc/kisa-cce-scanner/policy.d/00-default.tsv
```

With `prefix=/usr`, the default installed layout is:

```text
/usr/bin/kisa-cce-scan
/usr/bin/kisa-cce-collect
/usr/bin/kisa-cce-policy-compile
/usr/bin/kisa-cce-patch
/usr/lib/kisa-cce-linux-scanner/kisa-cce-checks/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-cli/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-core/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-policy/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-resolvers/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-runtime/_*.sh
/usr/lib/kisa-cce-linux-scanner/kisa-cce-patcher/_*.sh
/usr/share/kisa-cce-linux-scanner/criteria.tsv
/usr/share/kisa-cce-linux-scanner/VERSION
/usr/share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po
/usr/share/man/man8/kisa-cce-scan.8
/usr/share/man/man8/kisa-cce-collect.8
/usr/share/man/man8/kisa-cce-policy-compile.8
/usr/share/man/man8/kisa-cce-patch.8
```

The main file derives the data directory from its own private-library location. It does not accept a caller-controlled module path. The same relative-prefix rule allows a command inside a `DESTDIR` staging tree to execute before the package is built, provided the command, private library, and data retain one of the supported relative layouts.

## Execution flow

1. The POSIX launcher locates the private Bash main file in the source, private-lib, or supported libexec layout.
2. The launcher selects English reports only for an English `LANG`, otherwise selects the default Korean report catalog, then invokes `/bin/bash` through `/usr/bin/env -i` with a fixed system `PATH`.
3. The main file resolves its data directory and loads the version, strict PO catalog, core, resolvers, and check modules.
4. CLI arguments and `data/criteria.tsv` are validated before collection begins.
5. `/etc/os-release` inside the selected scan root determines the product identity, configuration family, and upstream base release.
6. An offline root disables runtime collection. A live-root scan requires UID 0.
7. Normal scans validate the output path, pin the output directory by file descriptor, create protected report and scratch files through that descriptor, and start one immutable scan epoch. Automation mode stages both reports in the protected scratch directory. Sysctl explanation mode creates only a protected temporary workspace and its own epoch.
8. Catalog rows are read in order. Each `U-NN` row dispatches to `check_u_nn` and produces exactly one result when selected.
9. The scanner appends a summary, verifies report ownership, permissions, record counts, and the pinned output-directory binding, prints both report paths, and returns the aggregate exit status. Automation mode resolves policy-class manual results through attestation or fail-closed vulnerability, rejects incomplete technical, runtime, or external evidence as `ERROR`, validates all 67 results, and moves both staged files through the pinned directory before printing their paths.

When `--debug` is active, the main flow and subsystem resolvers emit schema-versioned events through the central debug API. The option also enables normal verbose progress. Debug records go only to the standard-error descriptor captured when `--debug` is accepted during option parsing; result reports and the standard-output report-path protocol are unchanged. The API percent-encodes dynamic field values and applies per-field and per-event limits before using the normal dmesg-framed console writer. It intentionally exposes normalized operational states rather than shell execution, assessed content, result evidence, or native-command output.

In complete and automation modes, only a policy-class `MANUAL` can use an
attestation. `record_result` computes its SHA-256 review ID from review schema 2
over the full redacted basis before the display-size limit. The basis includes
scanner and platform identity, bundle identity and digest, criterion metadata,
applicability, resolution class, summary, and evidence. A matching unexpired
attestation can resolve only that exact basis. Incomplete technical, runtime,
or external evidence becomes `ERROR` and cannot be overridden. Automation
closes an absent policy attestation to non-actionable `VULNERABLE`; complete
mode treats the same absence as `ERROR`.

An offline evidence bundle is validated and bound to the root by exact `machine-id` and `os-release` matches. Central service, activation, listener, mount, and normalized time-source helpers consume validated bundle state without enabling host command execution against the analysis machine. The validator accepts legacy schema version 1 bundles, while the current collector writes schema version 2 with strict time-synchronization records.

## Patcher flow

The ordinary `kisa-cce-patch` path defaults to a dry run and supports U-12, U-16, U-18,
U-19, U-22, U-29, U-37, U-62, and U-67. U-12 and U-62 use fixed managed
content. U-37 and U-67 produce one transaction row per enumerated target rather
than assuming one path per criterion. The CLI creates a new
protected transaction directory, invokes the scanner for the selected criteria,
and rejects `MANUAL`, `ERROR`, or any
unsupported result before mutation. A vulnerable result must also be technical,
explicitly remediation-eligible, and name the exact expected versioned remediation
rule. Policy fail-closed vulnerabilities cannot enter the patch plan. The
metadata engine resolves fixed paths or bounded criterion inventories below the
selected root without following symbolic links and snapshots
the root identity plus each target's type, device, inode, link count, UID, GID,
mode, size, mtime, and ctime. Regular files also receive a content digest;
directory rows use a no-content sentinel.

`--automatic --desired-state FILE` is a root-only operation over U-01 through
U-67. It rejects `--checks`, requires an exact 67-row schema-version-2 profile,
and implies apply. Without an explicit output path, it creates a protected
unique transaction below `/var/lib/kisa-cce-patcher/transactions` and reports
the transaction through the stable `automatic_status` lifecycle. The ordinary
fixed-rule default remains U-12, U-16, U-18, U-19, U-22, U-29, and U-37.

Apply mode writes the complete transaction before the first change.
When configuration rules are selected, `configuration-plan.tsv` and
`configuration/manifest.tsv` are included in the main checksum inventory. The
configuration manifest binds its backup, payload, and journal data. Apply and
rollback cover both transaction domains.
Every target must still match its snapshot, and every mutation has a typed
postcondition. A new scanner invocation verifies the selected criteria after
apply. Any apply or verification failure triggers a reverse-order rollback.
Manual rollback consumes a protected transaction in an eligible apply or
recovery state and refuses targets whose inode or metadata drifted outside the
recorded before and after states. See
[Autopatcher](autopatcher.md) for the complete contract and its
power-loss limitations.

The private system transaction adapter keeps U-64 package simulation separate
from package mutation and returns `external_action_required`. U-65 and U-66
consume typed approvals through a trusted callback, create provider-specific
configuration and enable/start plans, validate through trusted native and
runtime callbacks, and restore the previous configuration and unit state on
failure. U-67 delegates to `metadata.u67.v1`. Callback executables must be
absolute root-owned files with a non-writable root-owned parent chain. The
public CLI dispatches these entry points only through the full automatic domain
bridge.

U-65 and U-66 persist a checksummed system manifest, plan, payload, optional
backup, lifecycle state, and applied target/unit record below the transaction.
`patch_system_load_transaction` reconstructs only a rule-derived target under
the recorded root. Cross-process strict rollback requires the exact recorded
applied fingerprint. Transition rollback accepts only recorded before/after
states so an interrupted `rollback_failed` transaction can be retried. U-64 is
excluded because package simulation never mutates the root.

The coverage contract contains all 67 criteria as 9 fixed, 58
conditional, and 0 gated rows. Conditional implementations are divided among
account, PAM, inventory, filesystem, service, network-service, edge-service,
and system domains. They require contract-typed desired state, evidence and
risk checks, and trusted callbacks where native, runtime, protocol, credential,
firewall, or external state is outside Bash's direct transaction boundary.

`--automatic --desired-state FILE` invokes the desired-state compiler, which
derives adapter, risk, resolution, domain,
postcondition, validator, and rollback fields from the coverage contract. The
orchestrator then requires a complete 67-row compiled profile and a
complete 67-result scanner JSONL file. It binds both inputs and the root
identity, invokes registered domain plans in fixed order, and rolls back
applied domains in reverse order.

Domain verification advances only to `awaiting_post_scan`. A fresh, distinct
JSONL file must contain every U-01 through U-67 result once and only
`GOOD`/`NOT_APPLICABLE` statuses before the orchestrator records `verified`.
Every other, missing, duplicate, malformed, or reused result causes rollback.
The orchestrator and domain engines also expose guarded cross-process recovery.
The public rollback command detects orchestrator transactions and invokes that
reverse-domain recovery path.

## Platform profiles

Platform authorization uses an explicit product and version allowlist. `ID_LIKE` is recorded but never authorizes an arbitrary derivative. Approved Ubuntu derivatives must also expose the expected `UBUNTU_CODENAME`; CentOS must identify itself as CentOS Stream. The exact lifecycle snapshot is documented in [Platform support](../reference/platform-support.md). The rendered-guide family branches and versioned native adapters are recorded in [KISA platform semantics](../reference/kisa-platform-semantics.md).

The detector assigns `PLATFORM_FAMILY`, `PLATFORM_BASE_ID`, and `PLATFORM_BASE_VERSION` independently from the product's own `ID` and `VERSION_ID`. Checks branch on the configuration family or a versioned capability instead of treating every non-Ubuntu target as RHEL.

## Criterion dispatch contract

The catalog is validated as a tab-separated file with this exact header:

```text
code	category	severity	title
```

The main file requires the exact ordered code range `U-01` through `U-67`. A row such as `U-01` maps to the Bash function `check_u_01`. A missing function, invalid status, or missing result becomes an `ERROR` rather than silently omitting a criterion. A report write failure sets a process-level report error and produces exit status `2`; it does not synthesize another criterion record.

Each check returns through `set_result` with seven logical fields:

```text
status, summary, evidence, applicable, resolution_class,
remediation_eligible, remediation_rule_id
```

`resolution_class` is `technical`, `policy`, `runtime`, or `external`.
Remediation eligibility is valid only for a technical `VULNERABLE` result with
a nonempty versioned rule ID. All other results require `false` and an empty
rule ID. Invalid combinations become `ERROR` at the result boundary.

Allowed statuses are `GOOD`, `VULNERABLE`, `MANUAL`, `NOT_APPLICABLE`, and `ERROR`. Applicability is the JSON boolean `true` or `false`.

## Evidence model

The scanner distinguishes four layers when the subsystem exposes them:

| Layer | Meaning |
|---|---|
| Persistent source | Files intended to survive reboot. |
| Manager-normalized state | The effective interpretation produced by a trusted native parser or service manager. |
| Runtime state | Active units, listeners, loaded kernel values, exported resources, or synchronization state. |
| Typed organization fact | A bounded approved value, owner, ticket, and expiry used as an evaluator input. |

A check may return `GOOD` only when the evidence required by that criterion is conclusive. Live scans prefer trusted native service tools and fall back to process and socket facts from the current procfs namespace when PID 1 is not systemd or `ss` and `pgrep` are unavailable. Ambiguous include graphs, unsupported native syntax, incomplete procfs tables, unavailable runtime state, external policy, and approved exceptions are represented as `MANUAL` or `ERROR` according to whether collection completed reliably.

## Shared filesystem collection

U-15, U-23, U-25, and U-33 share one lazy filesystem snapshot for each scan root, runtime mode, scratch workspace, and criterion selection. The collector resolves the local filesystem roots once and runs one `find -xdev` traversal per root. Live-root scans retain the trusted `findmnt` topology query in static-only mode because mount boundaries define the filesystem evidence scope rather than service or kernel security state. It prunes the current scratch directory and the two report-file inodes so scanner-created artifacts cannot become findings in the same run. Subsequent checks consume cached counts and the first 20 evidence paths without repeating the traversal.

Live collection retains host NSS behavior for U-15 by evaluating `-nouser` and `-nogroup` inside GNU `find`. Offline collection reads numeric UID, GID, type, and mode fields from a NUL-delimited GNU `find -P` metadata stream and compares them with the selected root's validated account databases. Symbolic-link records therefore use the link's own metadata instead of dereferencing the target, and a dangling target does not make the shared inventory incomplete.

All collector records terminate every field with NUL, so whitespace, control characters, and shell metacharacters in pathnames cannot change record boundaries. Evidence paths still pass through the normal display sanitizer. Tests that mutate a fixture after collection call `scanner_reset_full_filesystem_cache` before requesting a new snapshot.

U-67 uses a separate single-pass tagged traversal because its `/var/log` mount scope differs from the general local-filesystem scope. Regular-file and directory metadata comes from the same traversal, while symbolic-link targets retain rooted resolution and their existing policy treatment.

## Execution-cost controls

Hot path helpers return values through caller-supplied variables, avoiding command-substitution subshells while retaining compatibility wrappers for non-hot paths. The scanner caches the canonical scan root and validated native-command locations for one run. Layered sysctl files and PAM files are parsed once per scan epoch. Service facts use an epoch-scoped systemd snapshot when applicable. Procfs process and socket tables are also parsed once per epoch, and every listener query shares one mixed transport snapshot until the next epoch.

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

In a live non-systemd container, the absence of a systemd loader is an established runtime state rather than a loader error. If no trusted `sysctl` command exists, a dot-form key may use an existing regular `/proc/sys` file as a read-only runtime fallback. Filesystem drop-ins remain visible as static evidence but are not reported as applied persistent state without an active loader.

Unexpected loader commands, unsupported service overrides, or supplied `sysctl.extra` credential material prevent a conclusive result. A stock unit declaration that can load `sysctl.extra` is not itself evidence that a credential was supplied. On Debian-family targets, an active UFW `IPT_SYSCTL` source is resolved as an additional network-sysctl layer. `/etc/sysctl.conf.d` is reported as nonstandard and inactive; it is not treated as a standard source directory.

References: [systemd `sysctl.d(5)`](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html), [RHEL 10 kernel parameter management](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

### Other subsystem adapters

- OpenSSH prefers trusted `sshd -T` output and accounts for include position, first-obtained values, `Match` context, units, sockets, and listeners.
- PAM follows recursive `include` and `substack` relationships within the requested PAM facility, Debian-family `common-*` stacks, and Enterprise Linux authselect-managed stacks.
- Password quality combines `pwquality.conf.d`, `pwquality.conf`, and PAM module arguments in their implemented precedence.
- Password history reads `pwhistory.conf` only on platform versions whose PAM implementation supports that file; older supported Debian-family versions require module arguments.
- Password hash assessment combines active shadow identifiers, `login.defs`, and explicit `pam_unix` password-facility hash options. Yescrypt is supported on Debian-family profiles and Enterprise Linux 10 or newer.
- General login-default consumers use legacy last-match semantics on Debian-family and Enterprise Linux 8/9 targets. Enterprise Linux 10 uses libeconf's first main-file value and merged `login.defs.d/*.defs` overrides, including the last duplicate inside a merged drop-in. The `pam_umask` and PAM password-hash paths use their separately versioned native precedence: Enterprise Linux 9 reads libeconf roots from `/usr/share` and `/etc`, while Enterprise Linux 10 reads `/etc` only. PAM hash checks use the selected native value rather than rejecting duplicate definitions as a separate condition.
- systemd inspection includes unit aliases, masks, template and type drop-ins, socket activation, and manager properties.
- sudo inspection detects sudo-rs or traditional sudo. U-63 applies the rendered guide's exact owner and mode requirement to `/etc/sudoers`; provider-specific syntax validation is supplemental and cannot replace that criterion.
- Chrony follows `include`, `confdir`, and `sourcedir`, then checks selected runtime sources when available. NTPsec follows bounded `includefile` graphs and Debian-family `/etc/ntpsec/ntp.d/*.conf` package drop-ins. The optional ntpd-rs adapter parses `/etc/ntpd-rs/ntp.toml`, selects `ntpd-rs.service`, and normalizes `ntp-ctl status`. An active network peer establishes synchronization evidence; reference-clock and dynamic-only sources remain `MANUAL`. U-65 compares the selected provider and source with `facts/time-sources.tsv`; an unexpired exact match can complete the technical `GOOD` path.
- NFS combines `/etc/exports`, `/etc/exports.d/*.exports`, and the active export table when available.
- BIND, Samba, mail, FTP, Net-SNMP, rsyslog, and journald use trusted native validation where implemented and otherwise preserve ambiguity.
- U-31 and U-32 inspect root plus login-capable accounts whose UID is at least
  the effective `UID_MIN` and less than 65534. System and non-login accounts are
  excluded from the home-directory ownership and existence scope.

Ubuntu 26.04 uses sudo-rs as its default sudo provider, while the traditional implementation is exposed separately. See the [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/).

Ubuntu 26.04 continues to use Chrony as its default time daemon. A selected
ntpd-rs installation is an operational extension, not a default-profile
assumption. Canonical targets archive testing in Ubuntu 26.10 and default
adoption in Ubuntu 27.04. See the
[ntpd-rs transition plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154).

## Report pipeline

`set_result` validates the status, applicability, resolution class, remediation
eligibility, and rule ID before dispatch. `record_result` expands evidence
separators and builds control-byte-normalized, UTF-8-normalized working values
through one framed `iconv` call when available. The JSONL result records
`resolution_class`, the `remediation_eligible` boolean, and
`remediation_rule_id`. The Markdown serializer escapes normalized titles and
summaries before placing them in headings or prose. Evidence receives targeted
credential redaction and an 8192-byte limit, renders tab and carriage return as
visible escapes, maps remaining unsafe controls, and is HTML-escaped before
entering a `pre` and `code` container inside a `details` disclosure. Assessed
content therefore cannot terminate the code container or create active Markdown
or HTML structure.

During a normal scan, Markdown criterion sections are written to a protected run-scoped fragment. Separate protected fragments retain linked `ERROR`, `VULNERABLE`, and `MANUAL` index entries in scan order. After all selected checks complete, `write_report_summary` appends the overview, concatenates the three priority fragments in that order, and then appends the detailed criterion fragment. This produces header, overview, priority queue, and detailed-results ordering without retaining complete report content in shell variables. The fragments are removed with the existing protected scratch workspace.

The JSONL serializer and schema are independent from the Markdown presentation path. Its copy retains the unprefixed normalized evidence value and additionally removes an incomplete UTF-8 suffix created at the byte boundary. The Markdown evidence disclosure is omitted when its value is empty. Counters increment only after the criterion fragment, any priority-index entry, and the JSONL record are written successfully.

Before success, `validate_reports` verifies:

- both files are non-empty;
- both files belong to the invoking UID;
- both files have mode `0600`;
- JSONL line count equals result count plus one summary line;
- Markdown result headings match the JSONL criterion codes and recorded result count;
- the Markdown header and status-summary rows occur exactly once with the recorded counts.
- the generated priority links use stable, scanner-controlled `u-nn` anchors rather than title-derived anchors;
- complete mode contains exactly 67 results and zero final `MANUAL` states.
- automation mode publishes only when all 67 `status` and `technical_status` fields are `GOOD`, `VULNERABLE`, or `NOT_APPLICABLE`; policy provenance retains the original manual basis, and a blocked run leaves no report artifact from that invocation.

JSON schema validation is not currently part of the runtime finalization path. The test suite optionally parses JSONL with `jq` when it is installed.

## Design boundaries

- The scanner reads configuration and runtime state but does not remediate it.
- The public patcher installs fixed managed content for U-12 and U-62 and can
  change only the UID and mode of fixed or safely enumerated targets for seven
  metadata criteria. It is not a general configuration engine.
- The private remediation libraries register all 67 rows as 9 fixed and 58
  conditional, with no gated row. The public full automatic path invokes those
  domain engines through the orchestrator and domain bridge.
- Full-67 convergence requires a complete typed profile, trusted callbacks,
  fresh runtime and vendor evidence, completion of external actions, and a
  fresh post-boot scan. Only the private orchestrator's all-GOOD-or-
  NOT_APPLICABLE post-scan gate can record full-profile `verified`.
- It does not reload sysctl, firewall, NFS, or service configuration.
- It does not refresh package metadata or run network-fetch commands. Live U-15 owner lookup uses host NSS, which may consult a configured external identity backend.
- It does not turn organizational policy or approved exceptions into automatic decisions.
- It does not claim support outside the explicit product matrix and its two configuration families.
- It does not replace a platform acceptance test or a qualified security review.

See [Security model](security-model.md) for trust assumptions and residual risks.
