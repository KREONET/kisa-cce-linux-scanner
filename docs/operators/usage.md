# Usage

## Supported targets

The scanner accepts these directly identified base distributions from the target root's `/etc/os-release`:

| Platform | Accepted `ID` | Accepted `VERSION_ID` |
|---|---|---|
| Debian | `debian` | `12`, `13` |
| Ubuntu LTS | `ubuntu` | `22.04`, `24.04`, `26.04` |
| Red Hat Enterprise Linux | `rhel` | `8.10`, `9.8`, `10.2` |

The explicit derivative allowlist covers current AlmaLinux, Rocky Linux, Oracle Linux, CentOS Stream, Linux Mint, Pop!_OS, Zorin OS, elementary OS, and KDE neon User Edition releases. See [Platform support](../reference/platform-support.md) for exact product versions, required Ubuntu base codenames, lifecycle sources, and subscription-only exclusions.

Other platforms are rejected unless `--allow-unsupported` is supplied. That option only bypasses platform rejection; it does not make the collected result authoritative for another distribution. Arbitrary `ID_LIKE` values never authorize an unlisted product.

## Running from the source tree

Run a live audit of all 67 criteria as root:

```bash
sudo ./bin/kisa-cce-scan
```

Run selected criteria:

```bash
sudo ./bin/kisa-cce-scan --checks U-01,U-02,U-65
```

Use a dedicated output directory:

```bash
sudo install -d -m 0700 /var/log/kisa-cce-scanner
sudo ./bin/kisa-cce-scan --output-dir /var/log/kisa-cce-scanner
```

The output directory must be an absolute path with no symbolic-link component. It must belong to the invoking user, grant owner read/write/search access, and grant no group or other permissions. Existing ancestor directories must not be replaceable through an untrusted group- or other-writable path; trusted sticky directories such as `/tmp` and `/var/tmp` remain valid. The scanner creates a missing directory with mode `0700`, opens and pins that directory through a file descriptor, and creates reports with mode `0600` through the pinned directory. It refuses to print report paths if the lexical directory binding changes before finalization.

## Running an installed scanner

The installed command is:

```bash
sudo kisa-cce-scan
```

The installed configuration and metadata remediation command is:

```bash
sudo kisa-cce-patch --output-dir /var/lib/kisa-cce-patcher/change-20260904
```

Read the installed command manual with:

```bash
man 8 kisa-cce-scan
man 8 kisa-cce-patch
```

The installation layout and package staging interface are documented in [Packaging](../packaging/README.md).

## Command options

| Option | Behavior |
|---|---|
| `--root PATH` | Reads an offline filesystem rooted at the absolute `PATH`. Runtime collection is disabled automatically. |
| `--output-dir PATH` | Writes both reports below the absolute `PATH`. |
| `--checks U-01,U-02` | Runs only the comma-separated criterion codes. Input is case-insensitive and duplicate codes are removed. |
| `--mode audit\|complete\|automation` | Preserves `MANUAL`, requires final results, or publishes an all-or-nothing automation report. |
| `--policy-dir PATH` | Overrides the installed default policy directory with an absolute path. Complete and automation modes use `/etc/kisa-cce-scanner/policy.d` when it exists. |
| `--evidence-bundle PATH` | Uses a validated live-runtime directory with an offline root. |
| `--evidence-max-age SEC` | Rejects evidence older than `SEC`; default `3600`, maximum `604800`. |
| `--no-runtime` | Disables live services, procfs processes and listeners, kernel values, and native validators such as `sshd`, `named-checkconf`, `testparm`, and `visudo`. For a live-root scan, local mount topology is still collected to define complete filesystem traversal boundaries. |
| `--explain-sysctl KEY` | Prints the effective persistent and runtime interpretation for one sysctl key instead of producing a CCE report. |
| `--allow-unsupported` | Continues after an unsupported platform warning. |
| `-v`, `--verbose` | Writes platform context, each check code, status, and catalog title, and final counters to standard error. |
| `--debug` | Enables verbose progress and writes structured internal lifecycle, resolver, cache, collection, and report-validation events to standard error. |
| `-h`, `--help` | Prints command help. |
| `--version` | Prints the version read from `data/VERSION` or the installed data directory. |

Options that require values accept both `--option VALUE` and `--option=VALUE`. Empty values are rejected. Positional arguments are rejected. `--checks` and `--explain-sysctl` cannot be combined.

Selected results are always emitted in `data/criteria.tsv` order, not in the order supplied to `--checks`.

U-13 recognizes yescrypt on Debian-family targets and Enterprise Linux 10 or
newer. U-31 and U-32 inspect root plus login-capable accounts whose UID is at
least the effective `UID_MIN` and below 65534. System accounts below that
threshold and accounts using a recognized non-login shell are excluded from
those two home-directory checks.

One invocation uses one immutable scan epoch. Repeated checks share parse-once
configuration snapshots and one runtime listener snapshot. A new invocation
collects runtime state again; no cache persists across process runs.

Live scans prefer trusted `systemctl`, `ss`, and `pgrep` results. When the current PID namespace conclusively has a non-systemd PID 1 or the native listener and process tools are absent, the scanner uses an epoch-scoped procfs fallback. This supports containers and other reduced Linux userspaces without treating tool absence as service absence. Incomplete procfs evidence remains `MANUAL` or `ERROR`.

Every terminal line uses `[    12.345678] kisa-cce-scan: payload`, based on the scanner host's Linux uptime with six fractional digits. A safe process-time or zero fallback is used when `/proc/uptime` is unavailable. This framing applies to help, version, errors, warnings, verbose progress, sysctl explanations, and report paths. Automation keys such as `markdown_report`, `jsonl_report`, and the sysctl `key=value` fields remain unchanged inside the payload. Report paths remain on standard output, so automation can keep progress diagnostics separate by redirecting standard error.

Debug events use `DEBUG: schema=1 event=NAME key=value` payloads. The mode is a diagnostic superset of `--verbose`: it reports scan and criterion lifecycle, scan-epoch state, resolver and collection state, cache decisions, and report validation. It does not enable shell execution tracing, retain temporary files, print result summaries or evidence, or change result states, reports, or exit status. Dynamic field values use percent encoding for bytes outside the documented safe character set and are bounded in length. Native-command output and assessed configuration content are not debug fields.

Debug output is assessment data. It can expose the selected root, platform, criterion activity, subsystem availability, and error state even though raw evidence is excluded. Protect a redirected debug stream with an owner-only umask:

```bash
umask 077
kisa-cce-scan --debug 2>./kisa-cce-debug.log
```

`--debug` is available only on `kisa-cce-scan`; `kisa-cce-collect` does not implement this option. The scanner creates no separate debug file.

CLI help, progress, warning, and error output is always English. Reports are Korean by default. An explicit English `LANG`, such as `en_US.UTF-8`, selects English Markdown titles, summaries, and labels. See [Localization](localization.md).

## Scan modes

| Mode | Invocation | Root required | Runtime evidence |
|---|---|---:|---|
| Live audit, all criteria | `kisa-cce-scan` | Yes | Enabled. |
| Live, static-only | `kisa-cce-scan --no-runtime` | Yes | Disabled. |
| Offline root | `kisa-cce-scan --root /absolute/root` | No | Disabled automatically. |
| Sysctl explanation | `kisa-cce-scan --explain-sysctl KEY` | Yes for the live root | Enabled for a live root unless `--no-runtime` is supplied; disabled for an offline root. |
| Complete live | `kisa-cce-scan --mode complete --policy-dir PATH` | Yes | Current host runtime state. |
| Complete offline | `kisa-cce-scan --root ROOT --mode complete --policy-dir PATH --evidence-bundle PATH` | Bundle owner | Captured bundle state. |
| Automation live | `kisa-cce-scan --mode automation --policy-dir PATH` | Yes | Current host runtime state. |
| Automation offline | `kisa-cce-scan --root ROOT --mode automation --policy-dir PATH --evidence-bundle PATH` | Bundle owner | Captured bundle state. |

Even with `--no-runtime`, scanning `/` requires root. Use an offline root for non-root analysis.

`--root /` still selects the live root and does not create an offline scan boundary.

### Offline example

```bash
./bin/kisa-cce-scan \
  --root /srv/images/ubuntu-26.04 \
  --output-dir /tmp/kisa-cce-offline \
  --checks U-01,U-16,U-65
```

Offline analysis can evaluate persistent files and metadata. It does not require UID 0, but the invoking user still needs read and directory-search access to the selected image. By itself it cannot prove current services, listeners, manager-normalized configuration, loaded sysctl values, or time synchronization. A matching evidence bundle supplies the supported captured runtime facts, including normalized schema version 2 time-source state, without enabling live commands on the analysis host. Unsupported or incomplete runtime distinctions remain `MANUAL`, `NOT_APPLICABLE`, or `ERROR`.

### Complete-mode workflow

1. Run `kisa-cce-collect` on the live host immediately before creating the offline image.
2. Run an audit scan with the matching bundle and review every `MANUAL` result and `review_id`.
3. Record approved typed values in supported `policy.d/facts/*.tsv` schemas,
   then attest only remaining policy-class `GOOD` or `VULNERABLE` decisions in
   `policy.d/*.tsv` with a ticket, approver, and expiry date. Do not attest a
   technical, runtime, or external evidence gap.
4. Run complete mode against the same root and bundle.

Complete mode rejects partial selection, unsupported-platform overrides, live
`--no-runtime`, stale bundles, and missing policy input. Only a policy-class
`MANUAL` can be resolved by a matching attestation. A technical, runtime, or
external `MANUAL` becomes `ERROR` because an approval cannot replace missing
evidence. Missing, expired, or mismatched attestations also become `ERROR`.
`NOT_APPLICABLE` remains a conclusive final state.

The shipped default policy directory is structurally valid but grants no
criterion attestation. It does not create a time-source fact file because an
explicit empty allowlist would change U-65. Administrators must add reviewed
attestations and approved typed facts or use `--policy-dir` with a separately
managed directory. In complete mode an unattested policy review is an error; in
automation mode it is a fail-closed vulnerability that cannot authorize a
patch.

Policies may be authored with the restricted YAML schema and compiled into a new immutable policy generation:

```bash
sudo install -m 0600 ./policy.yml /etc/kisa-cce-scanner/policy.yml
sudo kisa-cce-policy-compile \
  --input /etc/kisa-cce-scanner/policy.yml \
  --output-dir /etc/kisa-cce-scanner/policy-20260904

sudo kisa-cce-scan \
  --mode automation \
  --policy-dir /etc/kisa-cce-scanner/policy-20260904
```

The compiler never replaces an existing directory. It emits the directory path and canonical policy digest only after the generated TSV passes the normal policy loader. See [Policy format](../reference/policy-format.md) for the accepted YAML subset.

Automation mode uses the same platform and evidence preconditions as complete
mode and always evaluates all 67 criteria. It stages reports inside the
protected scan workspace and publishes them only when every final status is
`GOOD`, `VULNERABLE`, or `NOT_APPLICABLE`. Both `status` and
`technical_status` use that three-state set in a published automation report.

A policy-class `MANUAL` with a matching attestation uses the attested decision.
When the attestation is absent, automation records `VULNERABLE` with
`decision_basis=fail_closed_policy`, `remediation_eligible=false`, and an empty
`remediation_rule_id`. This denotes a missing required approval, not permission
to mutate the host. An expired, mismatched, or malformed attestation remains an
error. A technical, runtime, or external `MANUAL` also becomes `ERROR` with an
evidence-incomplete decision basis, because policy cannot replace missing
collection or interpretation.

If any error remains, the command exits with status `2`, prints no report path,
removes the staged files, and leaves the output directory without artifacts
from that invocation. An unattested policy-class result is instead a published
fail-closed vulnerability and therefore normally produces exit status `1`.

See [Policy format](../reference/policy-format.md) and [Runtime evidence bundle](evidence-bundle.md).

## Ubuntu 26.04 time providers

Chrony is the default time daemon on new Ubuntu 26.04 installations. ntpd-rs
is not the 26.04 default, although a package is available for optional
installation. Canonical describes Ubuntu 26.10 archive availability for testing
and Ubuntu 27.04 default adoption as future goals. See the
[Ubuntu Chrony release note](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#chrony),
[Canonical ntpd-rs plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154),
and [Resolute ntpd-rs package](https://packages.ubuntu.com/resolute/ntpd-rs).

U-65 supports an optionally selected ntpd-rs provider as an operational
extension. The scanner parses sources from `/etc/ntpd-rs/ntp.toml`, evaluates
activation and persistence through `ntpd-rs.service`, and obtains live
synchronization state from the trusted `ntp-ctl status` command. A live scan
also requires `ntp-ctl validate -c` to accept the active TOML before the
configuration can contribute to `GOOD`. The parser recognizes `server`,
`pool`, `nts`, and `nts-pool` network sources, including bracketed IPv6
endpoints. The upstream
project documents the same configuration and status interfaces in the
[ntpd-rs repository](https://github.com/pendulum-project/ntpd-rs).

Every reported ntpd-rs network source must match an unexpired
`provider: ntpd-rs` policy fact, and the configured and observed source sets
must agree, before the path can become `GOOD`. Offline scans use a
validated normalized `provider=ntpd-rs` row from `runtime/time-sync.tsv`; they
do not run `ntp-ctl` on the analysis host. Multiple active time providers or
partial runtime evidence remain non-conclusive. The scanner does not install,
enable, stop, or migrate a time daemon.

## Remediation and automatic orchestration

The ordinary dry-run-first `kisa-cce-patch` path supports U-12, U-16,
U-18, U-19, U-22, U-29, U-37, U-62, and U-67. The default set is U-12, U-16,
U-18, U-19, U-22, U-29, and U-37. U-12 installs the fixed managed session
timeout profile. U-62 installs fixed warning text at the three standard banner
paths. Metadata rules preserve existing GIDs and remove excessive permission
bits without granting new bits.

U-37 inventories supported cron and at commands and related files, then records
every target separately in the transaction. U-67 does the same for files and
directories below `/var/log`. U-62 and U-67 are excluded from the default and
require an explicit live-root selection. Offline results cannot establish the
complete active banner or log-mount scope and are not actionable.

Apply the live log metadata rule explicitly:

```bash
sudo kisa-cce-patch \
  --checks U-67 \
  --output-dir /var/lib/kisa-cce-patcher/log-metadata-20260904 \
  --apply
```

Apply the live login-warning rule explicitly:

```bash
sudo kisa-cce-patch \
  --checks U-62 \
  --output-dir /var/lib/kisa-cce-patcher/login-warning-20260904 \
  --apply
```

Create and review a dry-run transaction:

```bash
sudo kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/plan-20260904
```

Apply a new plan explicitly:

```bash
sudo kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/change-20260904 \
  --checks U-12,U-16,U-18,U-19,U-22,U-29,U-37 \
  --apply
```

Run the full 67-criterion automatic workflow:

```bash
sudo kisa-cce-patch \
  --automatic \
  --desired-state /etc/kisa-cce-patcher/desired-state.yml
```

`--automatic` implies apply, requires `--desired-state FILE`, evaluates U-01
through U-67, and requires root even with an offline `--root`. It does not
accept `--checks` or `--rollback`; `--desired-state` is invalid without
`--automatic`. An explicit `--output-dir` remains available. When it is omitted,
the patcher atomically creates a unique protected transaction directory below
`/var/lib/kisa-cce-patcher/transactions`:

```text
/var/lib/kisa-cce-patcher/transactions/transaction-YYYYMMDDTHHMMSSZ.RANDOM
```

Because automatic mode runs as root, the desired-state YAML must be a readable
root-owned, single-linked, non-symlink regular file with no group or other write bit. It is
parsed as data and is never sourced.
The repository's `examples/desired-state-policy-v2.yml` contains only the nine
fixed examples and is not a complete automatic profile.

Missing `kisa-cce-patcher` and `transactions` parents are created root-owned
with mode `0700`. Existing parents must be physical root-owned directories with
no group or other write permission. Automatic mode publishes
`automatic_status=started transaction=PATH`, then
`automatic_status=verified transaction=PATH` only after every domain verifies
and an independent 67-result post-scan contains only `GOOD` and
`NOT_APPLICABLE`. Failure publishes `automatic_status=failed`, possibly before
a transaction exists, exits with status `2`, and attempts guarded reverse-domain
rollback when mutation has started. A successful rollback leaves the
transaction in `rolled_back`; an incomplete rollback leaves `rollback_failed`
for recovery. A verified prerequisite outside the patcher's mutation boundary
publishes `automatic_status=external_action_required prerequisite=VALUE` before
mutation and exits with status `3`.
The `started` and `failed` records use standard error. The final `verified`
record and validated transaction path use standard output.
The mode performs one explicit run; it does not install a daemon, timer, or
retry loop. After an external prerequisite is completed, start a new run with
fresh evidence rather than resuming the incomplete transaction.

For dry-run and manual apply, the output path must be absolute and must not
exist. Its physical parent chain must be trusted and contain no symbolic-link
component. The patcher creates the
directory with mode `0700`; transaction files use mode `0600`. A dry run ends
in `planned` state and never changes the assessed root. An apply transaction is
independent of an earlier dry-run directory: it repeats the scan and all
preflight checks so that an old plan cannot be promoted after its metadata
snapshot becomes stale.

When U-12 or U-62 is selected, the transaction also contains
`configuration-plan.tsv` and `configuration/manifest.tsv`. Their hashes are in
the main `checksums.sha256`; the configuration manifest binds owner-only backup,
payload, and journal files used by apply and rollback.

For an ordinary fixed-rule plan, the preflight scanner runs in audit mode with
verbose progress. Every selected
criterion must produce a conclusive `GOOD`, `VULNERABLE`, or
`NOT_APPLICABLE` result. The patcher verifies that result against its registered
rule plan and completes path, root-identity, target-metadata, and content-digest
checks for the whole plan before changing one target. A vulnerable result is
actionable only when `resolution_class=technical`,
`remediation_eligible=true`, and `remediation_rule_id` names the exact expected
configuration or metadata rule. Policy fail-closed results and every non-actionable result are
rejected. A `MANUAL`, `ERROR`, unsupported criterion, unsafe path, symbolic
link, unsupported object type, hard-linked regular file, or snapshot
disagreement blocks the complete apply. Regular files are bound to their
SHA-256 content digest; directory targets are bound to their type and metadata.

After a fixed-rule apply, a new scanner process evaluates the selected criteria. A remaining
`VULNERABLE`, `MANUAL`, `ERROR`, malformed report, or configuration or metadata
verification failure triggers automatic rollback. Only a transaction whose post-scan,
configuration, and metadata checks completed successfully reaches `verified`
state.

Roll back an eligible apply transaction with:

```bash
sudo kisa-cce-patch \
  --rollback /var/lib/kisa-cce-patcher/change-20260904
```

The same command detects an `orchestrator/` transaction produced by full
automatic mode and invokes guarded cross-process rollback for its applied child
transactions in reverse domain order.

The manifest supplies the original canonical root when `--root` is omitted. An
explicit root must match the recorded path, device, and inode. Manual rollback
accepts verified and interrupted apply or rollback states, but rejects a dry
run, a completed rollback, and a non-recoverable failed state. It also requires
every target to retain its recorded type, inode, size, and mtime. Regular files
must also remain single-linked and match their content digest. A normal
completed apply must match its full post-change state or an already-restored
pre-change state. Interrupted recovery also accepts only bounded combinations
of the recorded before and after UID, GID, and mode.
Other drift blocks the operation. A successful rollback advances the
transaction to `rolled_back`.
Rollback verifies restored metadata but does not create another scanner report;
run `kisa-cce-scan` separately when a post-rollback assessment is required.
The running scanner version must match the transaction manifest. Close the
rollback window before upgrading or retain a trusted matching package artifact.

The patcher always writes dmesg-framed English progress. It has no verbose or
debug option. Automatic-mode lifecycle output uses the stable
`automatic_status` key. Exit status `0` means that the plan, verified apply, or
rollback completed; exit status `2` means invocation, scan, preflight, mutation,
verification, transaction validation, or rollback failed. Exit status `3`
means a verified external prerequisite is required before mutation. SIGINT and SIGTERM
use status `130` and `143` after attempting automatic rollback when an apply is
active.

The ordinary fixed-rule path writes only the U-12 and U-62 managed content. It does not
apply arbitrary content, change groups, reload services, apply runtime settings,
update packages, or resolve organization policy. See
[Autopatcher](../design/autopatcher.md) and
`kisa-cce-patch(8)` for the artifact schema, safety tradeoffs, and rule-expansion
requirements.

The ordinary default remains seven fixed criteria. U-62 and U-67 are the eighth
and ninth fixed rules and require explicit live-root selection. This default is
unrelated to full automatic mode.

## Full-coverage automatic transaction

The library coverage contract has 9 fixed, 58 conditional, and 0 gated rows.
Account, PAM, inventory, filesystem, service, network-service, edge-service,
and system modules implement the conditional transaction
boundaries. Their typed operations can require account decisions, path
dispositions, CIDR/port/protocol allowlists, provider configuration, approved
time sources, logging routes, signed vendor evidence, or trusted native and
runtime callbacks.

`kisa-cce-patch --automatic --desired-state FILE` is the public orchestrated
interface. The desired-state compiler binds each conditional value to the exact
input type, risk, domain, validator, and rollback contract in
`_coverage.sh`. The orchestrator requires a complete 67-row compiled profile
and a complete 67-result pre-scan before it creates domain plans. It applies
registered domains in a fixed order and supports reverse-order automatic and
cross-process rollback.

Domain success is not final success. The orchestrator enters
`awaiting_post_scan` and reaches `verified` only after a fresh, complete scan
reports every U-01 through U-67 result as `GOOD` or `NOT_APPLICABLE`. Any other,
missing, duplicate, or malformed result triggers rollback. An
`external_action_required` transaction state, including U-64 package simulation, must be
completed outside the adapter and followed by a new plan and scan; it is never
treated as verified.

Complex desired-state values name absolute domain-input TSV files. Each file
must be root-owned, mode `0600`, regular, single-linked, and free of symbolic
link, repeated-separator, explicit-dot, or parent path components. The TSV can
carry criterion-specific decisions, referenced evidence files, and trusted
callback paths. Simple values remain restricted single scalars. Neither form is
evaluated as shell code, and plaintext secrets are prohibited.

A completed full apply transaction contains `pre-scan/`, `post-scan/`, and
`orchestrator/{manifest.tsv,manifest.sha256,state,applied.tsv,inputs/,domains/}`.
The domain tree holds protected requests, plans, and child transactions. A
preflight or external-action stop can legitimately have no `post-scan/`.
See [Autopatcher coverage](../reference/autopatcher-coverage.md) for the
schema-version-2 fields, risk ceiling, domain mapping, and input boundary.

An offline pre-patch evidence bundle cannot prove a runtime postcondition after
a service, firewall, package, kernel, or reboot change. Full convergence still
requires current typed inputs, fresh live and vendor evidence, trusted callback
implementations, and a new post-boot scan where applicable.

## Reports

Every audit or complete scan produces two files and prints their absolute paths. A successful automation scan does the same after its publication gate succeeds:

```text
[    12.345678] kisa-cce-scan: markdown_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.RANDOM.md
[    12.345679] kisa-cce-scan: jsonl_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.jsonl.RANDOM
```

When `--output-dir` is omitted, a root invocation uses `/var/log/kisa-cce-scanner`; a non-root offline invocation uses `/tmp/kisa-cce-scanner-<uid>`. The hostname component always identifies the machine running the scanner, not the offline image. The randomized suffix prevents predictable-name collisions. Temporary working files remain in a mode-`0700` directory below the output directory and are removed on normal exit and handled signals.

Report paths are printed only after the final summary and integrity checks succeed. If the process is interrupted, partially written report files can remain in the output directory even though their paths were not printed. Treat such files as incomplete.

Automation reports are written below the protected scratch directory first, then moved into the output directory after result and integrity validation. A blocked automation scan publishes neither file. The two-file publication is rollback-protected but is not a single filesystem transaction; an uncatchable process or host failure during the two renames can leave one file behind without a printed path.

### Markdown report

The Markdown report is organized for incident and remediation review:

1. The report header presents scanner, platform, scan-mode, policy, and evidence-bundle provenance in one metadata table.
2. The overview presents all result counts near the top of the report.
3. The priority index links to results in `ERROR`, `VULNERABLE`, then `MANUAL` order. `GOOD` and `NOT_APPLICABLE` results remain in the detailed results but do not lengthen the review queue.
4. Each `## U-NN` result starts with a final-status callout and its summary, followed by one compact metadata row, the guide reference, and optional evidence.

Evidence is collapsed by default in renderers that support the standard HTML `details` and `summary` elements. The content remains present in the Markdown source and in renderers without interactive disclosure support. Assessed evidence is normalized, redacted, bounded to 8192 bytes, HTML-escaped, and placed in a `pre` and `code` container. Host-provided headings, links, images, tables, and HTML therefore remain inert text. JSONL retains the unprefixed normalized evidence value and additionally removes an incomplete UTF-8 suffix created by byte-boundary truncation. An empty value remains present as the JSONL `evidence` string and omits the Markdown disclosure block.

### JSONL report

The JSONL report contains one JSON object per selected criterion followed by one summary object. Result objects use these fields:

```json
{"code":"U-07","category":"account","severity":"low","title":"...","status":"GOOD","technical_status":"MANUAL","decision_basis":"policy_attestation","review_id":"sha256:...","attestation_ticket":"IAM-2026-0142","attestation_approver":"identity-governance","attestation_expires":"2026-12-31","applicable":true,"summary":"...","evidence":"...","resolution_class":"policy","remediation_eligible":false,"remediation_rule_id":"","criterion_url":"..."}
```

The final line has `type` set to `summary` and contains all status counts plus `policy_resolved`. Consumers must parse the file as JSON Lines, not as one JSON array.

The Markdown readability layout does not change the JSONL field names, order, types, result semantics, or evidence normalization contract. Automation must continue to consume JSONL rather than parse the presentation-oriented Markdown index or tables.

`resolution_class` is `technical`, `policy`, `runtime`, or `external` and
identifies what must resolve an indeterminate result. `remediation_eligible` is
a JSON boolean. It can be `true` only for a technical `VULNERABLE` result with a
nonempty, versioned `remediation_rule_id`. A false value requires an empty rule
ID. Consumers must validate all three fields rather than treating every
`VULNERABLE` result as an executable patch instruction.

| Resolution class | Remaining authority or evidence |
|---|---|
| `technical` | Configuration parsing, native syntax, or another technical interpretation. |
| `policy` | Organization intent, necessity, allowlist, or approved exception. |
| `runtime` | Current service, listener, mount, session, or other live state. |
| `external` | Identity provider, vendor advisory, lifecycle, or another authority outside the scanned host. |

Manual review IDs use canonical review schema 2, represented as
`review_schema:2` in the hashed input. The schema binds `resolution_class` and
the complete redacted basis. It is not an additional JSONL field; review schema
1 attestations must be regenerated from a current audit.

The JSONL stream does not repeat the scanner, platform, root, runtime-mode, or timestamp header stored in the Markdown report. Retain the Markdown and JSONL files together when those provenance fields are required.

## Result states

| State | Meaning | Operator action |
|---|---|---|
| `GOOD` | Technical evidence or a matching policy-class attestation satisfies the implemented criterion. | Retain the decision basis and report as evidence. |
| `VULNERABLE` | Technical evidence violates the criterion, a matching attestation selects that decision, or automation lacks a required policy attestation. | Inspect `decision_basis` and remediation fields before planning any change. |
| `MANUAL` | Intent, an approved exception, external policy, or unavailable context prevents an automatic decision. | Perform the stated manual review. |
| `NOT_APPLICABLE` | The service or feature is absent and absence was established. | Confirm that non-applicability matches the system role. |
| `ERROR` | Required evidence could not be collected or parsed reliably. | Correct collection access or parser compatibility, then rerun. |

`GOOD` describes the implemented check and collected evidence. It is not a certification of the entire host.

## Exit status

| Status | Condition |
|---:|---|
| `0` | The invocation completed without a process-level failure, and a normal scan recorded no `VULNERABLE` or `ERROR` result. Sysctl explanation mode also returns `0` when its diagnostic completes successfully. |
| `1` | A normal scan completed without a process-level failure and recorded at least one `VULNERABLE` result but no `ERROR` result. |
| `2` | Invocation, platform detection, sysctl diagnosis, collection, report creation or integrity, at least one criterion produced an error, or automation publication was blocked by an unresolved result. |

`ERROR` takes precedence over `VULNERABLE`. `MANUAL` and `NOT_APPLICABLE` do not change the exit status by themselves.

An interrupt exits with status `130`; termination exits with status `143`. A signal can arrive before, during, or after the two report-path lines are printed. Paths printed before the signal refer to reports that already passed final integrity checks; unprinted partial reports may also remain after an earlier interruption.

## Explaining sysctl resolution

Use the diagnostic mode to inspect one key:

```bash
sudo kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

The prefixed output retains one `key=value` payload per line. It distinguishes the filesystem model, the active loader model where available, the runtime value, and drift between them. It also reports an observed `sysctl.extra` credential override and the nonstandard `/etc/sysctl.conf.d` directory.

The standard drop-in path is `/etc/sysctl.d/*.conf`. Configuration ordering and masking follow `sysctl.d(5)` semantics, not a recursive grep. See the [systemd sysctl.d specification](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html) and [RHEL 10 kernel parameter documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

This mode does not change kernel parameters and does not create CCE report files.

`--output-dir` must still be an absolute path in sysctl explanation mode, but the scanner does not create or write that directory. The public launcher clears the caller environment, so the diagnostic workspace is created below `/tmp` and removed at exit.

## Operational limitations

- U-64 always requires external vendor and lifecycle evidence that the current
  implementation does not collect. It is external-class `MANUAL` in audit and
  becomes a blocking `ERROR` in complete or automation mode. The check performs
  no advisory fetch or package metadata refresh.
- A live U-15 scan uses the host's configured NSS for owner lookup. External NSS backends may contact their identity service.
- Business necessity, approved exceptions, external identity-provider policy, and retention policy remain manual evidence.
- Stock Enterprise Linux units that defer daemon arguments to unresolved sysconfig variables can produce `MANUAL` for OpenSSH, BIND, or Net-SNMP checks; the scanner does not guess the expanded process arguments.
- Containers do not reproduce all PID 1, socket activation, PAM, authselect, boot-time sysctl, firewall, and device behavior.
- Complete acceptance on every listed product and release is outside the local fixture suite.
