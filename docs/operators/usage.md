# Usage

## Supported targets

The scanner reads `/etc/os-release` in the target root and accepts these base distributions:

| Platform | Accepted `ID` | Accepted `VERSION_ID` |
|---|---|---|
| Debian | `debian` | `12`, `13` |
| Ubuntu LTS | `ubuntu` | `22.04`, `24.04`, `26.04` |
| Red Hat Enterprise Linux | `rhel` | `8.10`, `9.8`, `10.2` |

An explicit allowlist also accepts current releases of AlmaLinux, Rocky Linux, Oracle Linux, CentOS Stream, Linux Mint, Pop!_OS, Zorin OS, elementary OS, and KDE neon User Edition. [Platform support](../reference/platform-support.md) lists the exact versions, required Ubuntu base codenames, lifecycle sources, and subscription-only exclusions.

Other platforms require `--allow-unsupported`. This option bypasses platform rejection without establishing that the results are valid for another distribution. An `ID_LIKE` value cannot authorize a product outside the allowlist.

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

The output path must be absolute and contain no symbolic-link component. The directory must belong to the invoking user, grant that user read, write, and search access, and grant no permissions to anyone else. Its ancestors must not be replaceable through an untrusted group- or other-writable path. Trusted sticky directories such as `/tmp` and `/var/tmp` are allowed. The scanner creates a missing directory with mode `0700`, pins the directory with an open file descriptor, and uses that descriptor to create reports with mode `0600`. It prints no report paths if the path stops referring to the pinned directory before finalization.

## Running an installed scanner

Run the installed scanner with:

```bash
sudo kisa-cce-scan
```

Configuration and metadata remediation is provided by the separately installed
[KISA CCE Linux Patcher](https://github.com/KREONET/kisa-cce-linux-patcher).

Read the scanner manual with:

```bash
man 8 kisa-cce-scan
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

Options with values accept both `--option VALUE` and `--option=VALUE`. Empty values and positional arguments are rejected. `--checks` cannot be combined with `--explain-sysctl`.

Results follow the order in `data/criteria.tsv`, regardless of the order supplied to `--checks`.

U-13 recognizes yescrypt on Debian-family targets and Enterprise Linux 10 or
newer. U-31 and U-32 inspect root plus login-capable accounts whose UID is at
least the effective `UID_MIN` and below 65534. System accounts below that
threshold and accounts using a recognized non-login shell are excluded from
those two home-directory checks.

Each invocation uses one immutable scan epoch. Checks share configuration
snapshots parsed once and a single runtime listener snapshot. Each new
invocation collects runtime state again; caches do not persist across runs.

Live scans prefer results from trusted `systemctl`, `ss`, and `pgrep` commands. The scanner falls back to procfs for the current scan epoch when PID 1 in the current PID namespace is conclusively not systemd or native listener and process tools are absent. This allows scans in containers and other reduced Linux userspaces while keeping missing tools distinct from absent services. Incomplete procfs evidence produces `MANUAL` or `ERROR`.

Every terminal line uses `[    12.345678] kisa-cce-scan: payload`, based on the scanner host's Linux uptime with six fractional digits. A safe process-time or zero fallback is used when `/proc/uptime` is unavailable. This framing applies to help, version, errors, warnings, verbose progress, sysctl explanations, and report paths. Automation keys such as `markdown_report`, `jsonl_report`, and the sysctl `key=value` fields remain unchanged inside the payload. Report paths remain on standard output, so automation can keep progress diagnostics separate by redirecting standard error.

Debug events use `DEBUG: schema=1 event=NAME key=value` payloads. Debug mode includes all `--verbose` output and adds scan and criterion lifecycle events, scan-epoch state, resolver and collection state, cache decisions, and report validation. It does not enable shell execution tracing, retain temporary files, print result summaries or evidence, or change result states, reports, or exit status. Dynamic values have a length limit and percent-encode bytes outside the documented safe character set. Debug fields exclude native-command output and assessed configuration content.

Debug output can expose the selected root, platform, criterion activity, subsystem availability, and error state even though it excludes raw evidence. Handle it as assessment data. Use an owner-only umask when redirecting it:

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

`--root /` selects a live scan, with the same privilege and runtime rules as omitting `--root`.

### Offline example

```bash
./bin/kisa-cce-scan \
  --root /srv/images/ubuntu-26.04 \
  --output-dir /tmp/kisa-cce-offline \
  --checks U-01,U-16,U-65
```

Offline analysis evaluates persistent files and metadata. It does not require UID 0, but the invoking user needs read and directory-search access to the image. Files alone cannot establish current services, listeners, manager-normalized configuration, loaded sysctl values, or time synchronization. A matching evidence bundle supplies supported runtime facts captured from the host, including normalized schema version 2 time-source state. It does not enable live runtime commands on the analysis host. Unsupported or incomplete runtime distinctions remain `MANUAL`, `NOT_APPLICABLE`, or `ERROR`.

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

To author policies in YAML, use the restricted schema and compile it into a new immutable policy directory:

```bash
sudo install -m 0600 ./policy.yml /etc/kisa-cce-scanner/policy.yml
sudo kisa-cce-policy-compile \
  --input /etc/kisa-cce-scanner/policy.yml \
  --output-dir /etc/kisa-cce-scanner/policy-20260904

sudo kisa-cce-scan \
  --mode automation \
  --policy-dir /etc/kisa-cce-scanner/policy-20260904
```

The compiler never replaces an existing directory. It prints the directory path and canonical policy digest only after the normal policy loader accepts the generated TSV. [Policy format](../reference/policy-format.md) describes the accepted YAML subset.

Automation mode uses the same platform and evidence preconditions as complete
mode and always evaluates all 67 criteria. It stages reports inside the
protected scan workspace and publishes them only when every final status is
`GOOD`, `VULNERABLE`, or `NOT_APPLICABLE`. Both `status` and
`technical_status` use that three-state set in a published automation report.

A policy-class `MANUAL` with a matching attestation uses the attested decision.
When the attestation is absent, automation records `VULNERABLE` with
`decision_basis=fail_closed_policy`, `remediation_eligible=false`, and an empty
`remediation_rule_id`. This records a missing required approval and does not
authorize a host change. An expired, mismatched, or malformed attestation remains
an error. A technical, runtime, or external `MANUAL` also becomes `ERROR` with an
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

## Reports

Audit and complete scans produce two report files and print their absolute paths. Automation scans do so only after passing all publication checks:

```text
[    12.345678] kisa-cce-scan: markdown_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.RANDOM.md
[    12.345679] kisa-cce-scan: jsonl_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.jsonl.RANDOM
```

When `--output-dir` is omitted, a root invocation uses `/var/log/kisa-cce-scanner`; a non-root offline invocation uses `/tmp/kisa-cce-scanner-<uid>`. The hostname component always identifies the machine running the scanner, not the offline image. The randomized suffix prevents predictable-name collisions. Temporary working files remain in a mode-`0700` directory below the output directory and are removed on normal exit and handled signals.

Report paths are printed only after the final summary and integrity checks succeed. If the process is interrupted, partially written report files can remain in the output directory even though their paths were not printed. Treat such files as incomplete.

Automation reports are written below the protected scratch directory first, then moved into the output directory after result and integrity validation. A blocked automation scan publishes neither file. The two-file publication is rollback-protected but is not a single filesystem transaction; an uncatchable process or host failure during the two renames can leave one file behind without a printed path.

### Markdown report

The Markdown report has four parts for incident and remediation review:

1. A metadata table records the scanner, platform, scan mode, policy, and evidence-bundle provenance.
2. An overview near the top lists every result count.
3. A priority index links to `ERROR`, `VULNERABLE`, and `MANUAL` results in that order. `GOOD` and `NOT_APPLICABLE` appear in the detailed results only.
4. Each `## U-NN` section begins with the final status and summary, followed by a compact metadata row, guide reference, and optional evidence.

Evidence is collapsed by default in renderers that support the standard HTML `details` and `summary` elements. The content remains present in the Markdown source and in renderers without interactive disclosure support. Assessed evidence is normalized, redacted, bounded to 8192 bytes, HTML-escaped, and placed in a `pre` and `code` container. Host-provided headings, links, images, tables, and HTML therefore remain inert text. JSONL retains the unprefixed normalized evidence value and additionally removes an incomplete UTF-8 suffix created by byte-boundary truncation. An empty value remains present as the JSONL `evidence` string and omits the Markdown disclosure block.

### JSONL report

The JSONL report contains one JSON object per selected criterion followed by one summary object. Result objects use these fields:

```json
{"code":"U-07","category":"account","severity":"low","title":"...","status":"GOOD","technical_status":"MANUAL","decision_basis":"policy_attestation","review_id":"sha256:...","attestation_ticket":"IAM-2026-0142","attestation_approver":"identity-governance","attestation_expires":"2026-12-31","applicable":true,"summary":"...","evidence":"...","resolution_class":"policy","remediation_eligible":false,"remediation_rule_id":"","criterion_url":"..."}
```

The final line has `type` set to `summary` and contains all status counts plus `policy_resolved`. Consumers must parse the file as JSON Lines, not as one JSON array.

The Markdown layout has no effect on JSONL field names, order, types, result semantics, or evidence normalization. Automation must read JSONL; the Markdown index and tables are intended for human review.

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

Manual review IDs use canonical review schema 2. The hashed input includes
`review_schema:2`, `resolution_class`, and the complete redacted review basis.
The schema marker is not a JSONL field. Regenerate review schema 1
attestations from a current audit.

The JSONL stream does not repeat the scanner, platform, root, runtime-mode, or timestamp header stored in the Markdown report. Retain the Markdown and JSONL files together when those provenance fields are required.

## Result states

| State | Meaning | Operator action |
|---|---|---|
| `GOOD` | Technical evidence or a matching policy-class attestation satisfies the implemented criterion. | Retain the decision basis and report as evidence. |
| `VULNERABLE` | Technical evidence violates the criterion, a matching attestation selects that decision, or automation lacks a required policy attestation. | Inspect `decision_basis` and remediation fields before planning any change. |
| `MANUAL` | Intent, an approved exception, external policy, or unavailable context prevents an automatic decision. | Perform the stated manual review. |
| `NOT_APPLICABLE` | The service or feature is absent and absence was established. | Confirm that non-applicability matches the system role. |
| `ERROR` | Required evidence could not be collected or parsed reliably. | Correct collection access or parser compatibility, then rerun. |

`GOOD` applies only to the implemented check and collected evidence. It does not certify the entire host.

## Exit status

| Status | Condition |
|---:|---|
| `0` | The invocation completed without a process-level failure, and a normal scan recorded no `VULNERABLE` or `ERROR` result. Sysctl explanation mode also returns `0` when its diagnostic completes successfully. |
| `1` | A normal scan completed without a process-level failure and recorded at least one `VULNERABLE` result but no `ERROR` result. |
| `2` | Invocation, platform detection, sysctl diagnosis, collection, report creation, or integrity checks failed; at least one criterion produced an error; or an unresolved result blocked automation publication. |

`ERROR` takes precedence over `VULNERABLE`. `MANUAL` and `NOT_APPLICABLE` do not change the exit status by themselves.

An interrupt exits with status `130`; termination exits with status `143`. A signal can arrive before, during, or after the two report-path lines are printed. Paths printed before the signal refer to reports that already passed final integrity checks; unprinted partial reports may also remain after an earlier interruption.

## Explaining sysctl resolution

Use the diagnostic mode to inspect one key:

```bash
sudo kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

Each prefixed output line contains one `key=value` payload. The output distinguishes the filesystem model, active loader model when available, runtime value, and any drift between them. It also reports an observed `sysctl.extra` credential override and the nonstandard `/etc/sysctl.conf.d` directory.

The standard drop-in path is `/etc/sysctl.d/*.conf`. Resolution follows the ordering and masking rules in `sysctl.d(5)`; recursively searching for a key does not reproduce those rules. See the [systemd sysctl.d specification](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html) and [RHEL 10 kernel parameter documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

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
