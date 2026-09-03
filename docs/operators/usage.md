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

Read the installed command manual with:

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
| `--mode audit\|complete` | Preserves `MANUAL` for review or requires all 67 criteria to reach a final result. |
| `--policy-dir PATH` | Loads strict review attestations and supported typed facts from an absolute directory. Required by complete mode. |
| `--evidence-bundle PATH` | Uses a validated live-runtime directory with an offline root. |
| `--evidence-max-age SEC` | Rejects evidence older than `SEC`; default `3600`, maximum `604800`. |
| `--no-runtime` | Disables live services, listeners, kernel values, and native validators such as `sshd`, `named-checkconf`, `testparm`, and `visudo`. For a live-root scan, local mount topology is still collected to define complete filesystem traversal boundaries. |
| `--explain-sysctl KEY` | Prints the effective persistent and runtime interpretation for one sysctl key instead of producing a CCE report. |
| `--allow-unsupported` | Continues after an unsupported platform warning. |
| `-v`, `--verbose` | Writes platform context, each check code, status, and catalog title, and final counters to standard error. |
| `--debug` | Enables verbose progress and writes structured internal lifecycle, resolver, cache, collection, and report-validation events to standard error. |
| `-h`, `--help` | Prints command help. |
| `--version` | Prints the version read from `data/VERSION` or the installed data directory. |

Options that require values accept both `--option VALUE` and `--option=VALUE`. Empty values are rejected. Positional arguments are rejected. `--checks` and `--explain-sysctl` cannot be combined.

Selected results are always emitted in `data/criteria.tsv` order, not in the order supplied to `--checks`.

One invocation uses one immutable scan epoch. Repeated checks share parse-once
configuration snapshots and one runtime listener snapshot. A new invocation
collects runtime state again; no cache persists across process runs.

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
3. Record approved technical inputs in supported `policy.d/facts/*.tsv` schemas, then record any remaining reviewed `GOOD` or `VULNERABLE` decisions in `policy.d/*.tsv` with a ticket, approver, and expiry date.
4. Run complete mode against the same root and bundle.

Complete mode rejects partial selection, unsupported-platform overrides, live `--no-runtime`, stale bundles, and missing policy input. A technical `MANUAL` with a matching attestation becomes the approved final decision. Missing, expired, or mismatched attestations become `ERROR`. `NOT_APPLICABLE` remains a conclusive final state.

See [Policy format](../reference/policy-format.md) and [Runtime evidence bundle](evidence-bundle.md).

## Reports

Every normal scan produces two files and prints their absolute paths:

```text
[    12.345678] kisa-cce-scan: markdown_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.RANDOM.md
[    12.345679] kisa-cce-scan: jsonl_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.jsonl.RANDOM
```

When `--output-dir` is omitted, a root invocation uses `/var/log/kisa-cce-scanner`; a non-root offline invocation uses `/tmp/kisa-cce-scanner-<uid>`. The hostname component always identifies the machine running the scanner, not the offline image. The randomized suffix prevents predictable-name collisions. Temporary working files remain in a mode-`0700` directory below the output directory and are removed on normal exit and handled signals.

Report paths are printed only after the final summary and integrity checks succeed. If the process is interrupted, partially written report files can remain in the output directory even though their paths were not printed. Treat such files as incomplete.

### Markdown report

The Markdown report contains scanner and platform metadata, followed by one `## U-NN` section for each selected criterion and a final status table. Each result includes its title, category, severity, status, applicability, summary, criterion URL, and optional evidence section.

Dynamic titles and summaries are escaped before entering Markdown. Evidence separators are expanded, tab and carriage-return bytes are rendered as visible escapes, remaining unsafe control bytes are removed or replaced, UTF-8 is normalized when `iconv` is available, and targeted credential redaction is applied before an 8192-byte limit. Every evidence line is indented by four spaces so headings, links, images, tables, and raw HTML from an assessed host remain inert code-block content. JSONL retains the unprefixed normalized value and additionally removes an incomplete UTF-8 suffix created by byte-boundary truncation. An empty value remains present as the JSONL `evidence` string.

### JSONL report

The JSONL report contains one JSON object per selected criterion followed by one summary object. Result objects use these fields:

```json
{"code":"U-01","category":"account","severity":"high","title":"...","status":"GOOD","technical_status":"MANUAL","decision_basis":"policy_attestation","review_id":"sha256:...","attestation_ticket":"SEC-2026-0142","attestation_approver":"security-governance","attestation_expires":"2026-12-31","applicable":true,"summary":"...","evidence":"...","criterion_url":"..."}
```

The final line has `type` set to `summary` and contains all status counts plus `policy_resolved`. Consumers must parse the file as JSON Lines, not as one JSON array.

The JSONL stream does not repeat the scanner, platform, root, runtime-mode, or timestamp header stored in the Markdown report. Retain the Markdown and JSONL files together when those provenance fields are required.

## Result states

| State | Meaning | Operator action |
|---|---|---|
| `GOOD` | Collected evidence conclusively satisfies the implemented criterion. | Retain the report as evidence. |
| `VULNERABLE` | Collected evidence conclusively violates the implemented criterion. | Validate impact and plan remediation. |
| `MANUAL` | Intent, an approved exception, external policy, or unavailable context prevents an automatic decision. | Perform the stated manual review. |
| `NOT_APPLICABLE` | The service or feature is absent and absence was established. | Confirm that non-applicability matches the system role. |
| `ERROR` | Required evidence could not be collected or parsed reliably. | Correct collection access or parser compatibility, then rerun. |

`GOOD` describes the implemented check and collected evidence. It is not a certification of the entire host.

## Exit status

| Status | Condition |
|---:|---|
| `0` | The invocation completed without a process-level failure, and a normal scan recorded no `VULNERABLE` or `ERROR` result. Sysctl explanation mode also returns `0` when its diagnostic completes successfully. |
| `1` | A normal scan completed without a process-level failure and recorded at least one `VULNERABLE` result but no `ERROR` result. |
| `2` | Invocation, platform detection, sysctl diagnosis, collection, report creation or integrity, or at least one criterion produced an error. |

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

- U-64 always requires review of organization policy, the approved baseline date, and vendor advisories. That check performs no advisory fetch or package metadata refresh.
- A live U-15 scan uses the host's configured NSS for owner lookup. External NSS backends may contact their identity service.
- Business necessity, approved exceptions, external identity-provider policy, and retention policy remain manual evidence.
- Stock Enterprise Linux units that defer daemon arguments to unresolved sysconfig variables can produce `MANUAL` for OpenSSH, BIND, or Net-SNMP checks; the scanner does not guess the expanded process arguments.
- Containers do not reproduce all PID 1, socket activation, PAM, authselect, boot-time sysctl, firewall, and device behavior.
- Complete acceptance on every listed product and release is outside the local fixture suite.
