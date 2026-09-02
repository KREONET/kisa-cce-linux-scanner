# Usage

## Supported targets

The scanner accepts these values from the target root's `/etc/os-release`:

| Platform | Accepted `ID` | Accepted `VERSION_ID` |
|---|---|---|
| Ubuntu Server 26.04 LTS | `ubuntu` | `26.04` |
| Red Hat Enterprise Linux 10 | `rhel` | `10` or `10.x` |

Other platforms are rejected unless `--allow-unsupported` is supplied. That option only bypasses platform rejection; it does not make the collected result authoritative for another distribution.

## Running from the source tree

Run a complete live scan as root:

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

The output directory must be an absolute path, must not be a symbolic link, must belong to the invoking user, and must not grant group or other permissions. The scanner creates a missing directory with mode `0700` and creates reports with mode `0600`.

## Running an installed scanner

The installed command is:

```bash
sudo kisa-cce-scan
```

Read the installed command manual with:

```bash
man 8 kisa-cce-scan
```

The installation layout and package staging interface are documented in [Packaging](packaging/README.md).

## Command options

| Option | Behavior |
|---|---|
| `--root PATH` | Reads an offline filesystem rooted at the absolute `PATH`. Runtime collection is disabled automatically. |
| `--output-dir PATH` | Writes both reports below the absolute `PATH`. |
| `--checks U-01,U-02` | Runs only the comma-separated criterion codes. Input is case-insensitive and duplicate codes are removed. |
| `--no-runtime` | Disables live services, listeners, kernel values, and native validators such as `sshd`, `named-checkconf`, `testparm`, and `visudo`. |
| `--explain-sysctl KEY` | Prints the effective persistent and runtime interpretation for one sysctl key instead of producing a CCE report. |
| `--allow-unsupported` | Continues after an unsupported platform warning. |
| `-h`, `--help` | Prints command help. |
| `--version` | Prints the version read from `data/VERSION` or the installed data directory. |

Options that require values accept both `--option VALUE` and `--option=VALUE`. Positional arguments are rejected. `--checks` and `--explain-sysctl` cannot be combined.

Selected results are always emitted in `data/criteria.tsv` order, not in the order supplied to `--checks`.

## Scan modes

| Mode | Invocation | Root required | Runtime evidence |
|---|---|---:|---|
| Live, complete | `kisa-cce-scan` | Yes | Enabled. |
| Live, static-only | `kisa-cce-scan --no-runtime` | Yes | Disabled. |
| Offline root | `kisa-cce-scan --root /absolute/root` | No | Disabled automatically. |
| Sysctl explanation | `kisa-cce-scan --explain-sysctl KEY` | Yes for the live root | Enabled for a live root unless `--no-runtime` is supplied; disabled for an offline root. |

Even with `--no-runtime`, scanning `/` requires root. Use an offline root for non-root analysis.

`--root /` still selects the live root and does not create an offline scan boundary.

### Offline example

```bash
./bin/kisa-cce-scan \
  --root /srv/images/ubuntu-26.04 \
  --output-dir /tmp/kisa-cce-offline \
  --checks U-01,U-16,U-65
```

Offline analysis can evaluate persistent files and metadata. It does not require UID 0, but the invoking user still needs read and directory-search access to the selected image. It cannot prove the current service state, open listeners, manager-normalized configuration, PAM/authselect runtime integration, loaded sysctl values, or current time synchronization. Checks return `MANUAL`, `NOT_APPLICABLE`, or `ERROR` when those distinctions cannot be established safely.

## Reports

Every normal scan produces two files and prints their absolute paths:

```text
text_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.txt.RANDOM
jsonl_report=/var/log/kisa-cce-scanner/kisa-cce-host-YYYYMMDDTHHMMSSZ.jsonl.RANDOM
```

When `--output-dir` is omitted, a root invocation uses `/var/log/kisa-cce-scanner`; a non-root offline invocation uses `/tmp/kisa-cce-scanner-<uid>`. The hostname component always identifies the machine running the scanner, not the offline image. The randomized suffix prevents predictable-name collisions. Temporary working files remain in a mode-`0700` directory below the output directory and are removed on normal exit and handled signals.

Report paths are printed only after the final summary and integrity checks succeed. If the process is interrupted, partially written report files can remain in the output directory even though their paths were not printed. Treat such files as incomplete.

### Text report

The text report contains scanner and platform metadata, one delimited section for each selected criterion, and a final count summary. Each result includes its code, title, category, severity, status, applicability, summary, evidence, and criterion URL.

### JSONL report

The JSONL report contains one JSON object per selected criterion followed by one summary object. Result objects use these fields:

```json
{"code":"U-01","category":"account","severity":"high","title":"...","status":"GOOD","applicable":true,"summary":"...","evidence":"...","criterion_url":"..."}
```

The final line has `type` set to `summary` and contains all status counts. Consumers must parse the file as JSON Lines, not as one JSON array.

The JSONL stream does not repeat the scanner, platform, root, runtime-mode, or timestamp header stored in the text report. Retain the text and JSONL files together when those provenance fields are required.

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
| `0` | No `VULNERABLE` or `ERROR` result was recorded. |
| `1` | At least one `VULNERABLE` result and no `ERROR` result were recorded. |
| `2` | Invocation, platform detection, report integrity, or at least one criterion produced an error. |

`ERROR` takes precedence over `VULNERABLE`. `MANUAL` and `NOT_APPLICABLE` do not change the exit status by themselves.

An interrupt exits with status `130`; termination exits with status `143`. These signal exits occur before the scanner prints validated report paths.

## Explaining sysctl resolution

Use the diagnostic mode to inspect one key:

```bash
sudo kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

The output distinguishes the filesystem model, the active loader model where available, the runtime value, and drift between them. It also reports an observed `sysctl.extra` credential override and the nonstandard `/etc/sysctl.conf.d` directory.

The standard drop-in path is `/etc/sysctl.d/*.conf`. Configuration ordering and masking follow `sysctl.d(5)` semantics, not a recursive grep. See the [systemd sysctl.d specification](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html) and [RHEL 10 kernel parameter documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-at-runtime).

This mode does not change kernel parameters and does not create CCE report files.

`--output-dir` has no effect in sysctl explanation mode. Its temporary workspace is created below `${TMPDIR:-/tmp}` and removed at exit.

## Operational limitations

- U-64 always requires review of organization policy, the approved baseline date, and vendor advisories. The scanner performs no network access or package metadata refresh.
- Business necessity, approved exceptions, external identity-provider policy, and retention policy remain manual evidence.
- Containers do not reproduce all PID 1, socket activation, PAM, authselect, boot-time sysctl, firewall, and device behavior.
- Complete acceptance on representative Ubuntu 26.04 and RHEL 10 virtual machines is outside the local fixture suite.
