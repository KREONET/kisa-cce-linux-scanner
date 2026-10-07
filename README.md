# KISA CCE 2026 Linux Scanner

KISA CCE 2026 Linux Scanner collects evidence and assesses Linux systems against
all 67 Unix-server criteria in the 2026 Detailed Guide to Technical Vulnerability
Analysis and Assessment for Critical Information Infrastructure (KISA CCE GUIDE).
When the evidence does not support a conclusive result, the scanner reports
`MANUAL` or `ERROR`.

The scanner supports listed releases from these distribution groups:

- Debian and Ubuntu LTS
- Red Hat Enterprise Linux, AlmaLinux, Rocky Linux, Oracle Linux, and CentOS Stream
- Explicitly listed Ubuntu derivatives

The dated [platform support matrix](docs/reference/platform-support.md) lists
the supported releases, lifecycle scope, and exclusions.

## Key properties

- Resolves effective configuration using each subsystem's precedence rules. It distinguishes persistent files, manager-normalized configuration, and runtime state.
- Produces a Markdown report with navigation links and findings ordered by priority, plus one JSONL record per selected criterion in a stable format.
- Classifies unresolved evidence as `technical`, `policy`, `runtime`, or `external` and records remediation eligibility in JSONL.
- Limits collected evidence and redacts recognized credential fields. Reports still contain sensitive security data and require controlled handling.
- Reuses filesystem traversals, collects metadata in batches, and caches path, command, systemd, procfs process, and listener facts for each run.
- Runs from a source checkout or a relocatable installation staged with `DESTDIR`.
- Validates typed policy facts, review-bound attestations, and runtime evidence bundles in complete mode. Automation mode publishes no report if technical, runtime, or external evidence is incomplete or policy evidence is invalid.
- Collects live service, listener, mount, firewall, and normalized time-source state with `kisa-cce-collect` for later offline scans.
- Compiles a restricted YAML policy format into validated TSV files with `kisa-cce-policy-compile`, without a YAML library dependency.

The criterion reference is published at [KISA CCE 2026 Unix criteria](https://kreonet.github.io/kisa-cce-guide-web/unix/).

## Quick start

Run a live audit of all 67 criteria as root:

```bash
sudo ./bin/kisa-cce-scan
```

Run selected criteria:

```bash
sudo ./bin/kisa-cce-scan --checks U-01,U-02,U-65
```

Show progress on standard error:

```bash
sudo ./bin/kisa-cce-scan --verbose
```

Every terminal line uses a dmesg-style prefix, including help, errors, versions,
progress, and result paths. The prefix does not change the automation keys in
the message. Treat verbose output as assessment data: it includes the scan
root, criterion statuses, and aggregate counts.

Inspect an offline filesystem:

```bash
./bin/kisa-cce-scan --root /srv/images/ubuntu-26.04 --no-runtime
```

Capture live runtime evidence before creating an offline image:

```bash
sudo ./bin/kisa-cce-collect \
  --output-dir /var/lib/kisa-cce-evidence/server-20260903T120000Z
```

Run all 67 criteria in complete mode after reviewing the IDs from an audit:

```bash
sudo ./bin/kisa-cce-scan \
  --root /srv/images/ubuntu-26.04 \
  --mode complete \
  --policy-dir /etc/kisa-cce-scanner/policy.d \
  --evidence-bundle /var/lib/kisa-cce-evidence/server-20260903T120000Z
```

Use `--mode automation` with the same policy and runtime-evidence inputs when a
consumer requires a complete result set containing only `GOOD`, `VULNERABLE`,
and `NOT_APPLICABLE`. An unattested policy-class review becomes
`VULNERABLE` with `decision_basis=fail_closed_policy` and is not remediation
eligible. Incomplete technical, runtime, or external evidence becomes `ERROR`;
the run exits with status `2` and publishes no report.

`make install` creates `/etc/kisa-cce-scanner/policy.d/00-default.tsv`. The file
contains no criterion approval. Installed complete and automation runs use that
directory when `--policy-dir` is omitted. Source-tree runs must pass the intended
policy directory explicitly unless the installed default already exists. Add
reviewed attestations and typed facts before expecting complete mode to resolve
policy-class results. In automation mode, a missing policy attestation produces
a fail-closed vulnerability that is not eligible for remediation.

Current review IDs use review-basis schema 2 and bind the result's resolution
class. Review schema 1 attestations must be regenerated from a current audit.

Author policy in YAML, then compile it into a new policy generation:

```bash
install -d -m 0700 ./policy-build
./bin/kisa-cce-policy-compile \
  --input ./examples/policy.yml \
  --output-dir ./policy-build/policy-20260904
```

The compiler accepts the documented YAML subset and validates the generated
files with the scanner's TSV loader. Make the directory root-owned before using
it for a privileged live scan. The scanner reads TSV and requires no YAML library.

Explain one sysctl key without changing it:

```bash
sudo ./bin/kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

Remediation is maintained and installed separately in [KISA CCE Linux Patcher](https://github.com/KREONET/kisa-cce-linux-patcher).

See [Operator usage](docs/operators/usage.md) for privileges, options, reports, result states, and exit codes.

## Documentation

| Document | Contents |
|---|---|
| [Documentation index](docs/README.md) | Guides, scope, and authoritative references. |
| [Operator usage](docs/operators/usage.md) | Live and offline operation, reports, statuses, and automation behavior. |
| [Platform support](docs/reference/platform-support.md) | Accepted releases, derivative mapping, and lifecycle sources. |
| [Contributor guide](docs/developers/README.md) | Contributor workflow, review checklist, and macOS container matrix testing. |
| [Packaging](docs/packaging/README.md) | `DESTDIR` layout and Debian/RPM integration. |
| [Autopatcher](https://github.com/KREONET/kisa-cce-linux-patcher/blob/main/docs/design/autopatcher.md) | Fixed-rule plans, automatic remediation across all 67 criteria, verification, and rollback requirements. |
| [Autopatcher coverage](https://github.com/KREONET/kisa-cce-linux-patcher/blob/main/docs/reference/autopatcher-coverage.md) | Fixed and conditional rules, typed desired state, private domains, and limits of orchestration across all 67 criteria. |

The installed command manuals are available as `kisa-cce-scan(8)`,
`kisa-cce-collect(8)`, and `kisa-cce-policy-compile(8)`.

## Installation staging

```bash
package_root="$(mktemp -d)" || exit 1
make check
make install DESTDIR="$package_root" prefix=/usr
"$package_root/usr/bin/kisa-cce-scan" --version
```

With `prefix=/usr`, private Bash modules are installed by function under
`/usr/lib/kisa-cce-linux-scanner/kisa-cce-*`. Their filenames begin with `_`.
Runtime data and PO catalogs go under `/usr/share/kisa-cce-linux-scanner`, and
manual pages go under `/usr/share/man/man8`. This target does not install the
repository's Markdown files.

## Validation

Use [automated Linux guest tests](docs/developers/test-automation.md) to run the Linux suite through Apple `container` or QEMU.

```bash
make check
make lint
```

The local suite checks platform detection and classification for every matrix
row, distribution-specific configuration behavior, the 67-result count, report
integrity, protection against secret disclosure, layered configuration, offline
path confinement, and staged installation. Runtime acceptance testing is still
required on every listed product and release.

## License

Unless otherwise noted, the original source code and documentation in this
repository are dual-licensed under
[`LGPL-3.0-or-later OR BSD-3-Clause`](LICENSING.md). Recipients may choose either
license. The complete license texts are available in
[LICENSE-LGPL](LICENSE-LGPL),
[GPL-3.0-or-later.txt](LICENSES/gnu/GPL-3.0-or-later.txt), and
[LICENSE-BSD](LICENSE-BSD).

Materials derived from or referring to the KISA CCE GUIDE, including criterion
identifiers, Korean titles, and source links, remain subject to their original
terms. See [NOTICE](NOTICE) for attribution and third-party rights information.
