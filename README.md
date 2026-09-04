# KISA CCE 2026 Linux Scanner

KISA CCE 2026 Linux Scanner is a Linux security assessment tool based on the
**Detailed Guide to Technical Vulnerability Analysis and Assessment for
Critical Information Infrastructure** (hereafter, the **KISA CCE GUIDE**). It
automates evidence collection and conservative assessment for all 67
Unix-server criteria defined in the 2026 guide.

Assessment support is limited to explicitly listed releases in these platform
groups:

- Debian and Ubuntu LTS
- Red Hat Enterprise Linux, AlmaLinux, Rocky Linux, Oracle Linux, and CentOS Stream
- Explicitly listed Ubuntu derivatives

See the dated [platform support matrix](docs/reference/platform-support.md) for the exact
supported releases, lifecycle scope, and exclusions.

## Key properties

- Resolves subsystem-specific effective configuration instead of grepping one legacy file.
- Keeps persistent configuration, manager-normalized configuration, and runtime state distinct.
- Uses `MANUAL` and `ERROR` when available evidence cannot justify a conclusive result.
- Produces a linked, priority-oriented Markdown report and one stable JSONL result for every selected criterion.
- Classifies unresolved evidence as `technical`, `policy`, `runtime`, or `external` and exposes explicit remediation eligibility in JSONL.
- Minimizes collected evidence and applies targeted credential redaction. Reports remain sensitive security data and require controlled handling.
- Shares full-filesystem traversals, batches metadata collection, and caches run-scoped path, command, systemd, procfs process, and listener facts to avoid repeated collection.
- Supports source-tree execution and relocatable `DESTDIR` package staging.
- Provides strict complete mode with typed policy facts, review-bound attestations, and validated runtime evidence bundles.
- Provides all-or-nothing scanner automation mode that publishes no report when incomplete technical, runtime, external, or invalid-policy evidence remains.
- Includes `kisa-cce-collect` for capturing live service, listener, mount, firewall, and normalized time-source state before an offline scan.
- Includes `kisa-cce-policy-compile` for converting a restricted, dependency-free YAML authoring format into validated scanner TSV policy files.
- Includes a dry-run-first `kisa-cce-patch` command for two deterministic configuration rules and seven file-metadata rules, including multi-target cron and log rules.
- Provides an explicit `--automatic --desired-state FILE` mode that evaluates all 67 criteria, dispatches typed domain transactions, and retains protected recovery state.
- Registers the remediation contract as 9 fixed and 58 conditional rules, with no gated row.

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

Show progress on standard error. Every terminal line, including help, errors,
versions, progress, and result paths, uses a consistent dmesg-style prefix.
Automation keys remain unchanged inside the payload. Treat verbose output as
assessment data because it includes the scan root, criterion statuses, and
aggregate counts:

```bash
sudo ./bin/kisa-cce-scan --verbose
```

Inspect an offline filesystem:

```bash
./bin/kisa-cce-scan --root /srv/images/ubuntu-26.04 --no-runtime
```

Capture live runtime evidence before creating an offline image:

```bash
sudo ./bin/kisa-cce-collect \
  --output-dir /var/lib/kisa-cce-evidence/server-20260903T120000Z
```

Run all 67 criteria in complete mode after reviewing the audit review IDs:

```bash
sudo ./bin/kisa-cce-scan \
  --root /srv/images/ubuntu-26.04 \
  --mode complete \
  --policy-dir /etc/kisa-cce-scanner/policy.d \
  --evidence-bundle /var/lib/kisa-cce-evidence/server-20260903T120000Z
```

Use `--mode automation` with the same policy and runtime-evidence inputs when a
machine consumer must receive only a complete set of `GOOD`, `VULNERABLE`, and
`NOT_APPLICABLE` final statuses. An unattested policy-class review closes to
`VULNERABLE` with `decision_basis=fail_closed_policy` and is not remediation
eligible. Incomplete technical, runtime, or external evidence becomes `ERROR`;
the run exits with status `2` and publishes no report.

`make install` creates `/etc/kisa-cce-scanner/policy.d/00-default.tsv`. The file
contains no criterion approval. Installed complete and automation runs use that
directory when `--policy-dir` is omitted. Source-tree runs must pass the intended
policy directory explicitly unless the installed default already exists. Add
reviewed attestations and typed facts before expecting complete mode to resolve
policy-class results. Automation mode instead publishes an absent policy
attestation as a non-actionable fail-closed vulnerability.

Current review IDs use review-basis schema 2 and bind the result's resolution
class. Review schema 1 attestations must be regenerated from a current audit.

Author policy in YAML, then compile it into a new policy generation:

```bash
install -d -m 0700 ./policy-build
./bin/kisa-cce-policy-compile \
  --input ./examples/policy.yml \
  --output-dir ./policy-build/policy-20260904
```

The compiler accepts only the documented policy YAML subset and validates its output through the canonical TSV loader. Deploy the generated directory as root-owned configuration before using it for a privileged live scan. The scanner runtime continues to consume TSV and gains no YAML dependency.

Explain one sysctl key without changing it:

```bash
sudo ./bin/kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

Review a remediation plan before explicitly applying it:

```bash
sudo ./bin/kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/change-20260904

sudo ./bin/kisa-cce-patch \
  --output-dir /var/lib/kisa-cce-patcher/change-20260904-apply \
  --apply
```

The public patcher supports U-12, U-16, U-18, U-19, U-22, U-29, U-37, U-62,
and U-67. The default set omits U-62 and U-67; both require an explicit
live-root selection. U-12 and U-62 install deterministic managed content, while
the other rules change owner UID and permission bits. Configuration and
metadata changes share one checksummed rollback transaction and are verified by
a new scan. The patcher does not reload services or apply arbitrary content.
See the
[autopatcher design](docs/design/autopatcher.md).

The complete coverage contract is fixed=9, conditional=58, gated=0. Account,
PAM, filesystem, inventory, service, network-service, edge-service, and system
transaction modules implement the conditional domain boundaries. The public
full-coverage mode binds a complete desired-state v2 profile, complete pre-scan,
root identity, ordered domain plans, and cross-process rollback.

Run the all-67 automatic workflow without selecting a transaction path
manually:

```bash
sudo ./bin/kisa-cce-patch \
  --automatic \
  --desired-state /etc/kisa-cce-patcher/desired-state.yml
```

Automatic mode is root-only and atomically creates a protected transaction below
`/var/lib/kisa-cce-patcher/transactions`. The profile must contain exactly one
schema-version-2 desired state for every U-01 through U-67 criterion. Automatic
mode reaches `verified` only after a fresh 67-result post-scan reports every
criterion as `GOOD` or `NOT_APPLICABLE`.

The shipped `examples/desired-state-policy-v2.yml` demonstrates only the nine
fixed rows. It must not be passed to full automatic mode as an all-67 profile.
Use [`examples/desired-state-policy-v2-full.yml`](examples/desired-state-policy-v2-full.yml)
as the compile-valid 67-row template, then replace its domain-input path with
reviewed site data before installation.

The full workflow still requires all typed organization inputs, trusted
callbacks, fresh live and vendor evidence, and post-boot verification where
applicable. A verified external prerequisite such as U-64 package action stops
before mutation with `automatic_status=external_action_required` and exit
status 3; it is never treated as successful remediation.

See [Operator usage](docs/operators/usage.md) for privileges, options, reports, result states, and exit codes.

## Documentation

| Document | Contents |
|---|---|
| [Documentation index](docs/README.md) | Documentation map, scope, and sources of truth. |
| [Operator usage](docs/operators/usage.md) | Live and offline operation, reports, statuses, and automation behavior. |
| [Platform support](docs/reference/platform-support.md) | Accepted releases, derivative mapping, and lifecycle sources. |
| [Contributor guide](docs/developers/README.md) | Contributor workflow, review checklist, and macOS container matrix testing. |
| [Packaging](docs/packaging/README.md) | `DESTDIR` layout and Debian/RPM integration. |
| [Autopatcher](docs/design/autopatcher.md) | Fixed-rule planning, all-67 automatic apply, verification, and rollback safety contract. |
| [Autopatcher coverage](docs/reference/autopatcher-coverage.md) | Fixed/conditional contract, typed desired state, private domains, and all-67 orchestration boundary. |

The installed command manuals are available as `kisa-cce-scan(8)`,
`kisa-cce-collect(8)`, `kisa-cce-policy-compile(8)`, and
`kisa-cce-patch(8)`.

## Installation staging

```bash
package_root="$(mktemp -d)" || exit 1
make check
make install DESTDIR="$package_root" prefix=/usr
"$package_root/usr/bin/kisa-cce-scan" --version
```

With `prefix=/usr`, private Bash files are grouped by function under `/usr/lib/kisa-cce-linux-scanner/kisa-cce-*`; every private filename begins with `_`. Runtime data and PO catalogs are installed under `/usr/share/kisa-cce-linux-scanner`, and command manuals under `/usr/share/man/man8`. Repository Markdown is not installed by this target.

## Validation

```bash
make check
make lint
```

The local suite verifies detection and classification for every platform row, family-specific semantic fixtures, 67-result cardinality, report integrity, secret-safety regressions, layered configuration, offline path confinement, and staged installation. Complete runtime acceptance still requires every listed product and release.

## License

Unless otherwise noted, the original source code and documentation in this
repository are dual-licensed under
[`LGPL-3.0-or-later OR BSD-3-Clause`](LICENSE). Recipients may choose either
license. The complete license texts are available in
[LGPL-3.0-or-later.txt](LICENSES/LGPL-3.0-or-later.txt),
[GPL-3.0-or-later.txt](LICENSES/GPL-3.0-or-later.txt), and
[BSD-3-Clause.txt](LICENSES/BSD-3-Clause.txt).

Materials derived from or referring to the KISA CCE GUIDE, including criterion
identifiers, Korean titles, and source links, remain subject to their original
terms. See [NOTICE](NOTICE) for attribution and third-party rights information.
