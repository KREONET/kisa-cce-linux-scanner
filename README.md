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
- Minimizes collected evidence and applies targeted credential redaction. Reports remain sensitive security data and require controlled handling.
- Shares full-filesystem traversals, batches metadata collection, and caches run-scoped path, command, systemd, procfs process, and listener facts to avoid repeated collection.
- Supports source-tree execution and relocatable `DESTDIR` package staging.
- Provides strict complete mode with typed policy facts, review-bound attestations, and validated runtime evidence bundles.
- Includes `kisa-cce-collect` for capturing live service, listener, mount, firewall, and normalized time-source state before an offline scan.

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

Explain one sysctl key without changing it:

```bash
sudo ./bin/kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

See [Operator usage](docs/operators/usage.md) for privileges, options, reports, result states, and exit codes.

## Documentation

| Document | Contents |
|---|---|
| [Documentation index](docs/README.md) | Documentation map, scope, and sources of truth. |
| [Operator usage](docs/operators/usage.md) | Live and offline operation, reports, statuses, and automation behavior. |
| [Platform support](docs/reference/platform-support.md) | Accepted releases, derivative mapping, and lifecycle sources. |
| [Contributor guide](docs/developers/README.md) | Contributor workflow, review checklist, and macOS container matrix testing. |
| [Packaging](docs/packaging/README.md) | `DESTDIR` layout and Debian/RPM integration. |

The installed command manuals are available as `kisa-cce-scan(8)` and `kisa-cce-collect(8)`.

## Installation staging

```bash
package_root="$(mktemp -d)" || exit 1
make check
make install DESTDIR="$package_root" prefix=/usr
"$package_root/usr/bin/kisa-cce-scan" --version
```

With `prefix=/usr`, private Bash files are installed under `/usr/lib/kisa-cce-linux-scanner`, runtime data and PO catalogs under `/usr/share/kisa-cce-linux-scanner`, and the command manuals under `/usr/share/man/man8`. Repository Markdown is not installed by this target.

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
