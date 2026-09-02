# KISA CCE 2026 Linux Scanner

This project implements the 67 Unix-server criteria in the KISA CCE 2026 profile for:

- Ubuntu Server 26.04 LTS
- Red Hat Enterprise Linux 10.x

The scanner assesses configuration and runtime state without applying remediation. It writes only protected reports and temporary workspace files, and it does not reload services, update package metadata, or contact external hosts.

## Key properties

- Resolves subsystem-specific effective configuration instead of grepping one legacy file.
- Keeps persistent configuration, manager-normalized configuration, and runtime state distinct.
- Uses `MANUAL` and `ERROR` when available evidence cannot justify a conclusive result.
- Produces one text result and one JSONL result for every selected criterion.
- Minimizes collected evidence and applies targeted credential redaction. Reports remain sensitive security data and require controlled handling.
- Supports source-tree execution and relocatable `DESTDIR` package staging.

The criterion reference is published at [KISA CCE 2026 Unix criteria](https://kreonet.github.io/kisa-cce-guide-web/unix/).

## Quick start

Run a complete live scan as root:

```bash
sudo ./bin/kisa-cce-scan
```

Run selected criteria:

```bash
sudo ./bin/kisa-cce-scan --checks U-01,U-02,U-65
```

Inspect an offline filesystem:

```bash
./bin/kisa-cce-scan --root /srv/images/ubuntu-26.04 --no-runtime
```

Explain one sysctl key without changing it:

```bash
sudo ./bin/kisa-cce-scan --explain-sysctl net.ipv4.ip_forward
```

See [Operator usage](docs/usage.md) for privileges, options, reports, result states, and exit codes.

## Documentation

| Document | Contents |
|---|---|
| [Documentation index](docs/README.md) | Documentation map, scope, and sources of truth. |
| [Usage](docs/usage.md) | Live and offline operation, reports, statuses, and automation behavior. |
| [Architecture](docs/architecture.md) | Components, execution flow, resolvers, and reporting pipeline. |
| [Security model](docs/security-model.md) | Trust boundaries, controls, residual risks, and deployment requirements. |
| [Development](docs/development.md) | Check contracts, testing, and release workflow. |
| [Packaging](docs/packaging/README.md) | `DESTDIR` layout and Debian/RPM integration. |

The installed command manual is available as `kisa-cce-scan(8)`.

## Installation staging

```bash
make check
make install DESTDIR="$package_root" prefix=/usr
"$package_root/usr/bin/kisa-cce-scan" --version
```

With `prefix=/usr`, private Bash files are installed under `/usr/lib/kisa-cce-linux-scanner`, runtime data under `/usr/share/kisa-cce-linux-scanner`, and the command manual under `/usr/share/man/man8`. Repository Markdown is not installed by this target.

## Validation

```bash
make check
make lint
```

The local suite verifies 67-result cardinality, report integrity, secret-safety regressions, layered configuration, offline path confinement, and staged installation. Complete runtime acceptance still requires representative Ubuntu 26.04 and RHEL 10 virtual machines.
