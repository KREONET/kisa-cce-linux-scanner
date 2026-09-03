# Project documentation

This directory documents the behavior implemented by the current source tree. The scanner evaluates the 67 Unix-server criteria in the KISA CCE 2026 profile on the Debian, Ubuntu, and Enterprise Linux releases in the dated platform support matrix.

## Documentation map

| Document | Audience | Contents |
|---|---|---|
| [Usage](usage.md) | Operators | Privileges, scan modes, command options, reports, statuses, and exit codes. |
| [Platform support](platform-support.md) | Operators and maintainers | Accepted releases, derivative mapping, lifecycle sources, and exclusions. |
| [KISA platform semantics](kisa-platform-semantics.md) | Maintainers and reviewers | Rendered-guide family branches, versioned native behavior, and validation limits. |
| [Architecture](architecture.md) | Maintainers and reviewers | Components, execution flow, configuration resolution, and result production. |
| [Security model](security-model.md) | Security and operations teams | Trust boundaries, defensive controls, residual risks, and safe deployment. |
| [Development](development.md) | Contributors | Check implementation contract, validation workflow, and release gates. |
| [Packaging](packaging/README.md) | Package maintainers | `DESTDIR` installation and future Debian/RPM integration. |

The source for the installed `kisa-cce-scan(8)` command manual is `man/kisa-cce-scan.8`.

## Scope and sources of truth

| Concern | Source of truth |
|---|---|
| Accepted product identities and versions | Platform detection in `lib/core.sh`. |
| Lifecycle scope and support policy | `docs/platform-support.md`. |
| Rendered-guide platform branches | `docs/kisa-platform-semantics.md`. |
| Criterion codes, categories, severities, and titles | `data/criteria.tsv`. |
| Command-line behavior | `lib/kisa-cce-scan-main.sh`. |
| Result and report contracts | `lib/core.sh`. |
| Configuration precedence | `lib/resolvers.sh` and the subsystem-specific check modules. |
| Regression coverage | `tests/run.sh`. |
| Installed file layout | `Makefile`. |
| Command manual | `man/kisa-cce-scan.8`. |
| Scanner version | `data/VERSION`. |

The rendered KISA criterion pages provide the assessment reference, while the local catalog controls which results the scanner emits: [KISA CCE 2026 Unix criteria](https://kreonet.github.io/kisa-cce-guide-web/unix/).

## Validation scope

The fixture suite verifies platform classification, parsing, path confinement, report integrity, catalog cardinality, and staged installation without changing the host. It does not replace acceptance testing on every listed product and release.
