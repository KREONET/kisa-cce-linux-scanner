# Project documentation

This directory documents the behavior implemented by the current source tree. The scanner evaluates the 67 Unix-server criteria in the KISA CCE 2026 profile on the Debian, Ubuntu, and Enterprise Linux releases in the dated platform support matrix.

## Directory layout

```text
docs/
├── operators/   Operational commands, evidence collection, and report language.
├── reference/   Versioned support, criterion semantics, and policy schemas.
├── design/      Architecture, security boundaries, performance, and benchmarks.
├── developers/  Contribution workflow and development-environment procedures.
└── packaging/   Debian and RPM staging and integration.
```

## Operator guides

| Document | Contents |
|---|---|
| [Usage](operators/usage.md) | Privileges, scan modes, command options, reports, statuses, and exit codes. |
| [Evidence bundle](operators/evidence-bundle.md) | Runtime collector, bundle contents, validation, and offline binding. |
| [Localization](operators/localization.md) | Report language selection, PO catalog layout, and translation workflow. |

## Reference

| Document | Contents |
|---|---|
| [Platform support](reference/platform-support.md) | Accepted releases, derivative mapping, lifecycle sources, and exclusions. |
| [KISA platform semantics](reference/kisa-platform-semantics.md) | Rendered-guide family branches, versioned native behavior, and validation limits. |
| [Policy format](reference/policy-format.md) | Typed fact and attestation schemas, trust requirements, expiry, and lookup behavior. |

## Design

| Document | Contents |
|---|---|
| [Architecture](design/architecture.md) | Components, execution flow, configuration resolution, and result production. |
| [Security model](design/security-model.md) | Trust boundaries, defensive controls, residual risks, and safe deployment. |
| [Performance](design/performance.md) | Scan epochs, parse-once snapshots, dependency DAG, and benchmark method. |

## Contributors and packaging

| Document | Contents |
|---|---|
| [Contributor guide](developers/README.md) | Repository workflow, subsystem boundaries, review checklist, and macOS container validation. |
| [Development reference](developers/development.md) | Check implementation contract, validation workflow, and release gates. |
| [macOS container testing](developers/macos-container-testing.md) | Apple `container` setup, eight-image validation matrix, debug smoke checks, and scoped cleanup. |
| [Packaging](packaging/README.md) | `DESTDIR` installation and future Debian/RPM integration. |

The installed command manuals are maintained as [kisa-cce-scan(8)](../man/kisa-cce-scan.8) and [kisa-cce-collect(8)](../man/kisa-cce-collect.8).

## Scope and sources of truth

| Concern | Source of truth |
|---|---|
| Accepted product identities and versions | Platform detection in `lib/core.sh`. |
| Lifecycle scope and support policy | `docs/reference/platform-support.md`. |
| Rendered-guide platform branches | `docs/reference/kisa-platform-semantics.md`. |
| Criterion codes, categories, severities, and titles | `data/criteria.tsv`. |
| Command-line behavior | `lib/kisa-cce-scan-main.sh`. |
| Result and report contracts | `lib/core.sh`. |
| Configuration precedence | `lib/resolvers.sh` and the subsystem-specific check modules. |
| Regression coverage | `tests/run.sh` and focused scripts under `tests/`. |
| Installed file layout | `Makefile`. |
| Command manuals | `man/kisa-cce-scan.8` and `man/kisa-cce-collect.8`. |
| Complete-mode policy contract | `docs/reference/policy-format.md` and `lib/policy.sh`. |
| Runtime evidence contract | `docs/operators/evidence-bundle.md` and `lib/evidence.sh`. |
| Report localization contract | `docs/operators/localization.md`, `lib/i18n.sh`, and `share/kisa-cce-linux-scanner/locale`. |
| Scan cache and invalidation contract | `docs/design/performance.md` and `lib/scan_epoch.sh`. |
| Project license | `LICENSE` and `LICENSES/`. |
| Scanner version | `data/VERSION`. |

The rendered KISA criterion pages provide the assessment reference, while the local catalog controls which results the scanner emits: [KISA CCE 2026 Unix criteria](https://kreonet.github.io/kisa-cce-guide-web/unix/).

## Validation scope

The fixture suite verifies platform classification, parsing, path confinement, report integrity, catalog cardinality, and staged installation without changing the host. It does not replace acceptance testing on every listed product and release.
