# Packaging integration

The source tree exposes one relocatable install interface for Debian-family and RPM-family packages. Package builds should call `make install` with `DESTDIR` instead of copying individual files.

## Installed layout

| Path | Purpose | Mode |
|---|---|---:|
| `/usr/bin/kisa-cce-scan` | User-facing command | `0755` |
| `/usr/bin/kisa-cce-collect` | Live runtime evidence collector | `0755` |
| `/usr/bin/kisa-cce-policy-compile` | Restricted scanner-policy YAML-to-TSV compiler | `0755` |
| `/usr/bin/kisa-cce-patch` | Dry-run-first configuration and file-metadata remediation command | `0755` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-checks/_*.sh` | Criterion implementations | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-cli/_*.sh` | Private CLI entry points | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-core/_*.sh` | Core, localization, and scan-epoch modules | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-policy/_*.sh` | Policy loader and YAML compiler modules | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-resolvers/_*.sh` | Configuration resolvers | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-runtime/_*.sh` | Runtime and evidence modules | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-patcher/_*.sh` | Fixed-scope configuration, metadata, and private subsystem transaction engines | `0644` |
| `/usr/share/kisa-cce-linux-scanner/criteria.tsv` | Criterion catalog | `0644` |
| `/usr/share/kisa-cce-linux-scanner/VERSION` | Runtime version | `0644` |
| `/usr/share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po` | Korean and English report catalogs | `0644` |
| `/usr/share/man/man8/kisa-cce-scan.8` | System administration manual | `0644` |
| `/usr/share/man/man8/kisa-cce-collect.8` | Evidence collector manual | `0644` |
| `/usr/share/man/man8/kisa-cce-policy-compile.8` | Policy compiler manual | `0644` |
| `/usr/share/man/man8/kisa-cce-patch.8` | Configuration and metadata patcher manual | `0644` |
| `/etc/kisa-cce-scanner/policy.d/00-default.tsv` | Header-only criterion attestation configuration | `0600` |

The policy directory uses mode `0700`. `make install` does not replace the policy file when it already exists or is a symbolic link. Debian packages should declare the file as a conffile through their normal packaging workflow. RPM packages should install it with the appropriate no-replace configuration attribute. The shipped file contains no approval decision; package installation must not synthesize site policy. Typed fact files are not installed because even a header-only fact set can carry a non-neutral closed-set meaning.

The project deliberately uses the requested cross-distribution path `/usr/lib/kisa-cce-linux-scanner`. Debian permits this location, although its policy recommends `/usr/share` when a directory is entirely architecture-independent. An RPM spec must not substitute `%{_libdir}`, because that macro can select `/usr/lib64`; use the exact noarch private path instead. The launcher also supports `/usr/libexec/kisa-cce-linux-scanner` as an RPM packaging override:

```bash
package_root="$(mktemp -d)" || exit 1
make install \
  DESTDIR="$package_root" \
  prefix=/usr \
  pkglibdir=/usr/libexec/kisa-cce-linux-scanner
```

The executable derives the matching data and library directories from its own installed prefix. This keeps staged package tests, `/usr` installations, and `/usr/local` installations relocatable when the command, private library, and data retain the documented relative layout. Independently relocating `bindir`, `pkglibdir`, or `datadir` to unrelated prefixes is not supported without changing the launcher.

Each public command uses a direct `#!/bin/sh` shebang and immediately executes
its private Bash main file through `/usr/bin/env -i`. Private sourced files are
non-executable and do not carry shebangs. This preserves the clean-environment
boundary while remaining compatible with RPM shebang policy.

The installed patcher library contains the fixed configuration/metadata
engines, the 58 conditional account, PAM, inventory, filesystem, service,
network-service, edge-service, and system adapters, the desired-state v2
compiler, domain bridge, and all-domain orchestrator. The validated coverage
split is fixed=9, conditional=58, gated=0. Desired-state v2 has no standalone
compiler command; `kisa-cce-patch --automatic --desired-state FILE` invokes it
internally. `kisa-cce-policy-compile` remains the scanner policy
schema-version-1 command.

The installed `kisa-cce-patch` command exposes ordinary planning and apply for
the nine fixed rules; the ordinary default contains seven. Its separate
root-only `--automatic --desired-state FILE` path evaluates and orchestrates
U-01 through U-67. Packages must not run that path at installation time or
prepopulate organization approvals, secrets, provider decisions, callback
paths, or external rollback tokens.

Conditional adapters use trusted callback and native-provider boundaries.
Package dependency metadata should distinguish commands required by the public
fixed path from optional commands used only when an integrator invokes a
private provider adapter. Do not make every supported mail, DNS, NFS, firewall,
FTP, SNMP, time, or service implementation a mandatory runtime dependency.
Callback executables, site desired-state profiles, and referenced domain-input
TSV files are administrator-managed security inputs and are not upstream
conffiles. Domain-input files must remain root-owned mode `0600`; packages must
not relax this requirement through shared group ownership.

The install target does not create a writable patch-transaction directory.
Operators select a new owner-only directory with `kisa-cce-patch --output-dir`
for each dry run or manual apply. `--automatic` creates root-owned protected
parents and a unique transaction below
`/var/lib/kisa-cce-patcher/transactions` at runtime when no path was supplied.
Manual rollback updates the state in that existing transaction directory. A
distribution package must not pre-create a shared or group-writable transaction
location. See
[Autopatcher](../design/autopatcher.md) for retention and rollback
requirements.

Full automatic transactions add the protected `orchestrator/`, domain child
transactions, and pre/post scan directories. The existing `--rollback` command
detects that layout and performs reverse-domain cross-process recovery.

Manual rollback requires the installed scanner version to match the transaction
manifest. Package upgrade procedures must either close outstanding rollback
windows first or retain a trusted, runnable copy of the matching package
artifact. A package must not silently rewrite transaction manifests during an
upgrade.

## Debian-family package entry point

A future `debian/rules` file can use the standard debhelper build sequence and delegate installation to this interface:

```makefile
#!/usr/bin/make -f

%:
	dh $@

override_dh_auto_install:
	$(MAKE) install \
		DESTDIR=$(CURDIR)/debian/kisa-cce-linux-scanner \
		prefix=/usr
```

Declare the package as architecture-independent because it contains shell and data files only. Derive runtime dependencies from the commands used by the final release, and keep service-specific inspection tools optional when the scanner already reports unavailable evidence conservatively.

## RPM-family package entry point

A future spec file can install through RPM's standard path macros:

```spec
BuildArch: noarch

%install
%make_install \
    prefix=%{_prefix} \
    bindir=%{_bindir} \
    pkglibdir=%{_prefix}/lib/kisa-cce-linux-scanner \
    datadir=%{_datadir}/kisa-cce-linux-scanner \
    mandir=%{_mandir} \
    sysconfdir=%{_sysconfdir}
```

List the installed files explicitly under `%files`. Use RPM path macros where they preserve the intended noarch layout; keep `%{_prefix}/lib/kisa-cce-linux-scanner` explicit so the package does not move between `/usr/lib` and `/usr/lib64` across architectures.

Repository Markdown under `docs/` is not part of `make install`. Debian or RPM metadata may select individual source documents as package documentation later. The section 8 command manuals are part of the upstream install target and package tools may compress them during package construction.

## Metadata still required

Do not publish Debian or RPM package metadata until all of the following values are reviewed:

- Package maintainer, vendor, source URL, and release ownership.
- Exact mandatory and optional runtime dependency sets for each supported platform group.
- Package upgrade, removal, and report-retention policy.
- Real-package installation and execution results on every listed product and release.

The current tree provides the filesystem and build interface, but it does not yet claim a policy-complete `.deb` or `.rpm` package.

The project license expression is `LGPL-3.0-or-later OR BSD-3-Clause`. Debian metadata must reproduce the applicable copyright and alternative-license information. RPM metadata should use `License: LGPL-3.0-or-later OR BSD-3-Clause` and install `LICENSE`, `NOTICE`, and all files under `LICENSES/` through `%license` without adding them to the upstream runtime install target.

## References

- [Debian Policy: file system structure](https://www.debian.org/doc/debian-policy/ch-opersys.html#file-system-structure)
- [Guide for Debian Maintainers: installation](https://www.debian.org/doc/manuals/debmake-doc/ch05.en.html)
- [RHEL 10: RPM macros](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/packaging_and_distributing_software/rpm-macros)
- [Fedora Packaging Guidelines](https://forge.fedoraproject.org/packaging/guidelines/src/branch/main/guidelines/modules/ROOT/pages/index.adoc)
- [RPM spec format](https://rpm.org/docs/4.20.x/manual/spec.html)
