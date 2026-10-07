# Packaging integration

Debian-family and RPM-family packages use the same relocatable install interface. Package builds should stage files with `make install` and `DESTDIR` rather than copying them individually.

## Installed layout

| Path | Purpose | Mode |
|---|---|---:|
| `/usr/bin/kisa-cce-scan` | User-facing command | `0755` |
| `/usr/bin/kisa-cce-collect` | Live runtime evidence collector | `0755` |
| `/usr/bin/kisa-cce-policy-compile` | Restricted scanner-policy YAML-to-TSV compiler | `0755` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-checks/_*.sh` | Criterion implementations | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-cli/_*.sh` | Private CLI entry points | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-core/_*.sh` | Core, localization, and scan-epoch modules | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-policy/_*.sh` | Policy loader and YAML compiler modules | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-resolvers/_*.sh` | Configuration resolvers | `0644` |
| `/usr/lib/kisa-cce-linux-scanner/kisa-cce-runtime/_*.sh` | Runtime and evidence modules | `0644` |
| `/usr/share/kisa-cce-linux-scanner/criteria.tsv` | Criterion catalog | `0644` |
| `/usr/share/kisa-cce-linux-scanner/VERSION` | Runtime version | `0644` |
| `/usr/share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po` | Korean and English report catalogs | `0644` |
| `/usr/share/man/man8/kisa-cce-scan.8` | System administration manual | `0644` |
| `/usr/share/man/man8/kisa-cce-collect.8` | Evidence collector manual | `0644` |
| `/usr/share/man/man8/kisa-cce-policy-compile.8` | Policy compiler manual | `0644` |
| `/etc/kisa-cce-scanner/policy.d/00-default.tsv` | Header-only criterion attestation configuration | `0600` |

The policy directory has mode `0700`. `make install` preserves an existing policy file or symbolic link. Debian packages should declare the file as a conffile through their normal packaging workflow. RPM packages should use the appropriate no-replace configuration attribute. The supplied file contains no approval decision, and installation must not generate site policy. Typed fact files are not installed: even a header-only fact set can express a closed set and therefore affect policy decisions.

The default private library path is `/usr/lib/kisa-cce-linux-scanner` on all distributions. Debian permits this location, though its policy recommends `/usr/share` for entirely architecture-independent directories. An RPM spec must use this exact noarch path rather than `%{_libdir}`, which can select `/usr/lib64`. RPM packages can also use the launcher's supported `/usr/libexec/kisa-cce-linux-scanner` override:

```bash
package_root="$(mktemp -d)" || exit 1
make install \
  DESTDIR="$package_root" \
  prefix=/usr \
  pkglibdir=/usr/libexec/kisa-cce-linux-scanner
```

The executable locates data and libraries relative to its installed prefix. Staged package tests and installations under `/usr` or `/usr/local` can therefore relocate together, provided the command, private library, and data keep the documented relative layout. Moving `bindir`, `pkglibdir`, or `datadir` to unrelated prefixes requires a launcher change.

Each public command starts with `#!/bin/sh` and immediately executes its
private Bash main file through `/usr/bin/env -i`. This starts Bash with a clean
environment and complies with RPM shebang policy. Private sourced files have
no shebangs and are not executable.

## Debian-family package entry point

A future `debian/rules` file can use the standard debhelper build sequence and call the install target as follows:

```makefile
#!/usr/bin/make -f

%:
	dh $@

override_dh_auto_install:
	$(MAKE) install \
		DESTDIR=$(CURDIR)/debian/kisa-cce-linux-scanner \
		prefix=/usr
```

Declare the package architecture-independent; it contains only shell and data files. Base runtime dependencies on the commands used by the final release. Keep service-specific inspection tools optional where the scanner handles unavailable evidence conservatively.

## RPM-family package entry point

A future RPM spec file can use the standard path macros for installation:

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

List installed files explicitly under `%files`. Use RPM path macros where they preserve the noarch layout. Keep `%{_prefix}/lib/kisa-cce-linux-scanner` explicit so the library path stays the same across architectures instead of switching between `/usr/lib` and `/usr/lib64`.

`make install` excludes Markdown under `docs/`. Future Debian or RPM metadata may include selected source documents as package documentation. The upstream install target includes the section 8 command manuals, which packaging tools may compress.

## Metadata still required

Before publishing Debian or RPM package metadata, review all of the following:

- Package maintainer, vendor, source URL, and release ownership.
- Exact mandatory and optional runtime dependency sets for each supported platform group.
- Package upgrade, removal, and report-retention policy.
- Real-package installation and execution results on every listed product and release.

The repository provides install paths and a build interface. It does not yet provide a `.deb` or `.rpm` package with all required packaging policies defined.

The project license expression is `LGPL-3.0-or-later OR BSD-3-Clause`. Debian metadata must reproduce the applicable copyright and alternative-license information. RPM metadata should use `License: LGPL-3.0-or-later OR BSD-3-Clause` and install `LICENSING.md`, `LICENSE-LGPL`, `LICENSE-BSD`, `NOTICE`, and all files under `LICENSES/` through `%license`. Keep these files outside the upstream runtime install target.

## References

- [Debian Policy: file system structure](https://www.debian.org/doc/debian-policy/ch-opersys.html#file-system-structure)
- [Guide for Debian Maintainers: installation](https://www.debian.org/doc/manuals/debmake-doc/ch05.en.html)
- [RHEL 10: RPM macros](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/packaging_and_distributing_software/rpm-macros)
- [Fedora Packaging Guidelines](https://forge.fedoraproject.org/packaging/guidelines/src/branch/main/guidelines/modules/ROOT/pages/index.adoc)
- [RPM spec format](https://rpm.org/docs/4.20.x/manual/spec.html)

## Upgrade from the combined package

Fresh scanner and patcher installations own separate library and data trees. `make install` leaves obsolete files from a previous combined installation in place. Distribution upgrade metadata must transfer ownership of `kisa-cce-patch` and its manual to the patcher package. After installing replacements, remove the obsolete scanner-owned `kisa-cce-patcher` library and `_patch-main.sh`. Preserve all transaction directories and keep a trusted matching legacy package throughout the rollback window. Test this migration separately from a fresh staged install.
