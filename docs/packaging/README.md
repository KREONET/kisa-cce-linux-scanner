# Packaging integration

The source tree exposes one relocatable install interface for Debian-family and RPM-family packages. Package builds should call `make install` with `DESTDIR` instead of copying individual files.

## Installed layout

| Path | Purpose | Mode |
|---|---|---:|
| `/usr/bin/kisa-cce-scan` | User-facing command | `0755` |
| `/usr/bin/kisa-cce-collect` | Live runtime evidence collector | `0755` |
| `/usr/lib/kisa-cce-linux-scanner/*.sh` | Private Bash scanner and sourced modules | `0644` |
| `/usr/share/kisa-cce-linux-scanner/criteria.tsv` | Criterion catalog | `0644` |
| `/usr/share/kisa-cce-linux-scanner/VERSION` | Runtime version | `0644` |
| `/usr/share/kisa-cce-linux-scanner/locale/{ko,en}/LC_MESSAGES/kisa-cce-linux-scanner.po` | Korean and English report catalogs | `0644` |
| `/usr/share/man/man8/kisa-cce-scan.8` | System administration manual | `0644` |
| `/usr/share/man/man8/kisa-cce-collect.8` | Evidence collector manual | `0644` |

The project deliberately uses the requested cross-distribution path `/usr/lib/kisa-cce-linux-scanner`. Debian permits this location, although its policy recommends `/usr/share` when a directory is entirely architecture-independent. An RPM spec must not substitute `%{_libdir}`, because that macro can select `/usr/lib64`; use the exact noarch private path instead. The launcher also supports `/usr/libexec/kisa-cce-linux-scanner` as an RPM packaging override:

```bash
package_root="$(mktemp -d)" || exit 1
make install \
  DESTDIR="$package_root" \
  prefix=/usr \
  pkglibdir=/usr/libexec/kisa-cce-linux-scanner
```

The executable derives the matching data and library directories from its own installed prefix. This keeps staged package tests, `/usr` installations, and `/usr/local` installations relocatable when the command, private library, and data retain the documented relative layout. Independently relocating `bindir`, `pkglibdir`, or `datadir` to unrelated prefixes is not supported without changing the launcher.

The public command uses a direct `#!/bin/sh` shebang and immediately executes the private Bash main file through `/usr/bin/env -i`. Private sourced files are non-executable and do not carry shebangs. This preserves the clean-environment boundary while remaining compatible with RPM shebang policy.

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
    mandir=%{_mandir}
```

List the installed files explicitly under `%files`. Use RPM path macros where they preserve the intended noarch layout; keep `%{_prefix}/lib/kisa-cce-linux-scanner` explicit so the package does not move between `/usr/lib` and `/usr/lib64` across architectures.

Repository Markdown under `docs/` is not part of `make install`. Debian or RPM metadata may select individual source documents as package documentation later. The section 8 command manual is part of the upstream install target and package tools may compress it during package construction.

## Metadata still required

Do not publish Debian or RPM package metadata until all of the following values are reviewed:

- Package maintainer, vendor, source URL, and release ownership.
- Exact mandatory and optional runtime dependency sets for each supported platform group.
- Package upgrade, removal, and report-retention policy.
- Real-package installation and execution results on every listed product and release.

The current tree provides the filesystem and build interface, but it does not yet claim a policy-complete `.deb` or `.rpm` package.

The project license is `LGPL-3.0-or-later`. Debian metadata must reproduce the applicable copyright and license information. RPM metadata should use `License: LGPL-3.0-or-later` and install `LICENSE`, `NOTICE`, and both files under `LICENSES/` through `%license` without adding them to the upstream runtime install target.

## References

- [Debian Policy: file system structure](https://www.debian.org/doc/debian-policy/ch-opersys.html#file-system-structure)
- [Guide for Debian Maintainers: installation](https://www.debian.org/doc/manuals/debmake-doc/ch05.en.html)
- [RHEL 10: RPM macros](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/packaging_and_distributing_software/rpm-macros)
- [Fedora Packaging Guidelines](https://forge.fedoraproject.org/packaging/guidelines/src/branch/main/guidelines/modules/ROOT/pages/index.adoc)
- [RPM spec format](https://rpm.org/docs/4.20.x/manual/spec.html)
