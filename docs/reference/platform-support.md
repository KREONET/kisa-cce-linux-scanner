# Platform support

## Scope

This matrix records support as of 2026-09-03. By default, the scanner accepts
releases receiving project or vendor base-stream security maintenance. It
excludes subscription-only extended streams, third-party extended maintenance,
development releases, and point releases retired when a successor is released.

Detection and classification fixtures cover every listed product identity.
Separate fixtures cover the implemented Debian-family and Enterprise Linux
configuration rules. This coverage is not vendor certification; release
acceptance still requires live testing on every listed target. See
[KISA platform semantics](kisa-platform-semantics.md) for distribution-specific
guide procedures and the limits of automatic assessment.

## Direct distributions

| Distribution | Accepted `ID` | Accepted `VERSION_ID` | Lifecycle basis |
|---|---|---|---|
| Debian 12 | `debian` | `12` | Debian LTS through 2028-06-30. |
| Debian 13 | `debian` | `13` | Debian security support through 2028-08-09, followed by LTS. |
| Ubuntu 22.04 LTS | `ubuntu` | `22.04` | Standard security maintenance through 2027-05. |
| Ubuntu 24.04 LTS | `ubuntu` | `24.04` | Standard security maintenance through 2029-05. |
| Ubuntu 26.04 LTS | `ubuntu` | `26.04` | Standard security maintenance through 2031-05. |
| Red Hat Enterprise Linux 8 | `rhel` | `8.10` | Current and final RHEL 8 base stream; the RHEL 8 major lifecycle continues through 2029-05-31. |
| Red Hat Enterprise Linux 9 | `rhel` | `9.8` | Current base stream at the snapshot date; the RHEL 9 major lifecycle continues through 2032-05-31. |
| Red Hat Enterprise Linux 10 | `rhel` | `10.2` | Current base stream at the snapshot date; the RHEL 10 major lifecycle continues through 2035-05-31. |

Sources: [Debian releases](https://www.debian.org/releases/), [Debian 12 LTS transition](https://www.debian.org/News/2026/20260712), [Ubuntu release cycle](https://ubuntu.com/about/release-cycle), and [RHEL lifecycle](https://access.redhat.com/support/policy/updates/errata).

The RHEL 9 and 10 lifecycle dates apply to the major release, not to each minor
release for that entire period. Update the allowlist when Red Hat publishes
the next base-stream minor. A pinned older minor requires a separately
qualified extended-support entitlement.

## Enterprise Linux derivatives

| Distribution | Accepted `ID` | Accepted `VERSION_ID` | Lifecycle basis |
|---|---|---|---|
| AlmaLinux | `almalinux` | `8.10`, `9.8`, `10.2` | Each superseded minor release is unsupported. |
| Rocky Linux | `rocky` | `8.10`, `9.8`, `10.2` | Each superseded minor release is moved to the vault and unsupported. |
| Oracle Linux | `ol` | `8.10`, `9.8`, `10.2` | Current update snapshots; Oracle treats update releases as rolling snapshots within each major release. |
| CentOS Stream | `centos` | `9`, `10` | Stream 9 ends 2027-05-31; Stream 10 ends 2030-05-31. |

For CentOS, `PRETTY_NAME` must also identify CentOS Stream. An `ID_LIKE` match
alone does not qualify an Enterprise Linux derivative for support.

Sources: [AlmaLinux release notes](https://wiki.almalinux.org/release-notes/), [Rocky Linux release policy](https://docs.rockylinux.org/latest/releases/), Oracle Linux release information for [8](https://docs.oracle.com/en/operating-systems/oracle-linux/8/), [9](https://docs.oracle.com/en/operating-systems/oracle-linux/9/), and [10](https://docs.oracle.com/en/operating-systems/oracle-linux/10/), the [Oracle Linux lifetime support policy](https://www.oracle.com/a/ocom/docs/lifetime-support-policy-operating-system.pdf), and the [CentOS Stream lifecycle](https://www.centos.org/download/).

## Ubuntu derivatives

| Distribution | Accepted `ID` | Accepted `VERSION_ID` | Required Ubuntu base |
|---|---|---|---|
| Linux Mint | `linuxmint` | `21`, `21.1`, `21.2`, `21.3` | `UBUNTU_CODENAME=jammy` |
| Linux Mint | `linuxmint` | `22`, `22.1`, `22.2`, `22.3` | `UBUNTU_CODENAME=noble` |
| Pop!_OS | `pop` | `22.04`, `24.04` | `jammy`, `noble` respectively |
| Zorin OS | `zorin` | `17`, `18` | `jammy`, `noble` respectively |
| elementary OS | `elementary` | `7`, `7.1`, `8` | `jammy` for 7.x; `noble` for 8 |
| KDE neon User Edition | `neon` | `24.04` | `UBUNTU_CODENAME=noble` |

Every listed Ubuntu derivative must also declare both `ubuntu` and `debian` in `ID_LIKE`. KDE neon Testing, Unstable, and Developer editions are excluded. Linux Mint Debian Edition is not matched by the Ubuntu-derivative rules.

Linux Mint 21.x is maintained through 2027-04 and 22.x through 2029-04. Zorin OS 17 is maintained through 2027-06-01 and Zorin OS 18 through 2029-06-01. elementary OS 7 and 8 inherit Ubuntu repository maintenance through 2027-04 and 2029-04 respectively; these are base-repository dates rather than a single project-wide EOL guarantee. A System76 project statement places Pop!_OS 22.04 EOL in 2027-04. The projects do not publish fixed EOL dates for Pop!_OS 24.04 or KDE neon User Edition.

Sources: [Linux Mint supported releases](https://www.linuxmint.com/download_all.php), [Pop!_OS downloads](https://system76.com/pop/download/), [Pop!_OS upgrades](https://support.system76.com/support/upgrade-pop), [Pop!_OS 22.04 lifecycle statement](https://github.com/pop-os/shell/discussions/1728#discussioncomment-10467718), [Zorin OS details](https://zorin.com/os/details/), [elementary OS release upgrades](https://github.com/elementary/os/wiki/Release-Upgrades), and [KDE neon FAQ](https://neon.kde.org/faq.php).

Identity-field evidence: [Linux Mint 21.3 base-files](http://packages.linuxmint.com/pool/upstream/b/base-files/base-files_21.3.0.tar.xz), [Linux Mint 22.3 base-files](http://packages.linuxmint.com/pool/upstream/b/base-files/base-files_13ubuntu10mint22.3.0.tar.xz), [Pop!_OS os-release generator](https://github.com/pop-os/default-settings/blob/master/src/os-release.sh), [elementary OS 7.1 os-release](https://github.com/elementary/os-patches/blob/73e6ae29a886f1a43e7053dca8bad19679589ed5/etc/os-release), [elementary OS 8 os-release](https://github.com/elementary/os-patches/blob/b6c78c2b2b8e4af90d60c2845a5817c4a44e2f99/etc/os-release), and [KDE neon base-files](https://invent.kde.org/neon/forks/base-files/-/blob/09f588bcab417664b416cfdc8087a7cb44c678a9/etc/os-release). Zorin identity fields were extracted from checksum-matched official [Zorin OS 17](https://zorin.com/os/download/17/core/) and [Zorin OS 18](https://zorin.com/os/download/18/core/) Core images by using the project's [image-verification procedure](https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/).

## Explicit exclusions

- Debian 9 through 11 are available only through third-party commercial ELTS, not Debian Project security support.
- Ubuntu 14.04 through 20.04 require Ubuntu Pro ESM or the Legacy add-on after standard support. Those releases also require older runtime adapters that this scanner does not implement.
- RHEL 6 and 7, pinned RHEL EUS/ELC/E4S streams, and Oracle Linux 7 require subscription-specific extended support and older platform behavior.
- AlmaLinux and Rocky Linux point releases stop receiving project updates when superseded.
- CentOS Linux, CentOS Stream 8, arbitrary `ID_LIKE` matches, and development or beta releases are unsupported.

Use `--allow-unsupported` only for exploratory collection. Results from excluded
targets remain outside the supported assessment scope and are not authoritative.

## Platform adapters

The detector records each product's configuration family and base release
separately from its identity:

- Debian, Ubuntu, and approved Ubuntu derivatives use Debian-family PAM, APT, BIND, Chrony, and path conventions.
- RHEL and approved Enterprise Linux derivatives use Enterprise Linux PAM, authselect, DNF, BIND, Chrony, and path conventions.
- General login-default consumers on RHEL 8 and 9 use legacy `login.defs` duplicate handling. RHEL 9 PAM consumers such as `pam_umask` use libeconf's `/usr/share` and `/etc` roots. RHEL 10-family targets use the implemented `/etc`-only libeconf model and `/etc/login.defs.d/*.defs`.
- `pwhistory.conf` is active on Debian 13, Ubuntu 24.04 and 26.04, their approved derivatives, and the supported Enterprise Linux targets. Older supported Debian or Ubuntu bases use PAM module arguments instead.

### Ubuntu 26.04 native providers

Ubuntu 26.04 ships rust-coreutils 0.8.0 as the default provider, while `cp`,
`mv`, and `rm` remain GNU coreutils 9.7. The scanner treats this as a mixed
command environment and tests the command options it uses. It does not select
commands by implementation name alone. Run the focused regression test with
`tests/uutils_compatibility.sh`. See Canonical's
[rust-coreutils update](https://discourse.ubuntu.com/t/an-update-on-rust-coreutils/80773),
the [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/),
and the [Resolute GNU package](https://packages.ubuntu.com/resolute/gnu-coreutils).

Chrony is the default time daemon for new Ubuntu 26.04 installations. The
Resolute archive also provides `ntpd-rs` as an optional package. Canonical's
published goals are archive testing in Ubuntu 26.10 and default adoption in
Ubuntu 27.04. These plans do not change the Ubuntu 26.04 default. See the
[Chrony release note](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#chrony),
[ntpd-rs transition plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154),
and [Resolute ntpd-rs package](https://packages.ubuntu.com/resolute/ntpd-rs).

The scanner supports a selected installation of ntpd-rs as an operational
extension. It recognizes `/etc/ntpd-rs/ntp.toml`, `ntpd-rs.service`, and
normalized `ntp-ctl status` evidence while retaining Chrony as the expected
Ubuntu 26.04 provider.

Review the matrix whenever an upstream project publishes a stable, LTS,
Enterprise Linux minor, or derivative release. Update the detector, fixtures,
this document, and target-host acceptance evidence together.

## Acceptance status

The repository contains deterministic generated fixtures. Booted-host reports
have not been retained for every matrix row. Report release validation at the
following levels:

| Level | Current status |
|---|---|
| Product/version identity detection | Covered for every listed matrix row. |
| Debian-family and Enterprise Linux semantic adapters | Covered by targeted synthetic fixtures, including guide-explicit platform branches and known version-specific configuration and service layouts. |
| Full 67-result cardinality | Covered on representative generated roots. |
| Containerized userspace regression | Passed on 2026-09-04 for Debian 12/13, Ubuntu 22.04/24.04/26.04, and Rocky Linux 8.10/9.8/10.2 on arm64. Every image passed `make check`, its packaged ShellCheck gate, source and installed CLI smoke tests, YAML policy compilation, schema-2 evidence collection, sysctl explanation, and a selected debug scan. Every full root scan produced 67 results with zero `ERROR`. |
| Booted-host package and runtime acceptance on every matrix row | Not performed in this repository. |

The full root scan results were:

| Container | `GOOD` | `VULNERABLE` | `MANUAL` | `NOT_APPLICABLE` | `ERROR` |
|---|---:|---:|---:|---:|---:|
| Debian 12 | 31 | 10 | 5 | 21 | 0 |
| Debian 13 | 30 | 10 | 6 | 21 | 0 |
| Ubuntu 22.04 | 30 | 10 | 6 | 21 | 0 |
| Ubuntu 24.04 | 29 | 12 | 6 | 20 | 0 |
| Ubuntu 26.04 | 29 | 11 | 7 | 20 | 0 |
| Rocky Linux 8.10 | 30 | 10 | 9 | 18 | 0 |
| Rocky Linux 9.8 | 33 | 7 | 8 | 19 | 0 |
| Rocky Linux 10.2 | 33 | 7 | 8 | 19 | 0 |

The run used Apple container 1.3.1, read-only source mounts, and the
`lib/kisa-cce-*` directory layout. Test tools were installed in local OCI images
before execution. Each staged installation kept private `_*.sh` modules in
their function-specific directories. The installed policy compiler converted
the YAML example with no approvals into a mode-0700 directory containing a
mode-0600 TSV and a validated policy digest.

Evidence collection was rejected on minimal images without a machine ID. The
test then supplied a temporary valid ID and verified schema version 2, all 11
checksums, directory mode 0700, and file mode 0600. Non-systemd containers read
`kernel.randomize_va_space` through `/proc/sys` without changing it and reported
`loader=no-system-manager` with runtime value `2`.

These tests cover installed userspace, supported Bash and ShellCheck versions,
configuration adapters, report integrity, and static-only mount-boundary
collection. They do not establish acceptance on a booted systemd host or verify
SELinux enforcement, host storage topology, or live services and listeners.
