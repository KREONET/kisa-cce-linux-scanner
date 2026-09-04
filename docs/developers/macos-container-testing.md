# Testing with Apple container on macOS

This procedure runs the scanner's Linux validation matrix from an Apple silicon Mac. It uses Apple's `container` command to execute OCI images as lightweight Linux virtual machines. It does not replace acceptance testing on booted systems with a real systemd manager, listeners, mount topology, and native validators.

Apple supports `container` on macOS 26 and later on Apple silicon. Install the latest signed package from the [Apple container releases](https://github.com/apple/container/releases), then follow the [official installation instructions](https://github.com/apple/container#initial-install). Do not pin this project documentation to a locally installed `container` version; consult the command reference for the installed release because command availability can vary by release and macOS version.

The authoritative upstream references are:

- [Apple container repository and requirements](https://github.com/apple/container)
- [Container CLI command reference](https://github.com/apple/container/blob/main/docs/command-reference.md)
- [Mounts and volumes](https://github.com/apple/container/blob/main/docs/volumes.md)

## Start and inspect the service

Start the per-user container services. The first invocation may prompt to install the default Linux kernel:

```bash
container system start
```

Inventory running and stopped containers before the test run:

```bash
container list --all
```

Apple `container` consumes and produces OCI-compatible images. Use arm64 Linux images on Apple silicon unless a specific compatibility test requires another architecture.

## Test matrix

Exercise all eight maintained base-image tags:

| Platform | OCI base image |
|---|---|
| Debian 12 | `debian:12-slim` |
| Debian 13 | `debian:13-slim` |
| Ubuntu 22.04 LTS | `ubuntu:22.04` |
| Ubuntu 24.04 LTS | `ubuntu:24.04` |
| Ubuntu 26.04 LTS | `ubuntu:26.04` (rust-coreutils 0.8.0 default; GNU `cp`, `mv`, and `rm`) |
| Rocky Linux 8.10 | `rockylinux/rockylinux:8.10` |
| Rocky Linux 9.8 | `rockylinux/rockylinux:9.8` |
| Rocky Linux 10.2 | `rockylinux/rockylinux:10.2` |

Prepare a test image for each tag with the distribution's Bash, GNU findutils,
compatible base utilities, `make`, ShellCheck, `mandoc`, and `jq`. Do not replace
Ubuntu 26.04's compatible rust-coreutils commands merely to satisfy an
implementation-name check. Test-only packages do not become scanner production
dependencies. Record the resolved image digest so a later run can distinguish
source changes from image changes.

The examples below use `TEST_IMAGE` for one prepared image and derive the checkout path without embedding a developer-specific absolute path:

```bash
repository_root="$(git rev-parse --show-toplevel)"
TEST_IMAGE="kisa-cce-test:ubuntu-26.04"
```

Repeat the validation and smoke steps for every row in the matrix.

### Ubuntu 26.04 command-capability check

Keep the Ubuntu 26.04 image's default mixed coreutils selection for at least one
matrix run. Ubuntu ships rust-coreutils 0.8.0 by default but retains GNU
coreutils 9.7 for `cp`, `mv`, and `rm`; replacing the provider before testing
would hide the compatibility boundary. See the official
[rust-coreutils update](https://discourse.ubuntu.com/t/an-update-on-rust-coreutils/80773)
and [Ubuntu release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/),
plus the [Resolute GNU coreutils package](https://packages.ubuntu.com/resolute/gnu-coreutils).

Run the focused gate explicitly in the Ubuntu 26.04 image:

```bash
container run --rm \
  --uid 1000 \
  --gid 1000 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc './tests/uutils_compatibility.sh'
```

The test executes the scanner's actual option forms for `stat`, `readlink`,
`sort`, `date`, `sha256sum`, and `install`. It does not accept or reject an
implementation based on branding or version output. Expect a `PASS` on Ubuntu
26.04 and a deliberate `SKIP` on other matrix rows. `make check` also runs this
gate.

Do not seed ntpd-rs into the base Ubuntu 26.04 image and then describe it as a
distribution default. Chrony is the default for new installations. The
repository's `tests/ntpd_rs.sh` covers the optionally selected provider's
configuration, service, runtime-status, and policy paths; a separate ntpd-rs
image is an extension test. See the
[Ubuntu Chrony note](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#chrony)
and [Canonical transition plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154).

## Non-root correctness and lint gates

Mount the checkout read-only. Run permission-sensitive fixtures as UID and GID 1000 so root privilege does not bypass the unreadable-file cases:

```bash
container run --rm \
  --uid 1000 \
  --gid 1000 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc 'make check'
```

Run lint under the same distribution userspace:

```bash
container run --rm \
  --uid 1000 \
  --gid 1000 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc 'make lint && mandoc -T lint man/kisa-cce-scan.8 && mandoc -T lint man/kisa-cce-collect.8 && mandoc -T lint man/kisa-cce-policy-compile.8 && mandoc -T lint man/kisa-cce-patch.8'
```

The read-only bind mount confirms that tests and package staging use protected temporary directories instead of modifying the checkout. The `--mount` syntax and key-only `readonly` option follow Apple's [mount option reference](https://github.com/apple/container/blob/main/docs/volumes.md#options-for---mount).

## Root debug smoke and report checks

Run one full static scan as container root. The repository remains read-only, while reports are written to the container's temporary filesystem:

```bash
container run --rm \
  --uid 0 \
  --gid 0 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc '
    set -u
    output_directory=/tmp/kisa-cce-container-smoke
    stdout_file=/tmp/kisa-cce-stdout
    stderr_file=/tmp/kisa-cce-stderr

    scanner_status=0
    ./bin/kisa-cce-scan \
      --root / \
      --no-runtime \
      --debug \
      --output-dir "$output_directory" \
      >"$stdout_file" 2>"$stderr_file" || scanner_status=$?

    case "$scanner_status" in 0|1|2) ;; *) exit "$scanner_status" ;; esac

    markdown_report="$(sed -n "s/^\[[^]]*\] kisa-cce-scan: markdown_report=//p" "$stdout_file")"
    jsonl_report="$(sed -n "s/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p" "$stdout_file")"
    test -f "$markdown_report"
    test -f "$jsonl_report"
    test "$(grep -Ec "^## U-[0-9]{2}: " "$markdown_report")" -eq 67
    test "$(wc -l < "$jsonl_report")" -eq 68
    jq -e -c . "$jsonl_report" >/dev/null
    tail -n 1 "$jsonl_report" | jq -e ".type == \"summary\" and .total == 67" >/dev/null
    test "$(stat -c %a "$output_directory")" = 700
    test "$(stat -c %a "$markdown_report")" = 600
    test "$(stat -c %a "$jsonl_report")" = 600
    grep -Eq "^\\[[[:space:]]*[0-9]+\\.[0-9]{6}\\] kisa-cce-scan: DEBUG: schema=1 event=scan_start" "$stderr_file"
    grep -Eq "^\\[[[:space:]]*[0-9]+\\.[0-9]{6}\\] kisa-cce-scan: DEBUG: schema=1 event=scan_end" "$stderr_file"
    ! grep -Ev "^\\[[[:space:]]*[0-9]+\\.[0-9]{6}\\] kisa-cce-scan: .*$" "$stdout_file" "$stderr_file" >/dev/null
  '
```

Exit status 1 represents a completed scan with at least one `VULNERABLE` result. Exit status 2 can represent a completed minimal-container scan with a criterion `ERROR`; the existence and integrity checks above distinguish that result from an invocation that failed before producing reports. Review the final JSONL summary and debug stream instead of treating either status as an automatic harness failure.

## Metadata patch and rollback smoke

Exercise dry-run, apply, independent post-scan, and guarded rollback in an
ephemeral offline root. Repeat this test for every matrix image. It changes only
files created below `/tmp` inside the disposable container:

```bash
container run --rm \
  --uid 0 \
  --gid 0 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc '
    set -eu
    target_root=/tmp/kisa-cce-patch-root
    dry_run=/tmp/kisa-cce-patch-dry-run
    transaction=/tmp/kisa-cce-patch-transaction

    install -d -m 0755 "$target_root/etc" "$target_root/etc/cron.daily" \
      "$target_root/usr/bin"
    cp /etc/os-release "$target_root/etc/os-release"
    printf "%s\n" "root:x:0:0:root:/root:/bin/bash" >"$target_root/etc/passwd"
    printf "%s\n" "root:!:20000:0:99999:7:::" >"$target_root/etc/shadow"
    printf "%s\n" "127.0.0.1 localhost" >"$target_root/etc/hosts"
    printf "%s\n" "ssh 22/tcp" >"$target_root/etc/services"
    : >"$target_root/etc/hosts.lpd"
    : >"$target_root/usr/bin/crontab"
    : >"$target_root/etc/cron.daily/package-job"
    chmod 0666 "$target_root/etc/passwd" "$target_root/etc/shadow" \
      "$target_root/etc/hosts" "$target_root/etc/services" \
      "$target_root/etc/hosts.lpd"
    chmod 04777 "$target_root/usr/bin/crontab"
    chmod 0666 "$target_root/etc/cron.daily/package-job"

    ./bin/kisa-cce-patch --root "$target_root" --output-dir "$dry_run"
    test "$(cat "$dry_run/state")" = planned
    test "$(stat -c %a "$target_root/etc/shadow")" = 666

    ./bin/kisa-cce-patch \
      --root "$target_root" \
      --output-dir "$transaction" \
      --apply
    test "$(cat "$transaction/state")" = verified
    test "$(stat -c %a "$target_root/etc/passwd")" = 644
    test "$(stat -c %a "$target_root/etc/shadow")" = 400
    test "$(stat -c %a "$target_root/etc/hosts")" = 644
    test "$(stat -c %a "$target_root/etc/services")" = 644
    test "$(stat -c %a "$target_root/etc/hosts.lpd")" = 600
    test "$(stat -c %a "$target_root/usr/bin/crontab")" = 750
    test "$(stat -c %a "$target_root/etc/cron.daily/package-job")" = 640

    ./bin/kisa-cce-patch --rollback "$transaction"
    test "$(cat "$transaction/state")" = rolled_back
    test "$(stat -c %a "$target_root/etc/shadow")" = 666
    test "$(stat -c %a "$target_root/usr/bin/crontab")" = 4777

    if ./bin/kisa-cce-patch --root "$target_root" --automatic \
      >/tmp/kisa-cce-patch-automatic.stdout 2>&1; then
      exit 1
    fi
    grep -F -- "--automatic requires --desired-state FILE" \
      /tmp/kisa-cce-patch-automatic.stdout >/dev/null
  '
```

Also run the negative fixtures in `make check`. A successful smoke test does
not prove crash durability or behavior on a booted host with concurrent package
or configuration management.

The default smoke covers the U-37 multi-target rule. It intentionally omits
U-67 because that rule is live-root-only and depends on the container's actual
`/var/log` mount and symlink topology. Exercise U-67 apply and rollback only in
a dedicated disposable live container or VM, then retain its full transaction
and scanner reports.

Full automatic testing requires an exact 67-row desired-state v2 profile,
criterion-specific root-owned mode-`0600` domain input files, trusted callback
executables, and the services or providers named by that profile. The minimal
offline fixture above deliberately cannot satisfy those prerequisites. Run
`tests/patch_orchestrator.sh`, `tests/patch_full_automatic.sh`,
`tests/patch_cli.sh`, and every focused domain transaction test in the
container matrix, then exercise a complete
`--automatic --desired-state FILE` run only in a disposable booted VM where
post-change service, firewall, listener, package, and reboot state can be
verified.

## Two different debug options

Apple `container` and the scanner both define an option named `--debug`, but they instrument different processes:

| Invocation | Diagnostic scope |
|---|---|
| `container --debug run ...` | Apple container client, service, VM, image, mount, and runtime operations |
| `kisa-cce-scan --debug ...` | Scanner lifecycle, criterion dispatch, resolver snapshots, cache decisions, collection state, and report validation |

Place Apple's global option before the `run` subcommand to debug Apple `container`. Place the scanner option after `kisa-cce-scan` inside the guest command to debug the scanner. Enabling one does not enable the other. Both streams can contain sensitive environment or assessment metadata and must be handled accordingly.

## Optional offline image-preparation workaround

This section is an optional local workaround, not the normal project workflow. Use it only when an Apple container guest cannot reach distribution package repositories but a separately installed Docker or BuildKit environment has network access.

Build the dependency-equipped arm64 test image with Docker Buildx and export it as an OCI archive. The local Containerfile must start from the matching matrix tag and install only the test packages described above:

```bash
base_image="ubuntu:26.04"
test_image="kisa-cce-test:ubuntu-26.04"
temporary_directory="$(mktemp -d -t kisa-cce-test-image)"
oci_archive="$temporary_directory/image.tar"

docker buildx build \
  --platform linux/arm64 \
  --build-arg BASE_IMAGE="$base_image" \
  --tag "$test_image" \
  --output "type=oci,name=$test_image,dest=$oci_archive" \
  --file /path/to/local/test.Containerfile \
  /path/to/local/build-context

container image load --input "$oci_archive"
container image list
```

Use an equivalent package-installing Containerfile for Debian-family and Rocky Linux images. Do not commit credentials, proxy configuration, repository tokens, or package caches. After loading, use the imported reference shown by `container image list` as `TEST_IMAGE`. The `container image load --input` interface is documented in the [official command reference](https://github.com/apple/container/blob/main/docs/command-reference.md#container-image-load), and the archive creation syntax follows Docker's [OCI exporter documentation](https://docs.docker.com/build/exporters/oci-docker/).

This workaround changes only how the local test image is prepared. All scanner tests must still run through Apple `container`, with the checkout mounted read-only and the same UID/GID and report checks.

## Cleanup

Every example uses `container run --rm`, so its container is removed after the command exits. Confirm that no stopped test containers remain:

```bash
container list --all
```

Delete only the test images and archives created for this run:

```bash
container image delete "$TEST_IMAGE"
rm -rf -- "$temporary_directory"
```

Do not use an unscoped delete command on a workstation that may contain unrelated containers or images. Stop the Apple container services only when no other local work needs them:

```bash
container system stop
```
