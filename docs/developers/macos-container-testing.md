# Testing with Apple container on macOS

For scripted Apple and QEMU runs, use [automated Linux guest tests](test-automation.md).

Run the scanner's Linux validation matrix from an Apple silicon Mac with Apple's `container` command. It runs OCI images in lightweight Linux virtual machines. These tests do not replace acceptance testing on booted systems with a real systemd manager, listeners, mount topology, and native validators.

Apple supports `container` on Apple silicon with macOS 26 or later. Install the latest signed package from the [Apple container releases](https://github.com/apple/container/releases) using the [official installation instructions](https://github.com/apple/container#initial-install). Keep this guide independent of a developer's installed `container` version. Check the command reference for the installed release because commands can vary by release and macOS version.

Upstream references:

- [Apple container repository and requirements](https://github.com/apple/container)
- [Container CLI command reference](https://github.com/apple/container/blob/main/docs/command-reference.md)
- [Mounts and volumes](https://github.com/apple/container/blob/main/docs/volumes.md)

## Start and inspect the service

Start the per-user container services. The first invocation may prompt to install the default Linux kernel:

```bash
container system start
```

List running and stopped containers before testing:

```bash
container list --all
```

Apple `container` reads and writes OCI-compatible images. On Apple silicon, use arm64 Linux images unless a compatibility test specifically requires another architecture.

## Test matrix

Run the matrix reviewed on 2026-09-08. The [automated test guide](test-automation.md)
defines lifecycle scope and the checked-in release snapshot. Use
`make test-apple TEST_ARGS="--matrix supported --prepare"` to execute it:

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
| Fedora 43 | `registry.fedoraproject.org/fedora:43` |
| Fedora 44 | `registry.fedoraproject.org/fedora:44` |

For each tag, prepare an image with the distribution's Bash, GNU findutils,
compatible base utilities, `make`, ShellCheck, `mandoc`, and `jq`. Keep Ubuntu
26.04's compatible rust-coreutils commands; do not replace them just to pass an
implementation-name check. These test packages are not scanner production
dependencies. Record each resolved image digest to distinguish source changes
from image changes in later runs.

Set `TEST_IMAGE` to a prepared image. The examples derive the checkout path from Git:

```bash
repository_root="$(git rev-parse --show-toplevel)"
TEST_IMAGE="kisa-cce-test:ubuntu-26.04"
```

Repeat validation for every matrix row. The manual scanner smoke check below
assumes a production-supported platform. For Fedora, use the automated smoke
check. It verifies default rejection, then runs an exploratory
`--allow-unsupported` scan and checks its warning and reports. Testing Fedora
userspace does not expand production platform support.

### Ubuntu 26.04 command-capability check

Keep the Ubuntu 26.04 image's default mix of coreutils providers for at least
one matrix run. Ubuntu ships rust-coreutils 0.8.0 by default but retains GNU
coreutils 9.7 for `cp`, `mv`, and `rm`. Replacing either provider before testing
would leave the default configuration untested. See the official
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

The test runs the scanner's option forms for `stat`, `readlink`, `sort`, `date`,
`sha256sum`, and `install`. It checks behavior without using implementation
names or version output to accept or reject a provider. Expect `PASS` on Ubuntu
26.04 and `SKIP` on other matrix rows. `make check` also runs this test.

Chrony is the default for new Ubuntu 26.04 installations. If ntpd-rs is added
to a base image, do not describe it as the distribution default. The
repository's `tests/ntpd_rs.sh` covers the optional provider's configuration,
service, runtime-status, and policy paths. Test a separate ntpd-rs image as an
extension. See the
[Ubuntu Chrony note](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#chrony)
and [Canonical transition plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154).

## Non-root correctness and lint gates

Mount the checkout read-only. Run fixtures that test permissions as UID and GID 1000 so root privileges cannot bypass unreadable-file cases:

```bash
container run --rm \
  --uid 1000 \
  --gid 1000 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc 'make check'
```

Run lint in the same distribution environment:

```bash
container run --rm \
  --uid 1000 \
  --gid 1000 \
  --mount type=bind,source="$repository_root",target=/src,readonly \
  --workdir /src \
  "$TEST_IMAGE" \
  /bin/bash -lc 'make lint && mandoc -T lint man/kisa-cce-scan.8 && mandoc -T lint man/kisa-cce-collect.8 && mandoc -T lint man/kisa-cce-policy-compile.8'
```

The read-only bind mount checks that tests and package staging work from protected temporary directories without modifying the checkout. For the `--mount` syntax and key-only `readonly` option, see Apple's [mount option reference](https://github.com/apple/container/blob/main/docs/volumes.md#options-for---mount).

## Root debug smoke and report checks

Run one full static scan as container root, with the repository mounted read-only and reports written to the container's temporary filesystem:

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

Exit status 1 means the scan completed with at least one `VULNERABLE` result. Exit status 2 can also follow a completed scan in a minimal container if a criterion reports `ERROR`. The report existence and integrity checks above distinguish that case from an invocation that failed before producing reports. Review the final JSONL summary and debug stream before classifying either status as a harness failure.

## Two different debug options

Apple `container` and the scanner each have a `--debug` option:

| Invocation | Diagnostic scope |
|---|---|
| `container --debug run ...` | Apple container client, service, VM, image, mount, and runtime operations |
| `kisa-cce-scan --debug ...` | Scanner lifecycle, criterion dispatch, resolver snapshots, cache decisions, collection state, and report validation |

To debug Apple `container`, put its global option before `run`. To debug the scanner, put the option after `kisa-cce-scan` inside the guest command. The options work independently. Treat both output streams as sensitive because they can contain environment or assessment metadata.

## Optional offline image-preparation workaround

Use this optional local workaround only when an Apple container guest cannot reach distribution package repositories and a separately installed Docker or BuildKit environment has network access. It is not part of the normal project workflow.

Use Docker Buildx to build an arm64 image with the test dependencies and export it as an OCI archive. The local Containerfile must use the matching matrix tag as its base and install only the test packages listed above:

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

Use an equivalent Containerfile that installs the required packages for Debian-family and Rocky Linux images. Do not commit credentials, proxy configuration, repository tokens, or package caches. After loading the image, set `TEST_IMAGE` to the imported reference shown by `container image list`. See the [official command reference](https://github.com/apple/container/blob/main/docs/command-reference.md#container-image-load) for `container image load --input` and Docker's [OCI exporter documentation](https://docs.docker.com/build/exporters/oci-docker/) for archive creation.

Only image preparation changes. Keep the checkout mounted read-only and use the same UID/GID and report checks in the Apple workflow. Other hosts can use the QEMU workflow.

## Cleanup

Each run example uses `container run --rm` to remove the container when its command exits. Check for any stopped test containers:

```bash
container list --all
```

Delete only the test images and archives created for this run:

```bash
container image delete "$TEST_IMAGE"
rm -rf -- "$temporary_directory"
```

Do not use unscoped delete commands on workstations that may contain unrelated containers or images. Stop the Apple container services only when no other local work needs them:

```bash
container system stop
```
