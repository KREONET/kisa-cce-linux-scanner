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
| Ubuntu 26.04 LTS | `ubuntu:26.04` |
| Rocky Linux 8.10 | `rockylinux/rockylinux:8.10` |
| Rocky Linux 9.8 | `rockylinux/rockylinux:9.8` |
| Rocky Linux 10.2 | `rockylinux/rockylinux:10.2` |

Prepare a test image for each tag with the distribution's Bash, GNU base utilities, `make`, ShellCheck, `mandoc`, and `jq`. Keep those packages in the test image only; they do not become scanner production dependencies. Record the resolved image digest so a later run can distinguish source changes from image changes.

The examples below use `TEST_IMAGE` for one prepared image and derive the checkout path without embedding a developer-specific absolute path:

```bash
repository_root="$(git rev-parse --show-toplevel)"
TEST_IMAGE="kisa-cce-test:ubuntu-26.04"
```

Repeat the validation and smoke steps for every row in the matrix.

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
  /bin/bash -lc 'make lint && mandoc -T lint man/kisa-cce-scan.8 && mandoc -T lint man/kisa-cce-collect.8'
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
