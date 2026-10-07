# Automated Linux guest tests

The test launcher runs the same Linux guest validation with Apple `container`
on macOS or QEMU on Linux and macOS. The host needs Git and Python 3.9 or newer.
Python and the virtualization tools are development dependencies only.

## Backends and prerequisites

| Backend | Host tools | Test image |
|---|---|---|
| `apple` | Apple `container` with its service running | Prepared Linux OCI image, or a supported base image with `--prepare` |
| `qemu` | `qemu-img`, `qemu-system-x86_64` or `qemu-system-aarch64`, OpenSSH client and `ssh-keygen`, and one seed builder: `cloud-localds`, `xorriso`, `genisoimage`, or macOS `hdiutil` | Trusted local raw or qcow2 Linux cloud image with cloud-init and SSH |

Run the launcher without host `sudo`. Native Windows execution is unsupported;
use a Linux environment with the required virtualization tools.
For QEMU, obtain a cloud image for the guest architecture from its distribution
and verify the published checksum before testing. The launcher does not download
VM images. QEMU leaves the base image unchanged and writes to a disposable overlay. See
[QEMU disk images](https://www.qemu.org/docs/master/system/images.html) for backing
images and [cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
for the local configuration seed.

Use the distribution's Bash and ShellCheck versions. With `--prepare`, the
launcher installs test dependencies in each disposable guest from Ubuntu,
Debian, Rocky Linux, or Fedora apt or dnf repositories. Preparation needs guest
network access. It installs no host packages and does not save a prepared
image. Omit `--prepare` if the image already has the required packages.

Every suite checks for Bash 4.3+, make, ShellCheck, mandoc, jq, find, stat,
runuser, and getent. The guest also needs standard base utilities and
account-management commands. QEMU images must include sudo; the launcher uses
cloud-init to configure passwordless sudo for its temporary test account.

## Run a suite

Run commands from the repository root. Replace the example image names and
filesystem paths with images already available on the host.

```bash
container system start
python3 tools/testing/run.py --backend apple \
  --matrix supported --prepare --suite all \
  --output-dir /tmp/cce-apple-run-001
```

On an x86_64 Linux host:

```bash
python3 tools/testing/run.py --backend qemu \
  --image /path/to/debian-13-amd64.qcow2 --arch x86_64 \
  --prepare --suite all --output-dir /tmp/cce-qemu-run-001
```

For an aarch64 guest, provide the QEMU-compatible UEFI firmware installed on the
host:

```bash
python3 tools/testing/run.py --backend qemu \
  --image /path/to/ubuntu-arm64.img --arch aarch64 \
  --firmware /path/to/edk2-aarch64-code.fd \
  --prepare --suite all --output-dir /tmp/cce-qemu-arm-run-001
```

`--accel auto` selects an available acceleration mode. Use `--accel tcg` for
software emulation, including a guest architecture different from the host.
Use `--cpu MODEL` when the guest requires a specific CPU feature level.
The runner defaults to `max` with TCG and `host` with hardware acceleration
to expose CPU features required by current Rocky Linux releases. Hardware
acceleration still requires a host CPU that meets the guest requirements. See the
[QEMU CPU model reference](https://www.qemu.org/docs/master/system/qemu-cpu-models.html).
`--accel kvm` and `--accel hvf` require the corresponding host facility. TCG runs
may need longer `--boot-timeout` and `--timeout` values. Set `--cpus` and `--memory`
(in MiB) to control guest resources. Consult `--help` for defaults.

Use `--dry-run` to inspect the backend, images, suite, and source paths before
starting a guest. It does not verify that an image boots or a test passes.

The Makefile calls the same launcher and passes options through `TEST_ARGS`:

```bash
make check-runner
make test-apple TEST_ARGS="--matrix supported --prepare --suite all"
make test-qemu TEST_ARGS="--matrix supported --image-dir /path/to/cloud-images --arch x86_64 --prepare"
```

`check-runner` tests the host automation without booting a guest; the Linux
suites are still required. The launcher snapshots tracked and non-ignored
untracked files from the current checkout, excluding Git metadata. Both
backends mount this snapshot read-only in the guest, so tests include
uncommitted source changes.

## Suites and matrix

| Suite | Validation |
|---|---|
| `check` | Repository `make check` |
| `lint` | Repository `make lint` and manual-page lint |
| `smoke` | Project smoke checks described below |
| `all` | Correctness, lint, and smoke checks |

Scanner correctness and lint run as UID/GID 1000 so root cannot bypass
unreadable-file fixtures. Smoke checks run as root and validate a static
67-result scan, report counts, parsing, permissions, and debug output.
`make check` covers staged installation.

On Fedora, smoke checks first verify that the scanner rejects the unsupported
platform by default. They then run and log an exploratory scan with
`--allow-unsupported`, checking the warning and report structure. These tests
cover userspace compatibility and do not add Fedora to production support.

Use `--matrix supported` to run the reviewed distribution matrix sequentially.
The launcher continues after a failed image but stops on an interrupt.
The snapshot in [`supported-matrix.json`](../../tools/testing/supported-matrix.json)
was reviewed on 2026-09-08:

| Distribution | Releases |
|---|---|
| Ubuntu | 22.04 LTS, 24.04 LTS, 26.04 LTS |
| Debian | 12, 13 |
| Rocky Linux | 8.10, 9.8, 10.2 |
| Fedora | 43, 44 |

The matrix covers upstream standard security maintenance, including Debian LTS.
It excludes subscription-only extended maintenance and development releases.
Consult the official [Ubuntu release cycle](https://ubuntu.com/about/release-cycle),
[Debian releases](https://www.debian.org/releases/),
[Rocky Linux releases](https://docs.rockylinux.org/latest/releases/), and
[Fedora lifecycle](https://docs.fedoraproject.org/en-US/releases/lifecycle/)
when reviewing the snapshot. Update the JSON and this table when a release is
added or reaches end of support. The launcher reads the checked-in snapshot;
it does not query lifecycle services during a run.

```bash
python3 tools/testing/run.py --backend apple --matrix supported \
  --prepare --suite all --output-dir /tmp/cce-apple-matrix-001
```

Repeat `--distribution` to select one or more families:

```bash
python3 tools/testing/run.py --backend apple --matrix supported \
  --distribution debian --distribution fedora --prepare --suite all
```

For QEMU, place verified local cloud images in `--image-dir` using
`<distribution>-<version>-<architecture>.qcow2` names, such as
`debian-13-x86_64.qcow2` and `fedora-44-x86_64.qcow2`.
Use `aarch64` instead of `x86_64` for that guest architecture. Every selected
image must be present before any guest starts. `--dry-run` prints the expected
paths without requiring those files to exist.

```bash
python3 tools/testing/run.py --backend qemu --matrix supported \
  --image-dir /path/to/cloud-images --arch x86_64 \
  --prepare --suite all --output-dir /tmp/cce-qemu-matrix-001
```

All images in a run must use the selected architecture and firmware. Use
separate invocations for different architectures. Record image digests or
checksums with the test results to distinguish images that reuse the same tag.

Use `--image` for a prepared image or custom test target; repeat it to run
several images. It is mutually exclusive with `--matrix`.
Custom images are not certified against the lifecycle snapshot. The
`--distribution` and `--image-dir` options require `--matrix supported`.
The generated plan records the selected releases, review date, and support scope.

## Results and limits

Use a new `--output-dir` for each run. If omitted, the launcher creates one
under the repository's `.test-results/` directory. It saves logs and a JSON
summary (`summary.json`), with a separate numbered directory for each matrix
image. Guest phase logs and `phases.tsv` record each validation stage.
Check the summary and guest logs before reporting a pass. A preparation, boot,
or transport failure leaves the test incomplete. Keep failure logs for diagnosis.

The guest suite tests repository behavior and static scan or fixture results.
Although QEMU boots a full VM, the standard suite does not cover every native
service, vendor, package, network, or reboot acceptance requirement. Configure
the actual services and reviewed inputs required by each criterion, then run
and record the separate acceptance checks. Never report an unexecuted matrix
row as tested.
