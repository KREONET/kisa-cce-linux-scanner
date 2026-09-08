# Automated Linux guest tests

Run the same Linux guest validation through Apple `container` on macOS or QEMU
on Linux and macOS. The host launcher requires Git and Python 3.9 or newer. Python and
the virtualization tools are development dependencies only.

## Backends and prerequisites

| Backend | Host tools | Test image |
|---|---|---|
| `apple` | Apple `container` with its service running | Prepared Linux OCI image, or a supported base image with `--prepare` |
| `qemu` | `qemu-img`, `qemu-system-x86_64` or `qemu-system-aarch64`, OpenSSH client and `ssh-keygen`, and one seed builder: `cloud-localds`, `xorriso`, `genisoimage`, or macOS `hdiutil` | Trusted local raw or qcow2 Linux cloud image with cloud-init and SSH |

Run the launcher without host `sudo`. Native Windows execution is not supported;
use a suitable Linux environment with the required virtualization tools.
For QEMU, obtain the matching architecture's cloud image from its distribution
and verify its published checksum before testing. The launcher does not download
VM images. QEMU uses a disposable overlay and preserves the base image. See
[QEMU disk images](https://www.qemu.org/docs/master/system/images.html) for backing
images and [cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
for the local configuration seed.

Use the distribution-provided Bash and ShellCheck versions. `--prepare` installs
test dependencies inside each disposable guest using Debian-family or RHEL-family
package repositories. It requires guest network access, installs no host packages, and does not persist a
prepared image. Omit it when the image already contains the required packages. Every suite
checks for Bash 4.3+, make, ShellCheck, mandoc, jq, find, stat, runuser, and getent.
The guest also needs standard base utilities and account-management commands.
QEMU images must include sudo. The launcher configures passwordless sudo for its
ephemeral test account through cloud-init.

## Run a suite

Run from this repository's root. Image names and filesystem paths below are
placeholders for images already available on your machine.

```bash
container system start
python3 tools/testing/run.py --backend apple \
  --image kisa-cce-test:ubuntu-26.04 --suite all \
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
Use `--cpu MODEL` when the guest requires a specific CPU feature level;
`--cpu max` exposes the emulated feature set available with TCG. The default x86
CPU model may lack features required by newer distribution images. See the
[QEMU CPU model reference](https://www.qemu.org/docs/master/system/qemu-cpu-models.html).
`--accel kvm` and `--accel hvf` require the corresponding host facility. TCG runs
can need a larger `--boot-timeout` and `--timeout`. Set `--cpus` and `--memory`
(in MiB) to control guest resources. Consult `--help` for defaults.

Add `--dry-run` to inspect the selected backend, images, suite, and source paths before starting a
guest. A dry run does not demonstrate that an image boots or a test passes.

The Makefile exposes the same launcher without duplicating backend options:

```bash
make check-runner
make test-apple TEST_ARGS="--image kisa-cce-test:ubuntu-26.04 --suite all"
make test-qemu TEST_ARGS="--image /path/to/debian-13-amd64.qcow2 --arch x86_64 --prepare"
```

`check-runner` checks the host automation; it does not boot a guest or replace
the Linux suites. The launcher snapshots tracked and non-ignored untracked
files from the current checkout, excluding Git metadata. Both backends expose
the snapshot read-only inside the guest. Uncommitted source changes are tested.

## Suites and matrix

| Suite | Validation |
|---|---|
| `check` | Repository `make check` |
| `lint` | Repository `make lint` and manual-page lint |
| `smoke` | Project smoke checks described below |
| `all` | Correctness, lint, and smoke checks |

Scanner correctness and lint run as UID/GID 1000 so root cannot bypass
unreadable-file fixtures. Root smoke validates a static 67-result scan, report cardinality, parsing,
permissions, and debug output. Staged installation is covered by `make check`.

Repeat `--image` to test a matrix sequentially with the same suite and options.
A failed image does not stop the remaining matrix rows; an interrupt does:

```bash
python3 tools/testing/run.py --backend apple --prepare \
  --image debian:12-slim --image debian:13-slim \
  --image ubuntu:22.04 --image ubuntu:24.04 --image ubuntu:26.04 \
  --image rockylinux/rockylinux:8.10 --image rockylinux/rockylinux:9.8 \
  --image rockylinux/rockylinux:10.2 --suite all \
  --output-dir /tmp/cce-apple-matrix-001
```

For QEMU, repeat `--image` with corresponding local cloud-image paths. All images
in one invocation must use the selected architecture and firmware. Split mixed
architecture matrices into separate invocations. Record image digests or
checksums with the validation evidence so repeated tags can be distinguished.

## Results and limits

Use a new `--output-dir` for each run. When omitted, it is generated below
`.test-results/` in the repository. The launcher retains logs and a JSON
summary (`summary.json`), with separate numbered directories for matrix images.
Guest phase logs and `phases.tsv` record the individual validation stages. Check the
summary and guest logs before reporting a pass. A preparation, boot, or transport
failure is not a completed test. Keep failure logs for diagnosis.

The guest suite tests repository behavior and static scan or fixture results.
QEMU boots a full VM, but the standard suite does not establish all native
service, vendor, package, network, or reboot acceptance requirements. Add the
actual services and reviewed inputs required by a criterion and record the
separate acceptance checks. Never describe an unexecuted matrix row as tested.
