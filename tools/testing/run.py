#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Run the Linux test suite in disposable Apple container or QEMU guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from qemu_backend import run_qemu


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--backend", required=True, choices=("apple", "qemu"))
    result.add_argument("--image", required=True, action="append", help="OCI reference or local cloud disk; repeat for a matrix")
    result.add_argument("--suite", default="all", choices=("all", "check", "lint", "smoke"))
    result.add_argument("--scanner-dir", type=Path, help="scanner checkout for patcher integration")
    result.add_argument("--output-dir", type=Path, help="new directory for logs and summary.json")
    result.add_argument("--prepare", action="store_true", help="install test tools inside each disposable guest")
    result.add_argument("--arch", choices=("x86_64", "aarch64"), default="aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64")
    result.add_argument("--accel", choices=("auto", "tcg", "kvm", "hvf"), default="auto")
    result.add_argument("--cpu", help="explicit QEMU CPU model, for example max with TCG")
    result.add_argument("--firmware", type=Path, help="QEMU firmware image; required for aarch64")
    result.add_argument("--cpus", type=positive, default=2)
    result.add_argument("--memory", type=positive, default=2048, help="guest memory in MiB")
    result.add_argument("--boot-timeout", type=positive, default=600)
    result.add_argument("--timeout", type=positive, default=3600, help="test timeout in seconds per image")
    result.add_argument("--dry-run", action="store_true", help="print the plan without creating a guest or requiring backend tools")
    return result


def source_files(repository):
    completed = subprocess.run(
        ["git", "-c", "safe.directory=" + str(repository), "-C", str(repository), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True, stdout=subprocess.PIPE,
    )
    paths = []
    for raw in sorted(set(completed.stdout.split(b"\0")) - {b""}):
        relative = Path(os.fsdecode(raw))
        if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
            raise ValueError("unsafe source inventory path")
        source = repository / relative
        if source.is_symlink() or any(parent.is_symlink() for parent in source.parents if parent != repository.parent):
            raise ValueError("source symlinks are unsupported: " + str(source))
        if source.is_file():
            paths.append(relative)
    return paths


def snapshot(repositories, destination):
    """Copy the current non-ignored worktree without Git metadata or host mounts."""
    metadata = {}
    for name, repository in repositories.items():
        target = destination / name
        target.mkdir(mode=0o755)
        digest = hashlib.sha256()
        files = source_files(repository)
        for relative in files:
            source = repository / relative
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            content = source.read_bytes()
            output.write_bytes(content)
            output.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
            digest.update(os.fsencode(relative.as_posix()) + b"\0" + str(output.stat().st_mode & 0o777).encode() + b"\0" + hashlib.sha256(content).digest())
        revision = subprocess.run(["git", "-c", "safe.directory=" + str(repository), "-C", str(repository), "rev-parse", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        metadata[name] = {"revision": revision.stdout.strip() if revision.returncode == 0 else None,
                          "snapshot_sha256": digest.hexdigest(), "files": len(files)}
    destination.chmod(0o755)
    for directory in destination.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    shutil.copyfile(Path(__file__).with_name("guest.sh"), destination / "guest.sh")
    (destination / "guest.sh").chmod(0o644)
    return metadata


def run_apple(args, source, output):
    if platform.system() != "Darwin":
        raise ValueError("Apple container requires macOS; choose --backend qemu on Linux")
    if not shutil.which("container"):
        raise ValueError("container executable is missing; install and start Apple container")
    guest_output = output / "guest"
    guest_output.mkdir(mode=0o700)
    if any("," in str(path) for path in (source, guest_output)):
        raise ValueError("Apple mount source paths cannot contain commas")
    name = "kisa-cce-test-" + uuid.uuid4().hex[:16]
    command = ["container", "run", "--rm", "--name", name, "--uid", "0", "--gid", "0",
               "--cpus", str(args.cpus), "--memory", str(args.memory) + "M",
               "--arch", "arm64" if args.arch == "aarch64" else "amd64",
               "--mount", "type=bind,source=" + str(source) + ",target=/opt/kisa-cce-tests,readonly",
               "--mount", "type=bind,source=" + str(guest_output) + ",target=/tmp/kisa-cce-test-results",
               "--env", "KISA_CCE_TEST_GUEST=1", args.image,
               "/bin/bash", "/opt/kisa-cce-tests/guest.sh", args.project, args.suite]
    if args.prepare:
        command.append("--prepare")
    with (output / "command.json").open("w") as handle:
        json.dump(command, handle, indent=2)
    try:
        with (output / "test.log").open("wb") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
        return completed.returncode
    finally:
        # The unique name belongs to this run, including partially started guests.
        with (output / "cleanup.log").open("ab") as log:
            for cleanup in (["container", "stop", name], ["container", "delete", name]):
                try:
                    subprocess.run(cleanup, stdout=log, stderr=subprocess.STDOUT, timeout=30)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def phases(output):
    path = output / "guest" / "phases.tsv"
    if not path.exists():
        return []
    result = []
    for line in path.read_text(errors="replace").splitlines()[1:]:
        values = line.split("\t")
        if len(values) == 3:
            result.append(dict(zip(("phase", "status", "exit_code"), values)))
    return result


def validate_phases(args, observed):
    expected = {"prerequisites"}
    if args.prepare:
        expected.add("prepare")
    if args.suite in ("all", "check"):
        expected.add("check-user")
        if args.project == "patcher":
            expected.add("check-root")
    if args.suite in ("all", "lint"):
        expected.add("lint")
    if args.suite in ("all", "smoke"):
        expected.add("smoke")
    names = [entry["phase"] for entry in observed]
    if set(names) != expected or len(names) != len(expected) or any(
            entry["status"] != "passed" or entry["exit_code"] != "0" for entry in observed):
        raise RuntimeError("guest exited successfully without complete passing phase results")


def main(argv=None):
    args = parser().parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    args.project = "patcher" if (repository / "bin/kisa-cce-patch").exists() else "scanner"
    repositories = {"kisa-cce-linux-" + args.project: repository}
    if args.project == "patcher":
        scanner = (args.scanner_dir or repository.parent / "kisa-cce-linux-scanner").resolve()
        if not (scanner / "bin/kisa-cce-scan").is_file():
            raise ValueError("patcher integration requires --scanner-dir or a sibling scanner checkout")
        repositories["kisa-cce-linux-scanner"] = scanner
    if any(any(ord(character) < 32 for character in value) for value in args.image):
        raise ValueError("image references cannot contain control characters")
    if args.firmware:
        args.firmware = args.firmware.resolve()
    plan = {"backend": args.backend, "project": args.project, "suite": args.suite,
            "images": args.image, "arch": args.arch, "prepare": args.prepare,
            "cpu": args.cpu, "accel": args.accel,
            "firmware": str(args.firmware) if args.firmware else None,
            "cpus": args.cpus, "memory_mib": args.memory,
            "boot_timeout": args.boot_timeout, "timeout": args.timeout,
            "sources": {name: str(path) for name, path in repositories.items()}}
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    os.umask(0o077)
    output = (args.output_dir or repository / ".test-results" / (time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])).resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    summary = {"plan": plan, "runs": []}
    failed = False
    interrupted = False
    try:
        with tempfile.TemporaryDirectory(prefix="kisa-cce-test-") as temporary:
            source = Path(temporary) / "source"
            source.mkdir(mode=0o755)
            summary["sources"] = snapshot(repositories, source)
            payload = Path(temporary) / "source.tar.gz"
            with tarfile.open(payload, "w:gz") as archive:
                for path in sorted(source.iterdir()):
                    archive.add(path, arcname=path.name, recursive=True)
            for index, image in enumerate(plan["images"], 1):
                label = re.sub(r"[^A-Za-z0-9._-]", "_", Path(image).name)[-60:] or "image"
                image_output = output / (str(index).zfill(3) + "-" + label)
                image_output.mkdir(mode=0o700)
                args.image = image
                record = {"image": image, "output": str(image_output), "status": "error"}
                started = time.monotonic()
                print("RUN " + args.backend + " " + image, flush=True)
                try:
                    code = run_apple(args, source, image_output) if args.backend == "apple" else run_qemu(args, payload, image_output)
                    if code == 0:
                        validate_phases(args, phases(image_output))
                    record.update(exit_code=code, status="passed" if code == 0 else "failed")
                    failed = failed or code != 0
                except KeyboardInterrupt:
                    record.update(exit_code=130, status="interrupted")
                    failed = interrupted = True
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    record.update(exit_code=2, error=str(error))
                    failed = True
                record.update(seconds=round(time.monotonic() - started, 3), phases=phases(image_output))
                summary["runs"].append(record)
                print(record["status"].upper() + " " + image, flush=True)
                if interrupted:
                    break
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print("Results: " + str(output), flush=True)
    return 130 if interrupted else 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(2)
