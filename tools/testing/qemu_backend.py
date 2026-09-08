# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Disposable NoCloud VM runner with no host filesystem sharing."""

import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _command(command, log, timeout=60, stdin=None, stdout=None):
    log.write(("$ " + shlex.join([str(part) for part in command]) + "\n").encode())
    log.flush()
    process = subprocess.Popen(command, stdin=stdin or subprocess.DEVNULL,
                               stdout=stdout or log, stderr=log)
    try:
        return process.wait(timeout=timeout)
    finally:
        _stop(process)


def _seed(seed, iso, log):
    if shutil.which("cloud-localds"):
        command = ["cloud-localds", str(iso), str(seed / "user-data"),
                   str(seed / "meta-data")]
    elif shutil.which("xorriso"):
        command = ["xorriso", "-as", "mkisofs", "-o", str(iso),
                   "-V", "cidata", "-J", "-r", str(seed)]
    elif shutil.which("genisoimage"):
        command = ["genisoimage", "-output", str(iso), "-volid", "cidata",
                   "-joliet", "-rock", str(seed)]
    elif shutil.which("hdiutil"):
        command = ["hdiutil", "makehybrid", "-o", str(iso), str(seed),
                   "-iso", "-joliet", "-default-volume-name", "cidata"]
    else:
        raise RuntimeError("Install cloud-localds, xorriso, or genisoimage (macOS also supports hdiutil).")
    if _command(command, log):
        raise RuntimeError("Could not create the cloud-init seed; see commands.log.")


def _acceleration(args):
    host_arch = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    if args.accel != "auto":
        return args.accel
    if host_arch == args.arch:
        if platform.system() == "Darwin":
            return "hvf"
        if platform.system() == "Linux" and os.access("/dev/kvm", os.R_OK | os.W_OK):
            return "kvm"
    return "tcg"


def _extract_results(archive, destination):
    # Guest archives are data, never a reason to follow paths outside the result directory.
    with tarfile.open(archive) as result:
        members = result.getmembers()
        for member in members:
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError("Guest results contain an unsafe archive member.")
        destination.mkdir(parents=True, exist_ok=True)
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with result.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)


def run_qemu(args, payload: Path, output: Path) -> int:
    """Run the guest suite and return its exit status, or raise for infrastructure failures."""
    executable = "qemu-system-" + args.arch
    missing = [name for name in (executable, "qemu-img", "ssh", "ssh-keygen")
               if not shutil.which(name)]
    if missing:
        raise RuntimeError("Missing QEMU runner tools: " + ", ".join(missing))
    image = Path(args.image).expanduser().resolve()
    if not image.is_file():
        raise RuntimeError("Cloud image does not exist: " + str(image))
    firmware = Path(args.firmware).expanduser().resolve() if args.firmware else None
    if args.arch == "aarch64" and firmware is None:
        raise RuntimeError("aarch64 requires --firmware pointing to compatible AAVMF/QEMU_EFI firmware.")
    if firmware is not None and not firmware.is_file():
        raise RuntimeError("Firmware does not exist: " + str(firmware))
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kisa-cce-qemu-") as temporary, \
            (output / "commands.log").open("wb") as log:
        temp = Path(temporary)
        metadata = temp / "image.json"
        with metadata.open("wb") as info:
            if _command(["qemu-img", "info", "--output=json", str(image)], log, stdout=info):
                raise RuntimeError("Cannot inspect cloud image; see commands.log.")
        image_format = json.loads(metadata.read_text())["format"]
        shutil.copyfile(metadata, output / "image.json")
        if image_format not in ("raw", "qcow2"):
            raise RuntimeError("Only raw and qcow2 cloud images are supported.")
        overlay = temp / "disk.qcow2"
        if _command(["qemu-img", "create", "-f", "qcow2", "-F", image_format,
                     "-b", str(image), str(overlay)], log):
            raise RuntimeError("Cannot create disposable image overlay; see commands.log.")
        key = temp / "identity"
        if _command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], log):
            raise RuntimeError("Cannot generate ephemeral SSH key.")
        seed = temp / "seed"
        seed.mkdir()
        public = key.with_suffix(".pub").read_text().strip()
        (seed / "user-data").write_text(
            "#cloud-config\nusers:\n  - name: cce-test\n    lock_passwd: true\n"
            "    shell: /bin/bash\n    sudo: ['ALL=(ALL) NOPASSWD:ALL']\n"
            "    ssh_authorized_keys:\n      - " + public + "\n"
            "ssh_pwauth: false\ndisable_root: true\n")
        (seed / "meta-data").write_text("instance-id: cce-" + uuid.uuid4().hex + "\nlocal-hostname: cce-test\n")
        iso = temp / "seed.iso"
        _seed(seed, iso, log)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        accel = _acceleration(args)
        command = [executable, "-machine", "virt" if args.arch == "aarch64" else "q35",
                   "-accel", accel, "-m", str(args.memory), "-smp", str(args.cpus),
                   "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
                   "-drive", "file=" + str(overlay).replace(",", ",,") + ",if=virtio,format=qcow2",
                   "-drive", "file=" + str(iso).replace(",", ",,") + ",if=virtio,format=raw,readonly=on",
                   "-nic", "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22"]
        if getattr(args, "cpu", None):
            command += ["-cpu", args.cpu]
        elif args.arch == "aarch64":
            command += ["-cpu", "max" if accel == "tcg" else "host"]
        if firmware is not None:
            command += ["-bios", str(firmware)]
        ssh = ["ssh", "-F", "/dev/null", "-i", str(key), "-p", str(port),
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
               "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "UserKnownHostsFile=" + str(temp / "known_hosts"), "cce-test@127.0.0.1"]
        log.write(("$ " + shlex.join(command) + "\n").encode())
        log.flush()
        with (output / "qemu.log").open("wb") as console:
            vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=console, stderr=console)
            ready = False
            try:
                deadline = time.monotonic() + args.boot_timeout
                with (output / "boot.log").open("wb") as boot:
                    while time.monotonic() < deadline:
                        if vm.poll() is not None:
                            raise RuntimeError("QEMU exited during boot; see qemu.log.")
                        try:
                            status = _command(ssh + ["sudo -n true"], boot,
                                              timeout=min(15, max(1, deadline - time.monotonic())))
                        except subprocess.TimeoutExpired:
                            status = 255
                        if status == 0:
                            ready = True
                            break
                        time.sleep(min(2, max(0, deadline - time.monotonic())))
                if not ready:
                    raise RuntimeError("Timed out waiting for cloud-init SSH access; see boot.log and qemu.log.")
                with payload.open("rb") as source:
                    status = _command(ssh + ["sudo -n mkdir -p /opt/kisa-cce-tests && "
                        "sudo -n tar -xzf - -C /opt/kisa-cce-tests && "
                        "sudo -n chown -R root:root /opt/kisa-cce-tests && "
                        "sudo -n chmod -R a+rX /opt/kisa-cce-tests && "
                        "for source in /opt/kisa-cce-tests/kisa-cce-linux-*; do "
                        "sudo -n mount --bind \"$source\" \"$source\" && "
                        "sudo -n mount -o remount,bind,ro \"$source\" || exit; done"],
                        log, timeout=120, stdin=source)
                if status:
                    raise RuntimeError("Cannot upload the test payload; see commands.log.")
                guest_command = ["sudo", "-n", "env", "KISA_CCE_TEST_GUEST=1", "/bin/bash",
                                 "/opt/kisa-cce-tests/guest.sh", args.project, args.suite]
                if args.prepare:
                    guest_command.append("--prepare")
                with (output / "test.log").open("wb") as test_log:
                    try:
                        return _command(ssh + [shlex.join(guest_command)], test_log, timeout=args.timeout)
                    except subprocess.TimeoutExpired:
                        test_log.write(b"\nGuest test timeout exceeded.\n")
                        return 124
            finally:
                original_error = sys.exc_info()[0]
                try:
                    if ready:
                        if vm.poll() is not None:
                            raise RuntimeError("QEMU exited before guest results could be collected; see qemu.log.")
                        archive = temp / "results.tar"
                        with archive.open("wb") as result:
                            status = _command(ssh + ["sudo -n tar -cf - -C /tmp/kisa-cce-test-results ."],
                                              log, timeout=30, stdout=result)
                        if status == 0:
                            _extract_results(archive, output / "guest")
                        else:
                            raise RuntimeError("Guest result collection failed; test.log and qemu.log remain available.")
                except Exception as error:
                    if original_error is None:
                        raise
                    log.write(("Guest result collection also failed: " + str(error) + "\n").encode())
                finally:
                    _stop(vm)
