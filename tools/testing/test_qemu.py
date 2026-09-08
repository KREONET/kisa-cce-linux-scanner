# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Exercise QEMU failure cleanup without requiring a hypervisor or cloud image."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("qemu_backend", Path(__file__).with_name("qemu_backend.py"))
BACKEND = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKEND)


class FakeVM:
    def __init__(self):
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class QemuCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.image = self.directory / "image.qcow2"
        self.image.touch()
        self.payload = self.directory / "payload.tar.gz"
        self.payload.touch()
        self.output = self.directory / "results"
        self.vm = FakeVM()
        self.key = None
        self.interrupt_test = False
        self.exit_vm_after_test = False
        self.args = SimpleNamespace(image=self.image, arch="x86_64", accel="tcg", firmware=None,
                                    cpus=1, memory=256, boot_timeout=2, timeout=2,
                                    project="scanner", suite="smoke", prepare=False)
        for target, options in [
            ("shutil.which", {"return_value": "/mock/tool"}),
            ("_command", {"side_effect": self.command}),
            ("_seed", {}),
            ("subprocess.Popen", {"return_value": self.vm}),
        ]:
            owner = BACKEND
            components = target.split(".")
            for component in components[:-1]:
                owner = getattr(owner, component)
            patcher = patch.object(owner, components[-1], **options)
            patcher.start()
            self.addCleanup(patcher.stop)

    def command(self, command, log, timeout=60, stdin=None, stdout=None):
        if command[:2] == ["qemu-img", "info"]:
            stdout.write(b'{"format":"qcow2"}')
        if command[0] == "ssh-keygen":
            self.key = Path(command[-1])
            self.key.with_suffix(".pub").write_text("ssh-ed25519 test")
        if command[0] == "ssh":
            if command[-1].startswith("sudo -n tar -cf"):
                return 1
            if self.interrupt_test and command[-1].startswith("sudo -n env"):
                raise KeyboardInterrupt()
            if self.exit_vm_after_test and command[-1].startswith("sudo -n env"):
                self.vm.returncode = 1
        return 0

    def assert_cleaned_up(self):
        self.assertEqual(self.vm.returncode, 0)
        self.assertIsNotNone(self.key)
        self.assertFalse(self.key.parent.exists())

    def test_failed_collection_cannot_report_success(self):
        with self.assertRaisesRegex(RuntimeError, "collection failed"):
            BACKEND.run_qemu(self.args, self.payload, self.output)
        self.assert_cleaned_up()
        self.assertEqual(json.loads((self.output / "image.json").read_text())["format"], "qcow2")

    def test_boot_timeout_stops_vm_and_deletes_secrets(self):
        with patch.object(BACKEND.time, "monotonic", side_effect=[0, 3]):
            with self.assertRaisesRegex(RuntimeError, "Timed out"):
                BACKEND.run_qemu(self.args, self.payload, self.output)
        self.assert_cleaned_up()

    def test_collection_failure_preserves_interruption(self):
        self.interrupt_test = True
        with self.assertRaises(KeyboardInterrupt):
            BACKEND.run_qemu(self.args, self.payload, self.output)
        self.assert_cleaned_up()
        self.assertIn("collection also failed", (self.output / "commands.log").read_text())

    def test_vm_exit_before_collection_cannot_report_success(self):
        self.exit_vm_after_test = True
        with self.assertRaisesRegex(RuntimeError, "exited before guest results"):
            BACKEND.run_qemu(self.args, self.payload, self.output)
        self.assertEqual(self.vm.returncode, 1)
        self.assertFalse(self.key.parent.exists())

    def test_default_cpu_exposes_features_required_by_matrix(self):
        for acceleration, expected in (("tcg", "max"), ("kvm", "host"), ("hvf", "host")):
            with self.subTest(acceleration=acceleration), \
                    patch.object(BACKEND, "_acceleration", return_value=acceleration):
                self.vm.returncode = None
                with self.assertRaisesRegex(RuntimeError, "collection failed"):
                    BACKEND.run_qemu(self.args, self.payload, self.output)
                command = BACKEND.subprocess.Popen.call_args.args[0]
                self.assertEqual(command[command.index("-cpu") + 1], expected)

    def test_explicit_cpu_model_is_passed_as_one_argument(self):
        self.args.cpu = "max"
        with self.assertRaisesRegex(RuntimeError, "collection failed"):
            BACKEND.run_qemu(self.args, self.payload, self.output)
        command = BACKEND.subprocess.Popen.call_args.args[0]
        self.assertEqual(command[command.index("-cpu") + 1], "max")
        self.assertEqual(command.count("-cpu"), 1)


if __name__ == "__main__":
    unittest.main()
