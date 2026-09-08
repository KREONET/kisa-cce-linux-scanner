#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Host runner regressions; no container or QEMU installation is required."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import qemu_backend
import run as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # macOS /var is a symlink; the inventory accepts canonical roots.
        self.root = Path(self.temporary.name).resolve()
        original_umask = os.umask(0o077)
        self.addCleanup(os.umask, original_umask)

    def args(self, **changes):
        values = dict(cpus=2, memory=1024, arch="aarch64", image="example:latest",
                      project="scanner", suite="all", prepare=True, timeout=5,
                      accel="auto")
        values.update(changes)
        return SimpleNamespace(**values)

    @unittest.skipUnless(shutil.which("git"), "Git is needed for source inventory")
    def test_snapshot_uses_worktree_and_excludes_ignored_deleted_metadata(self):
        repo = self.root / "repository"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / ".gitignore").write_text("ignored\n")
        (repo / "tracked").write_text("old")
        (repo / "deleted").write_text("gone")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        (repo / "tracked").write_text("current uncommitted contents")
        (repo / "deleted").unlink()
        (repo / "ignored").write_text("private")
        (repo / "executable").write_text("#!/bin/sh\n")
        (repo / "executable").chmod(0o755)
        (repo / "nested").mkdir(mode=0o700)
        (repo / "nested/file").write_text("readable")
        destination = self.root / "snapshot"
        destination.mkdir()
        metadata = runner.snapshot({"project": repo}, destination)
        copied = destination / "project"
        self.assertEqual((copied / "tracked").read_text(), "current uncommitted contents")
        self.assertEqual((copied / "executable").stat().st_mode & 0o777, 0o755)
        self.assertEqual((copied / "tracked").stat().st_mode & 0o777, 0o644)
        for excluded in ("ignored", "deleted", ".git"):
            self.assertFalse((copied / excluded).exists())
        self.assertEqual(copied.stat().st_mode & 0o777, 0o755)
        self.assertEqual((copied / "nested").stat().st_mode & 0o777, 0o755)
        self.assertEqual(metadata["project"]["files"], 4)

    def test_inventory_rejects_symlinks_and_traversal(self):
        (self.root / "outside").write_text("secret")
        (self.root / "link").symlink_to(self.root / "outside")
        for inventory in (b"link\0", b"../outside\0", b"/absolute\0", b".git/config\0"):
            with self.subTest(inventory=inventory), mock.patch.object(
                    runner.subprocess, "run", return_value=SimpleNamespace(stdout=inventory)):
                with self.assertRaises(ValueError):
                    runner.source_files(self.root)

    def test_apple_commands_and_cleanup_for_success_failure_timeout_interrupt(self):
        cases = (0, 17, subprocess.TimeoutExpired("container", 5), KeyboardInterrupt())
        for index, outcome in enumerate(cases):
            with self.subTest(outcome=outcome):
                output = self.root / str(index)
                output.mkdir()
                calls = []

                def execute(command, **kwargs):
                    calls.append(command)
                    if command[1] == "run":
                        if isinstance(outcome, BaseException):
                            raise outcome
                        return SimpleNamespace(returncode=outcome)
                    return SimpleNamespace(returncode=0)

                with mock.patch.object(runner.platform, "system", return_value="Darwin"), \
                        mock.patch.object(runner.shutil, "which", return_value="/bin/container"), \
                        mock.patch.object(runner.subprocess, "run", side_effect=execute):
                    if isinstance(outcome, BaseException):
                        with self.assertRaises(type(outcome)):
                            runner.run_apple(self.args(), self.root, output)
                    else:
                        self.assertEqual(runner.run_apple(self.args(), self.root, output), outcome)
                command = calls[0]
                name = command[command.index("--name") + 1]
                self.assertTrue(name.startswith("kisa-cce-test-"))
                self.assertEqual(calls[1:], [["container", "stop", name], ["container", "delete", name]])
                self.assertEqual(command[command.index("--arch") + 1], "arm64")
                self.assertEqual(command[command.index("--uid") + 1], "0")
                self.assertIn("KISA_CCE_TEST_GUEST=1", command)
                self.assertIn("type=bind,source=" + str(self.root) + ",target=/opt/kisa-cce-tests,readonly", command)
                self.assertIn("example:latest", command)
                self.assertEqual(command[-3:], ["scanner", "all", "--prepare"])

    def test_apple_x86_uses_amd64(self):
        with mock.patch.object(runner.platform, "system", return_value="Darwin"), \
                mock.patch.object(runner.shutil, "which", return_value="container"), \
                mock.patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as execute:
            runner.run_apple(self.args(arch="x86_64"), self.root, self.root)
        command = execute.call_args_list[0].args[0]
        self.assertEqual(command[command.index("--arch") + 1], "amd64")

    @unittest.skipUnless(shutil.which("bash"), "Bash is needed to exercise guest guard")
    def test_guest_rejects_unmarked_host_before_any_work(self):
        environment = os.environ.copy()
        environment.pop("KISA_CCE_TEST_GUEST", None)
        result = subprocess.run(["bash", str(Path(runner.__file__).with_name("guest.sh")),
                                 "scanner", "check"], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("disposable Linux guest", result.stderr)

    def test_dry_run_never_starts_backend_or_snapshot(self):
        with mock.patch.object(runner.subprocess, "run") as process, \
                mock.patch.object(runner, "snapshot") as snapshot, \
                mock.patch.object(runner, "run_qemu") as backend, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = runner.main(["--backend", "qemu", "--image", "missing.qcow2", "--dry-run"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["images"], ["missing.qcow2"])
        process.assert_not_called()
        snapshot.assert_not_called()
        backend.assert_not_called()

    def test_missing_patcher_scanner_is_diagnosed_before_execution(self):
        fake_script = self.root / "patcher/tools/testing/run.py"
        (self.root / "patcher/bin").mkdir(parents=True)
        (self.root / "patcher/bin/kisa-cce-patch").touch()
        with mock.patch.object(runner, "__file__", str(fake_script)), \
                mock.patch.object(runner, "run_qemu") as backend:
            with self.assertRaisesRegex(ValueError, "requires --scanner-dir"):
                runner.main(["--backend", "qemu", "--image", "missing", "--dry-run"])
        backend.assert_not_called()

    def test_matrix_continues_and_preserves_failure_exit_code(self):
        output = self.root / "results"

        def backend_result(args, payload, image_output):
            if args.image == "bad.qcow2":
                return 19
            phase_names = ["prerequisites", "check-user", "lint", "smoke"]
            if args.project == "patcher":
                phase_names.append("check-root")
            self.write_phases(image_output, phase_names)
            return 0

        with mock.patch.object(runner, "snapshot", return_value={}), \
                mock.patch.object(runner, "run_qemu", side_effect=backend_result) as backend, \
                contextlib.redirect_stdout(io.StringIO()):
            status = runner.main(["--backend", "qemu", "--image", "bad.qcow2", "--image",
                                  "good.qcow2", "--output-dir", str(output)])
        self.assertEqual(status, 1)
        self.assertEqual(backend.call_count, 2)
        records = json.loads((output / "summary.json").read_text())["runs"]
        self.assertEqual([record["exit_code"] for record in records], [19, 0])
        self.assertEqual([record["status"] for record in records], ["failed", "passed"])

    def write_phases(self, output, names):
        guest = output / "guest"
        guest.mkdir()
        (guest / "phases.tsv").write_text("phase\tstatus\texit_code\n" +
                                           "".join(name + "\tpassed\t0\n" for name in names))

    def test_zero_exit_without_complete_successful_phases_fails(self):
        for index, rows in enumerate((None, "prerequisites\tpassed\t0\n",
                "prerequisites\tpassed\t0\nlint\tfailed\t1\n",
                "prerequisites\tpassed\t0\nlint\tpassed\t0\nlint\tpassed\t0\n")):
            with self.subTest(rows=rows):
                output = self.root / ("results-" + str(index))

                def backend_result(args, payload, image_output):
                    if rows is not None:
                        guest = image_output / "guest"
                        guest.mkdir()
                        (guest / "phases.tsv").write_text("phase\tstatus\texit_code\n" + rows)
                    return 0

                with mock.patch.object(runner, "snapshot", return_value={}), \
                        mock.patch.object(runner, "run_qemu", side_effect=backend_result), \
                        contextlib.redirect_stdout(io.StringIO()):
                    status = runner.main(["--backend", "qemu", "--image", "disk", "--suite",
                                          "lint", "--output-dir", str(output)])
                self.assertEqual(status, 1)
                record = json.loads((output / "summary.json").read_text())["runs"][0]
                self.assertEqual(record["status"], "error")
                self.assertEqual(record["exit_code"], 2)
                self.assertIn("complete passing phase results", record["error"])

    def test_interrupt_writes_summary_and_stops_matrix(self):
        output = self.root / "results"
        with mock.patch.object(runner, "snapshot", return_value={}), \
                mock.patch.object(runner, "run_qemu", side_effect=KeyboardInterrupt) as backend, \
                contextlib.redirect_stdout(io.StringIO()):
            status = runner.main(["--backend", "qemu", "--image", "one", "--image", "two",
                                  "--output-dir", str(output)])
        self.assertEqual(status, 130)
        self.assertEqual(backend.call_count, 1)
        records = json.loads((output / "summary.json").read_text())["runs"]
        self.assertEqual(records[0]["status"], "interrupted")

    def test_qemu_result_archive_rejects_unsafe_members(self):
        for index, (name, kind) in enumerate((("../escape", tarfile.REGTYPE),
                ("/absolute", tarfile.REGTYPE), ("link", tarfile.SYMTYPE),
                ("hardlink", tarfile.LNKTYPE), ("device", tarfile.CHRTYPE))):
            with self.subTest(name=name):
                archive = self.root / (str(index) + ".tar")
                with tarfile.open(archive, "w") as handle:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "../escape"
                    handle.addfile(member)
                with self.assertRaisesRegex(RuntimeError, "unsafe archive"):
                    qemu_backend._extract_results(archive, self.root / "results")
                self.assertFalse((self.root / "results").exists())

    def test_qemu_result_archive_extracts_regular_nested_files(self):
        archive = self.root / "safe.tar"
        with tarfile.open(archive, "w") as handle:
            member = tarfile.TarInfo("./nested/test.log")
            member.size = 3
            handle.addfile(member, io.BytesIO(b"ok\n"))
        qemu_backend._extract_results(archive, self.root / "results")
        self.assertEqual((self.root / "results/nested/test.log").read_bytes(), b"ok\n")

    def test_qemu_acceleration_matches_host_and_permissions(self):
        cases = (("Darwin", "arm64", "aarch64", False, "hvf"),
                 ("Darwin", "arm64", "x86_64", False, "tcg"),
                 ("Linux", "x86_64", "x86_64", True, "kvm"),
                 ("Linux", "x86_64", "x86_64", False, "tcg"),
                 ("Linux", "aarch64", "x86_64", True, "tcg"))
        for system, machine, arch, accessible, expected in cases:
            with self.subTest(system=system, machine=machine, arch=arch, accessible=accessible), \
                    mock.patch.object(qemu_backend.platform, "system", return_value=system), \
                    mock.patch.object(qemu_backend.platform, "machine", return_value=machine), \
                    mock.patch.object(qemu_backend.os, "access", return_value=accessible):
                self.assertEqual(qemu_backend._acceleration(self.args(arch=arch)), expected)
                self.assertEqual(qemu_backend._acceleration(self.args(arch=arch, accel="tcg")), "tcg")


if __name__ == "__main__":
    unittest.main()
