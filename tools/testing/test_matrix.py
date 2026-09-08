# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Validate reviewed release selection independently of installed VM tools."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from matrix import resolve_matrix
import run as runner


class MatrixTests(unittest.TestCase):
    def args(self, *options):
        return runner.parser().parse_args(['--backend', 'apple', '--matrix', 'supported', *options])

    def test_reviewed_releases_exclude_eol_and_development_streams(self):
        images, metadata = resolve_matrix(self.args())
        self.assertEqual([(row['distribution'], row['version']) for row in metadata['releases']], [
            ('ubuntu', '22.04'), ('ubuntu', '24.04'), ('ubuntu', '26.04'),
            ('debian', '12'), ('debian', '13'), ('rocky', '8.10'),
            ('rocky', '9.8'), ('rocky', '10.2'), ('fedora', '43'), ('fedora', '44')])
        self.assertEqual(len(set(images)), 10)
        self.assertIn('docker.io/rockylinux/rockylinux:9.8', images)
        self.assertIn('registry.fedoraproject.org/fedora:44', images)
        self.assertEqual(metadata['reviewed_on'], '2026-09-08')

    def test_distribution_filter_deduplicates_and_preserves_catalog_order(self):
        images, metadata = resolve_matrix(self.args('--distribution', 'fedora', '--distribution',
                                                   'debian', '--distribution', 'fedora'))
        self.assertEqual([row['distribution'] for row in metadata['releases']],
                         ['debian', 'debian', 'fedora', 'fedora'])
        self.assertEqual(len(images), 4)

    def test_custom_images_remain_explicit_and_cannot_claim_matrix_filters(self):
        args = runner.parser().parse_args(['--backend', 'apple', '--image', 'custom:image'])
        self.assertEqual(resolve_matrix(args), (['custom:image'], None))
        args.distribution = ['fedora']
        with self.assertRaisesRegex(ValueError, 'require --matrix'):
            resolve_matrix(args)

    def test_image_and_matrix_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.args('--image', 'custom:image')

    def test_qemu_requires_all_selected_cloud_images_before_starting(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args('--backend', 'qemu', '--distribution', 'fedora', '--arch', 'x86_64',
                             '--image-dir', temporary)
            with self.assertRaisesRegex(ValueError, 'fedora-43-x86_64.qcow2'):
                resolve_matrix(args)
            for version in ('43', '44'):
                (Path(temporary) / ('fedora-' + version + '-x86_64.qcow2')).touch()
            images, _ = resolve_matrix(args)
            self.assertEqual(len(images), 2)
            self.assertTrue(all(Path(image).is_file() for image in images))

    def test_qemu_directory_required_and_rejected_for_apple(self):
        with self.assertRaisesRegex(ValueError, 'requires --image-dir'):
            resolve_matrix(self.args('--backend', 'qemu'))
        with self.assertRaisesRegex(ValueError, 'only used by the QEMU'):
            resolve_matrix(self.args('--image-dir', '/tmp/images'))

    def test_matrix_dry_run_resolves_without_guests_or_image_files(self):
        with mock.patch.object(runner, 'run_qemu') as backend, \
                mock.patch.object(runner, 'snapshot') as snapshot, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = runner.main(['--backend', 'qemu', '--matrix', 'supported', '--distribution',
                                  'fedora', '--arch', 'aarch64', '--image-dir', '/missing', '--dry-run'])
        plan = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(len(plan['images']), 2)
        self.assertTrue(plan['images'][0].endswith('fedora-43-aarch64.qcow2'))
        self.assertEqual(plan['matrix']['name'], 'supported')
        backend.assert_not_called()
        snapshot.assert_not_called()


if __name__ == '__main__':
    unittest.main()
