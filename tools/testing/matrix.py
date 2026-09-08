# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
"""Resolve the reviewed test matrix for either guest backend."""

import json
from pathlib import Path


def resolve_matrix(args):
    """Keep explicit image runs separate from the reviewed lifecycle snapshot."""
    if not args.matrix:
        if args.distribution or args.image_dir:
            raise ValueError("--distribution and --image-dir require --matrix supported")
        return args.image, None
    data = json.loads(Path(__file__).with_name("supported-matrix.json").read_text())
    rows = [row for row in data["releases"]
            if not args.distribution or row["distribution"] in args.distribution]
    if not rows:
        raise ValueError("the selected distributions have no reviewed releases")
    if args.backend == "qemu":
        if args.image_dir is None:
            raise ValueError("QEMU matrix requires --image-dir with verified local cloud images")
        directory = args.image_dir.expanduser().resolve()
        images = [str(directory / (row["distribution"] + "-" + row["version"] +
                                   "-" + args.arch + ".qcow2")) for row in rows]
        if not args.dry_run:
            missing = [image for image in images if not Path(image).is_file()]
            if missing:
                raise ValueError("missing QEMU matrix images: " + ", ".join(missing))
    else:
        if args.image_dir is not None:
            raise ValueError("--image-dir is only used by the QEMU matrix")
        images = [row["image"] for row in rows]
    return images, {"name": "supported", "reviewed_on": data["reviewed_on"],
                    "support_scope": data["support_scope"], "releases": rows}
