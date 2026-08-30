#!/usr/bin/env python3
"""Reconcile controls/ against the pinned Checkov catalogue, in both directions.

The rule id is this profile's primary key, and it appears in four places that
must agree:

    controls/CKV_AWS_79.rb      the file name
    control 'CKV_AWS_79' do     the InSpec control id
    tag checkov_id: '...'       the tag a reader joins back on
    tools/checkov_catalog.yml   the catalogue entry it was generated from

A mismatch between file name and control id is invisible in HDF — only the
control id survives — and a mismatch between control id and `checkov_id` breaks
the join back to the rule that motivated the control, which is the whole
provenance chain. Neither shows up in `check`, which cares about none of this.

Directions checked:

  controls -> catalogue   a control naming a check the pinned version does not
                          define. This is what a Checkov downgrade or a rename
                          looks like, and the control is then asserting
                          something no rule asks for.

  catalogue -> controls   a check with no control. Reported as coverage, not
                          failed, while the profile is still being filled — but
                          the number is printed every run, so "we cover Checkov"
                          is never claimable without a number beside it.

  resource_map -> controls  a check mapped to deployed assets but with no
                          control is a gap that looks like work already done.
                          That one fails.
"""
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CATALOG = HERE / "checkov_catalog.yml"
RESOURCE_MAP = HERE / "resource_map.yml"
CONTROLS = ROOT / "controls"

CONTROL_ID = re.compile(r"^control\s+'([^']+)'\s+do", re.M)
CHECKOV_ID = re.compile(r"^\s*tag checkov_id:\s*'([^']+)'", re.M)
CHECKOV_VERSION = re.compile(r"^\s*tag checkov_version:\s*'([^']+)'", re.M)


def main() -> int:
    catalog = yaml.safe_load(CATALOG.read_text())
    pinned = catalog["_source"]["version"]
    checks = catalog["checks"]
    mapped = set(yaml.safe_load(RESOURCE_MAP.read_text())["checks"])

    controls = {}
    problems = []

    for path in sorted(CONTROLS.glob("*.rb")):
        text = path.read_text()
        stem = path.stem
        if not stem.startswith("CKV_"):
            continue                      # inventory and other non-check controls
        controls[stem] = path

        ids = CONTROL_ID.findall(text)
        if ids != [stem]:
            problems.append(f"{path.name}: control id {ids or ['<none>']} does not match the file name")

        tagged = CHECKOV_ID.findall(text)
        if tagged != [stem]:
            problems.append(f"{path.name}: tag checkov_id: {tagged or ['<missing>']} does not match the file name")

        versions = set(CHECKOV_VERSION.findall(text))
        if versions != {pinned}:
            problems.append(
                f"{path.name}: tag checkov_version: {sorted(versions) or ['<missing>']} "
                f"but the catalogue is pinned at {pinned}")

        if stem not in checks:
            problems.append(f"{path.name}: {stem} is not defined by checkov {pinned}")

    for cid in sorted(mapped - set(controls)):
        problems.append(f"{cid}: mapped in resource_map.yml but has no controls/{cid}.rb")

    uncovered = sorted(set(checks) - set(controls))
    print(f"catalogue: {len(checks)} checks at checkov {pinned}")
    print(f"controls : {len(controls)} written, {len(mapped)} mapped to deployed assets")
    print(f"coverage : {len(controls)}/{len(checks)} "
          f"({100 * len(controls) // max(len(checks), 1)}%) — {len(uncovered)} check(s) have no control")

    if problems:
        print("::error::catalogue and controls disagree.")
        for p in problems:
            print(f"  {p}")
        return 1

    print("OK — every control names a check the pinned Checkov defines, and the "
          "file name, control id and checkov_id tag agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
