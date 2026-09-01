#!/usr/bin/env python3
"""Verify every api spec names a gem the auditor image actually ships.

A spec whose gem is absent does not fail loudly. The reader rescues the
LoadError into `unreadable_regions`, returns no rows, and the control renders
Not Applicable — "this rule does not apply here" — when the truth is that
nothing was ever read. Four specs shipped in exactly that state before this
existed: aws-sdk-neptune, aws-sdk-docdb, aws-sdk-dax and aws-sdk-bedrockagent
are not in the image.

The control template now also fails on a non-empty `unreadable_regions`, so the
runtime case is visible too. This is the static half: it refuses the spec before
anyone runs it.

The gem list is read from the image itself, so it cannot drift from reality:

    docker run --rm --entrypoint sh <image> -c 'ls .../gems | grep ^aws-sdk-'

Pass --image-gems FILE with that output to check against a specific image;
without it, the committed manifest is used.

It also asserts the BAKE is current. tools/api_specs.yml is what the linters
read; libraries/_api_specs.rb is what the reader reads, and only
tools/render_api_specs.py connects them. When the two drift, every static
guarantee about the specs -- this lint, and every path tools/lint_api_paths.rb
resolves against the SDK model -- is a guarantee about a file nothing executes.
That is not hypothetical: a field removed from the YAML because ListFunctions
does not return it stayed in the bake, so the reader went on declaring a member
the lint had just proved absent.
"""
import argparse
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
SPECS = HERE / "api_specs.yml"
MANIFEST = HERE / "image_gems.txt"
BAKE = HERE.parent / "libraries" / "_api_specs.rb"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image-gems", type=pathlib.Path,
                    help="file listing the gems present in the image, one per line")
    args = ap.parse_args()

    source = args.image_gems or MANIFEST
    if not source.is_file():
        print(f"::error::no gem manifest at {source}. Regenerate it from the image; "
              f"without it this lint would pass by having nothing to check.")
        return 1
    available = {line.strip() for line in source.read_text().splitlines() if line.strip()}

    specs = yaml.safe_load(SPECS.read_text()) or {}
    missing = sorted((t, s.get("gem")) for t, s in specs.items()
                     if s.get("gem") and s["gem"] not in available)

    print(f"api specs: {len(specs)}   gems in the image: {len(available)}")
    if missing:
        print("::error::an api spec names a gem the image does not ship. The reader "
              "rescues the LoadError and the control renders Not Applicable, so this "
              "cannot be caught by reading results.")
        for t, gem in missing:
            print(f"  {t}: {gem}")
        return 1
    if not BAKE.is_file():
        print(f"::error::no baked spec table at {BAKE}. Run tools/render_api_specs.py.")
        return 1
    import render_api_specs
    if BAKE.read_text() != render_api_specs.bake(specs):
        print("::error::libraries/_api_specs.rb is stale against tools/api_specs.yml. The "
              "reader loads the BAKE and every lint reads the YAML, so a drift means the "
              "specs are checked in one file and executed from another. Run "
              "tools/render_api_specs.py and commit the result.")
        return 1

    print("OK — every api spec names a gem the image ships, and the bake is current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
