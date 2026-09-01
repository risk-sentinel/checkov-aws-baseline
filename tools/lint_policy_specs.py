#!/usr/bin/env python3
"""Verify the policy-document shape agrees with itself across four files.

The shape spans four artefacts that can drift independently, and every way they
can disagree ends in a control that reads as an answer when it is not:

    libraries/_policy_document.rb   PREDICATES — what is implemented
    tools/render_controls.py        PREDICATE_PROSE — how a control describes it
    tools/policy_specs.yml          where the document lives, per source
    tools/resource_map*.yml         which check names which source and predicate

Six checks, and what each one exists to stop:

  1. A predicate implemented in Ruby with no prose in the renderer, or prose for
     a predicate nobody implemented. The second is the dangerous one: the
     control renders, `check` and `json` both pass, and the reader raises
     ArgumentError only on a real exec — which this repo cannot run.

  2. A mapping naming a predicate that does not exist. Same failure, reached
     from the data side.

  3. A mapping naming a source that is not in policy_specs.yml.

  4. A spec naming a gem the image does not ship. A LoadError here is raised as
     a profile error rather than rescued -- but the spec is still dead weight,
     and the same defect in api_specs.yml is what tools/lint_api_specs.py was
     written for after four specs shipped in that state.

  5. A spec that declares neither `document` nor `fetch`, or a `fetch` missing
     its call or its document path, or an argument reference that is neither
     `from: id|arn` nor `from_item: <path>`. All of those make every asset
     UNDECIDABLE at exec, which fails loudly -- but failing 400 assets on a
     typo is not a good way to find out.

  6. libraries/_policy_specs.rb out of sync with tools/policy_specs.yml. The
     bake is what the reader actually reads; an edited YAML that was never baked
     is a change that looks made and is not.

None of the six is visible to `cinc-auditor check` or `json`, which load control
files without evaluating a single control body.
"""
import pathlib
import re
import subprocess
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SPECS = HERE / "policy_specs.yml"
BAKED = ROOT / "libraries" / "_policy_specs.rb"
PREDICATE_LIB = ROOT / "libraries" / "_policy_document.rb"
RENDERER = HERE / "render_controls.py"
MANIFEST = HERE / "image_gems.txt"
MAPS = (HERE / "resource_map.yml", HERE / "resource_map_derived.yml")

SPEC_REQUIRED = ("gem", "client", "list", "collection", "id")


def load_yaml(path, default=None):
    if not path.is_file():
        return {} if default is None else default
    return yaml.safe_load(path.read_text()) or ({} if default is None else default)


def implemented_predicates():
    """PREDICATES, read out of the Ruby rather than copied.

    A copy is the drift this file exists to catch, so it must not introduce one.
    """
    text = PREDICATE_LIB.read_text()
    match = re.search(r"PREDICATES\s*=\s*%w\[(.*?)\]", text, re.S)
    if not match:
        return None
    return sorted(match.group(1).split())


def prose_predicates():
    """PREDICATE_PROSE's keys, read out of the renderer for the same reason."""
    text = RENDERER.read_text()
    match = re.search(r"PREDICATE_PROSE\s*=\s*\{(.*?)\n\}", text, re.S)
    if not match:
        return None
    return sorted(re.findall(r'"([a-z0-9_]+)":', match.group(1)))


def policy_mappings():
    """(check id, terraform type, spec) for every `reader: policy` mapping."""
    out = []
    for path in MAPS:
        for cid, per_type in (load_yaml(path).get("checks") or {}).items():
            for tf_type, spec in (per_type or {}).items():
                if isinstance(spec, dict) and spec.get("reader") == "policy":
                    out.append((cid, tf_type, spec))
    return out


def spec_problems(source, spec):
    problems = []
    for key in SPEC_REQUIRED:
        if not spec.get(key):
            problems.append(f"{source}: `{key}` is required")

    has_document, fetch = spec.get("document"), spec.get("fetch")
    if not has_document and not fetch:
        problems.append(f"{source}: declares neither `document` nor `fetch`, so no policy is "
                        f"ever read and every asset is undecidable")
    if has_document and fetch:
        problems.append(f"{source}: declares both `document` and `fetch`; `document` wins and "
                        f"the `fetch` is dead, which reads as a second call being made")
    if not fetch:
        return problems

    for key in ("call", "document"):
        if not fetch.get(key):
            problems.append(f"{source}: fetch.{key} is required")
    for name, value in (fetch.get("args") or {}).items():
        if not isinstance(value, dict):
            continue                                  # a literal argument
        if "from" in value:
            if value["from"] not in ("id", "arn"):
                problems.append(f"{source}: fetch.args.{name} `from: {value['from']}` — "
                                f"only `id` and `arn` exist on a row")
            if value["from"] == "arn" and not spec.get("arn"):
                problems.append(f"{source}: fetch.args.{name} takes `from: arn`, but the spec "
                                f"declares no `arn` member, so it would pass nil")
        elif "from_item" not in value:
            problems.append(f"{source}: fetch.args.{name} is an object with neither `from` "
                            f"nor `from_item`")
    return problems


def main() -> int:
    problems = []

    specs = load_yaml(SPECS)
    predicates = implemented_predicates()
    prose = prose_predicates()

    if predicates is None:
        print(f"::error::could not read PREDICATES from {PREDICATE_LIB.relative_to(ROOT)} — "
              f"without it this lint would pass by having nothing to check.")
        return 1
    if prose is None:
        print(f"::error::could not read PREDICATE_PROSE from {RENDERER.relative_to(ROOT)} — "
              f"without it this lint would pass by having nothing to check.")
        return 1

    for name in sorted(set(predicates) - set(prose)):
        problems.append(f"predicate '{name}' is implemented in Ruby but has no PREDICATE_PROSE "
                        f"entry, so no mapping can render it")
    for name in sorted(set(prose) - set(predicates)):
        problems.append(f"predicate '{name}' has PREDICATE_PROSE but is not implemented — a "
                        f"mapping naming it renders, passes `check` and `json`, and raises "
                        f"only at exec")

    available = {line.strip() for line in MANIFEST.read_text().splitlines() if line.strip()} \
        if MANIFEST.is_file() else None
    if available is None:
        print(f"::error::no gem manifest at {MANIFEST}. Regenerate it from the image.")
        return 1

    for source, spec in sorted(specs.items()):
        if not isinstance(spec, dict):
            problems.append(f"{source}: not a mapping")
            continue
        problems.extend(spec_problems(source, spec))
        gem = spec.get("gem")
        if gem and gem not in available:
            problems.append(f"{source}: gem '{gem}' is not in the auditor image")

    mappings = policy_mappings()
    for cid, tf_type, spec in mappings:
        source = spec.get("source") or tf_type
        if source not in specs:
            problems.append(f"{cid}/{tf_type}: policy source '{source}' is not in "
                            f"policy_specs.yml")
        predicate = spec.get("predicate")
        if not predicate:
            problems.append(f"{cid}/{tf_type}: reader 'policy' needs a `predicate`")
        elif predicate not in predicates:
            problems.append(f"{cid}/{tf_type}: predicate '{predicate}' is not implemented. "
                            f"Implemented: {', '.join(predicates)}")

    if BAKED.is_file() and SPECS.is_file():
        before = BAKED.read_text()
        subprocess.run([sys.executable, str(HERE / "render_policy_specs.py")],
                       check=True, capture_output=True)
        if BAKED.read_text() != before:
            BAKED.write_text(before)
            problems.append(f"{BAKED.relative_to(ROOT)} is stale — run "
                            f"`python3 tools/render_policy_specs.py` and commit the result")

    print(f"policy sources     : {len(specs)}")
    print(f"predicates         : {len(predicates)} ({', '.join(predicates)})")
    print(f"policy mappings    : {len(mappings)}")

    if problems:
        print("::error::the policy-document shape disagrees with itself.")
        for p in problems:
            print(f"  {p}")
        return 1

    print("OK — every predicate is implemented and describable, every mapping names a source "
          "and a predicate that exist, every spec names a gem the image ships, and the bake "
          "is in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
