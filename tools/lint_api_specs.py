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

SECOND RULE — the spec SCHEMA, which exists for the same reason.

libraries/aws_api_assets.rb reads a fixed set of keys and ignores everything
else. A key it does not implement is therefore silently inert, and the failure
that follows is the one this repo keeps paying for: `args:` on an ECS
DescribeClusters spec looks like it passes include: [CONFIGURATIONS], the
response comes back without the configuration block, every row's field is nil,
the control's nil filter removes every row, and the check renders Not Applicable
— a rule that cannot fail, reported as one that does not apply.

tools/proposals/parentchild.yml drafts five such keys (args, batch,
absent_errors, per-parent region routing, a third level). None is implemented.
So an unknown key is refused here rather than ignored at runtime, and the
refusal names what implementing it would take.
"""
import argparse
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPECS = HERE / "api_specs.yml"
MANIFEST = HERE / "image_gems.txt"
RESOURCE_MAPS = (HERE / "resource_map.yml", HERE / "resource_map_derived.yml")
BAKE = HERE.parent / "libraries" / "_api_specs.rb"

# Keys libraries/aws_api_assets.rb#row_for writes before it writes `fields`. A
# field with one of these names OVERWRITES the row's identity rather than adding
# to it: `type` breaks the exemption match, `region` and `account_id` mislabel
# every describe title, `id` and `parent_id` replace what the row is. Nothing
# raises -- the row is still a row.
RESERVED_FIELDS = {"id", "region", "account_id", "type", "parent_id", "arn"}

SPEC_KEYS = {"gem", "client", "list", "collection", "id", "arn", "fields", "scope",
             "parent", "arg"}
SPEC_REQUIRED = ("gem", "client", "list", "collection", "id")
PARENT_KEYS = {"list", "collection", "id"}
PARENT_REQUIRED = ("list", "collection", "id")

# Drafted in tools/proposals/parentchild.yml, deliberately not built. Named
# individually so a data pass that copies one out of the proposal is told what is
# missing rather than left with a spec that quietly does nothing.
NOT_IMPLEMENTED = {
    "args": "literal extra params on the child call (ECS DescribeClusters `include`, "
            "SQS GetQueueAttributes `AttributeNames`). Without it the fields it would "
            "populate are simply absent from the response.",
    "batch": "a child `arg` taking up to N ids per call (ECS DescribeClusters, "
             "CodeBuild BatchGetProjects). Those work without it, 100x more expensively.",
    "absent_errors": "errors meaning 'not configured', yielding a row of nils. Needs a "
                     "verb rule alongside it: a row of nils is removed again by a value "
                     "check's nil filter, which is how the failing population disappears.",
    "region_field": "per-parent region routing, needed before any S3 sub-resource spec "
                    "(S3 answers 301 unless the call goes to the bucket's own region).",
    "parents": "a chain deeper than one parent. Every three-level check is ALSO blocked "
               "on a child call taking two arguments, so depth alone unlocks nothing.",
}


def spec_problems(specs):
    """Schema errors, one message per offending spec."""
    out = []
    for name, spec in sorted(specs.items()):
        if not isinstance(spec, dict):
            out.append(f"{name}: spec is {type(spec).__name__}, not a mapping")
            continue

        for key in sorted(set(spec) - SPEC_KEYS):
            why = NOT_IMPLEMENTED.get(key)
            out.append(f"{name}: key '{key}' is not implemented by aws_api_assets and is "
                       f"silently ignored at runtime"
                       + (f" — it would need {why}" if why else ""))
        for key in SPEC_REQUIRED:
            if not spec.get(key):
                out.append(f"{name}: missing required key '{key}'")

        parent = spec.get("parent")
        if parent is not None and not isinstance(parent, dict):
            out.append(f"{name}: `parent` must be a mapping, got {type(parent).__name__}")
            parent = None

        # `arg` names the parameter the parent id travels in. It means nothing
        # without a parent, and a two-step spec cannot make its child call without
        # one — the call would go out unparameterised and AWS would reject it.
        if parent and not spec.get("arg"):
            out.append(f"{name}: declares `parent` but no `arg`, so there is nothing to "
                       f"pass the parent id in")
        if spec.get("arg") and not parent:
            out.append(f"{name}: declares `arg` without `parent`, which reads as two-step "
                       f"and is enumerated as one-step")

        if parent:
            for key in sorted(set(parent) - PARENT_KEYS):
                out.append(f"{name}: unknown key 'parent.{key}'")
            for key in PARENT_REQUIRED:
                if not parent.get(key):
                    out.append(f"{name}: missing required key 'parent.{key}'")
            if parent.get("id") == "_parent":
                out.append(f"{name}: parent.id cannot be `_parent` — a parent has no parent")
            if parent.get("collection") == "_response":
                out.append(f"{name}: parent.collection cannot be `_response` — a parent "
                           f"list call must name the member holding the parents")

        # The sentinels are position-specific, and using one in the wrong position
        # is silent: `_self` on a child id makes every row's id the response object.
        if spec.get("id") == "_self":
            out.append(f"{name}: `id: _self` is a PARENT sentinel; a child's id must name "
                       f"a member, or be `_parent`")
        if spec.get("id") == "_parent" and not parent:
            out.append(f"{name}: `id: _parent` needs a `parent` to take the id from")
        if spec.get("collection") == "_response" and not parent:
            out.append(f"{name}: `collection: _response` describes a child response with no "
                       f"wrapper member; a one-step list call has one")

        fields = spec.get("fields")
        if fields is not None and not isinstance(fields, dict):
            out.append(f"{name}: `fields` must be a mapping of name -> dotted path, got "
                       f"{type(fields).__name__}. The reader iterates it as pairs, so a list "
                       f"yields a nil path for every entry and every field reads nil.")
            fields = {}
        for fname, path in sorted((fields or {}).items()):
            if not isinstance(path, (str, int, float)) or not str(path).strip():
                out.append(f"{name}: field '{fname}' has no usable path ({path!r}); dig_path "
                           f"answers nil and the control's nil filter removes every row")
            if str(fname) in RESERVED_FIELDS:
                out.append(f"{name}: field '{fname}' collides with a row key the reader "
                           f"already writes, and overwrites it silently")

        if spec.get("scope") not in (None, "global", "regional"):
            out.append(f"{name}: scope '{spec['scope']}' is neither global nor regional; "
                       f"anything but `global` walks regions, so a typo silently does")
    return out


def bake_drift():
    """Whether libraries/_api_specs.rb matches tools/api_specs.yml.

    The bake is what the READER reads; the YAML is what render_controls.py reads
    for the control shape and what every other lint here checks. Nothing asserted
    they agree. An edit that was never re-baked therefore passes every gate in
    profile-lint.yml while the two halves of the profile disagree -- and the
    quiet direction is the likely one: rename a `fields:` key, and the control
    asserts on a key the reader never writes, which is nil, which the nil filter
    removes, which renders Not Applicable.
    """
    import render_api_specs

    if not BAKE.is_file():
        return [f"{BAKE.name} does not exist; run tools/render_api_specs.py"]
    specs = yaml.safe_load(SPECS.read_text()) or {}
    if render_api_specs.render(specs) == BAKE.read_text():
        return []
    return [f"libraries/{BAKE.name} does not match tools/api_specs.yml — "
            f"run `python3 tools/render_api_specs.py` and commit the result"]


def unmapped_specs():
    """`reader: api` mappings whose terraform type has no spec at all.

    aws_api_assets raises ArgumentError for an unknown type, which surfaces as a
    control error rather than a silent pass — but it surfaces at exec, in an
    account that happens to have the resource. This is the same answer, statically.
    """
    specs = yaml.safe_load(SPECS.read_text()) or {}
    missing = []
    for path in RESOURCE_MAPS:
        if not path.is_file():
            continue
        checks = (yaml.safe_load(path.read_text()) or {}).get("checks") or {}
        for cid, per_type in sorted(checks.items()):
            for tf_type, mapping in (per_type or {}).items():
                if not isinstance(mapping, dict) or mapping.get("reader") != "api":
                    continue
                if tf_type not in specs:
                    missing.append(f"{cid}/{tf_type}: reader is `api` but api_specs.yml "
                                   f"has no spec for that type")
    return missing


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
                     if isinstance(s, dict) and s.get("gem") and s["gem"] not in available)
    two_step = sum(1 for s in specs.values() if isinstance(s, dict) and s.get("parent"))
    schema = spec_problems(specs)
    unmapped = unmapped_specs()
    drift = bake_drift()

    print(f"api specs: {len(specs)} ({two_step} two-step)   "
          f"gems in the image: {len(available)}")
    if missing:
        print("::error::an api spec names a gem the image does not ship. The reader "
              "raises AwsApiAssets::MissingGem, so the control errors rather than "
              "reporting a result — but it does so only at exec, in an account that "
              "has the resource type.")
        for t, gem in missing:
            print(f"  {t}: {gem}")
    if schema:
        print("::error::an api spec does not match the schema aws_api_assets reads. An "
              "unknown key is silently inert at runtime, which is how a field ends up "
              "always nil and a control ends up unable to fail.")
        for problem in schema:
            print(f"  {problem}")
    if unmapped:
        print("::error::a mapping declares `reader: api` for a type with no api spec.")
        for problem in unmapped:
            print(f"  {problem}")
    if drift:
        print("::error::the baked spec table the READER reads has drifted from the YAML "
              "every other check reads. The halves disagree and nothing else can see it.")
        for problem in drift:
            print(f"  {problem}")
    if missing or schema or unmapped or drift:
        return 1
    print("OK — every api spec names a gem the image ships, matches the reader's schema, "
          "is baked into libraries/_api_specs.rb as committed, and every `reader: api` "
          "mapping has one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
