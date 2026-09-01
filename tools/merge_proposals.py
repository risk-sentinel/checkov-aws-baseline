#!/usr/bin/env python3
"""Fold per-slice staging files into the live data files, deterministically.

Why this exists rather than letting each drafting pass edit the data files
directly: every proposal lands in the SAME five files -- resource_map_derived,
api_specs, policy_specs, control_metadata_derived, fix_examples. Several passes
running at once therefore collide on all five, and the collisions are the silent
kind:
last-writer-wins on a YAML mapping drops the other pass's entry without any
diff conflict to notice.

So a pass writes ONE file it exclusively owns, under tools/staging/, and this
merges them. Every way two passes can disagree is an error here rather than a
silently dropped entry:

  * two staging files claiming the same check      -> named, both sides
  * a staging file redefining an already-live check -> refused; the live entry
    was exec-validated and a draft must not quietly replace it
  * a mapping whose `satisfies` no verb implements  -> refused, with the verb
    list, because render_controls would raise mid-render leaving controls/
    half-written
  * a mapping with no metadata                      -> refused; render indexes
    metadata[cid] unconditionally and would KeyError
  * an api spec naming a gem the image lacks        -> refused here as well as
    in lint_api_specs, because a LoadError is rescued into unreadable_regions
    and reads as Not Applicable
  * a policy mapping naming a predicate nobody implements, or a source with no
    policy spec -> refused; both render, pass `check` AND `json`, and raise only
    on a real exec

A merge that adds to policy_specs must be followed by
`python3 tools/render_policy_specs.py` -- the bake in libraries/_policy_specs.rb
is what the reader actually reads. tools/lint_policy_specs.py fails when it is
stale.

Staging schema (all keys optional, check-id keyed):

    mappings:   {CKV_AWS_1: {aws_foo: {reader: stock, ...}}}
    api_specs:  {aws_foo: {client:, list:, collection:, id:, gem:, fields:}}
    policy_specs: {aws_foo: {client:, list:, collection:, id:, gem:, document|fetch:}}
    metadata:   {CKV_AWS_1: {severity:, impact:, nist:, nist_r4:, cci:, ksi:,
                             rationale:, nist_source:}}
    fixes:      {CKV_AWS_1: {aws_foo: {terraform:, cli:, note:}}}
    skipped:    {CKV_AWS_1: "why this slice did not map it"}

`skipped` is carried into tools/staging/SKIPPED.md rather than dropped: a check
nobody could map is a finding about the catalogue, and losing the reason means
the next pass rediscovers it.
"""
import argparse
import pathlib
import sys

import yaml

import yaml_dump

HERE = pathlib.Path(__file__).resolve().parent
STAGING = HERE / "staging"

LIVE = {
    "mappings":  HERE / "resource_map_derived.yml",
    "api_specs": HERE / "api_specs.yml",
    "policy_specs": HERE / "policy_specs.yml",
    "metadata":  HERE / "control_metadata_derived.yml",
    "fixes":     HERE / "fix_examples.yml",
}
AUTHORED = {
    "mappings": HERE / "resource_map.yml",
    "metadata": HERE / "control_metadata.yml",
}

META_REQUIRED = ("severity", "impact", "nist", "nist_r4", "cci", "ksi", "rationale")
NIST_SOURCES = ("reviewed", "category-derived", "agent-drafted")
SPEC_REQUIRED = ("client", "list", "collection", "id", "gem")

# Required keys per reader shape. render_controls indexes these directly, so a
# missing one is an unhandled KeyError halfway through writing controls/.
SHAPE_REQUIRED = {
    "stock":     {"enumerate": ("resource", "ids"), "assert": ("resource", "property")},
    "api":       {"_self": ("field",)},
    "singleton": {"_self": ("resource", "property")},
    "custom":    {"_self": ()},
    # A policy mapping names a PREDICATE, not a `satisfies` verb: the unit of
    # judgement is a statement and the verdict depends on Effect, Principal,
    # Action, Resource and Condition together. `source` is optional and defaults
    # to the Terraform type.
    "policy":    {"_self": ("predicate",)},
}

# Readers whose mapping carries no `satisfies` at all. Defaulting these to
# "equals" would then demand a `value` and refuse every valid mapping.
VERBLESS_READERS = ("policy",)


def known_verbs():
    """The verbs the renderer implements, read from it rather than copied.

    A copy drifts: the renderer grew eight verbs in one commit and any list kept
    here by hand would have rejected all eight as unknown.

    TWO sources, because the renderer has two dispatchers. `matcher_for` renders
    a verb as an RSpec matcher against the asset's own field, and scraping its
    `satisfies == "x"` arms finds the thirteen scalar verbs. The ROLL-UP verbs
    are rendered by `collection_matcher_for` instead and deliberately never
    appear in matcher_for's body -- matcher_for RAISES on them, pointing at the
    other function. So scraping matcher_for alone reported every roll-up mapping
    as "not implemented", which refused a verb the renderer, the walker in
    libraries/_checkov_collection.rb and tools/lint_api_paths.rb all support.
    COLLECTION_VERBS is read out of the renderer for the same reason the scalar
    ones are: so this cannot drift from what actually renders.
    """
    import re
    src = (HERE / "render_controls.py").read_text()
    body = src.split("def matcher_for(", 1)[1].split("\ndef ", 1)[0]
    scalar = set(re.findall(r'satisfies == "([a-z_]+)"', body))
    match = re.search(r"^COLLECTION_VERBS\s*=\s*\((.*?)\)", src, re.M | re.S)
    rollup = set(re.findall(r'"([a-z_]+)"', match.group(1))) if match else set()
    return sorted(scalar | rollup)


def rollup_verbs():
    """Just the roll-up verbs, for the `conditions:` rule below."""
    import re
    src = (HERE / "render_controls.py").read_text()
    match = re.search(r"^COLLECTION_VERBS\s*=\s*\((.*?)\)", src, re.M | re.S)
    return set(re.findall(r'"([a-z_]+)"', match.group(1))) if match else set()


def known_predicates():
    """The policy predicates, read out of the Ruby rather than copied.

    Same reason as known_verbs: a list kept by hand here drifts from the one
    that actually runs, and a mapping naming a predicate nobody implemented
    renders, passes `check` and `json`, and raises only at exec.
    """
    import re
    text = (HERE.parent / "libraries" / "_policy_document.rb").read_text()
    match = re.search(r"PREDICATES\s*=\s*%w\[(.*?)\]", text, re.S)
    return sorted(match.group(1).split()) if match else []


def load_yaml(path, default=None):
    if not path.is_file():
        return default if default is not None else {}
    return yaml.safe_load(path.read_text()) or (default if default is not None else {})


def collect(files):
    """Read every staging file, refusing any check two of them both claim."""
    merged = {k: {} for k in ("mappings", "api_specs", "policy_specs", "metadata",
                              "fixes", "skipped")}
    owner = {k: {} for k in merged}
    errors = []
    for path in files:
        doc = load_yaml(path)
        if not isinstance(doc, dict):
            errors.append(f"{path.name}: not a YAML mapping")
            continue
        unknown = set(doc) - set(merged)
        if unknown:
            errors.append(f"{path.name}: unknown top-level key(s) {sorted(unknown)}")
        for section in merged:
            for key, value in (doc.get(section) or {}).items():
                if key in owner[section]:
                    errors.append(
                        f"{section}/{key}: claimed by both {owner[section][key]} "
                        f"and {path.name}. One slice must own it.")
                    continue
                owner[section][key] = path.name
                merged[section][key] = value
    return merged, owner, errors


def validate(merged, owner, verbs):
    errors, warnings = [], []

    live_map = load_yaml(LIVE["mappings"]).get("checks", {})
    authored_map = load_yaml(AUTHORED["mappings"]).get("checks", {})
    live_meta = load_yaml(LIVE["metadata"])
    authored_meta = load_yaml(AUTHORED["metadata"])
    live_specs = load_yaml(LIVE["api_specs"])
    live_policy_specs = load_yaml(LIVE["policy_specs"])
    catalog = load_yaml(HERE / "checkov_catalog.yml").get("checks", {})
    gems = {l.strip() for l in (HERE / "image_gems.txt").read_text().splitlines() if l.strip()}

    for cid, spec in merged["mappings"].items():
        where = owner["mappings"][cid]
        if cid in authored_map:
            errors.append(f"{cid} ({where}): already in the AUTHORED resource_map. "
                          f"A draft must not replace a reviewed mapping.")
        if cid in live_map:
            errors.append(f"{cid} ({where}): already in resource_map_derived. "
                          f"If it is wrong, change it there in its own commit — "
                          f"several entries in that file were removed after a live "
                          f"exec and must not be silently reinstated.")
        if cid not in catalog:
            errors.append(f"{cid} ({where}): not in checkov_catalog.yml")
        if not isinstance(spec, dict) or not spec:
            errors.append(f"{cid} ({where}): mapping must be keyed by terraform type")
            continue
        for tf_type, body in spec.items():
            if not isinstance(body, dict):
                errors.append(f"{cid}/{tf_type} ({where}): not a mapping")
                continue
            reader = body.get("reader")
            if reader not in SHAPE_REQUIRED:
                errors.append(f"{cid}/{tf_type} ({where}): reader '{reader}' is not one "
                              f"of {sorted(SHAPE_REQUIRED)}")
                continue
            for block, keys in SHAPE_REQUIRED[reader].items():
                target = body if block == "_self" else body.get(block)
                if target is None:
                    errors.append(f"{cid}/{tf_type} ({where}): reader '{reader}' needs a "
                                  f"'{block}' block")
                    continue
                for key in keys:
                    if not target.get(key):
                        errors.append(f"{cid}/{tf_type} ({where}): "
                                      f"{block if block != '_self' else reader}.{key} is required")
            if reader == "policy":
                predicate = body.get("predicate")
                if predicate and predicate not in known_predicates():
                    errors.append(f"{cid}/{tf_type} ({where}): predicate '{predicate}' is not "
                                  f"implemented. libraries/_policy_document.rb has: "
                                  f"{', '.join(known_predicates())}")
                source = body.get("source") or tf_type
                if source not in live_policy_specs and source not in merged["policy_specs"]:
                    errors.append(f"{cid}/{tf_type} ({where}): policy source '{source}' is not "
                                  f"in tools/policy_specs.yml")

            # `satisfies` sits on the assert block for stock, on the body otherwise.
            holder = body.get("assert", body) if reader == "stock" else body
            verb = holder.get("satisfies", "equals")
            if reader in VERBLESS_READERS:
                pass
            elif verb not in verbs:
                errors.append(f"{cid}/{tf_type} ({where}): satisfies '{verb}' is not "
                              f"implemented. matcher_for knows: {', '.join(verbs)}")
            elif verb in rollup_verbs():
                # A roll-up takes `conditions:`, not `value:`. render_controls
                # raises SystemExit on an empty list -- mid-render, after it has
                # already written part of controls/ -- so it is refused here.
                if not body.get("conditions"):
                    errors.append(f"{cid}/{tf_type} ({where}): satisfies '{verb}' rolls up over "
                                  f"the elements of a collection and needs a non-empty "
                                  f"`conditions:` list; with none it matches every element or "
                                  f"none of them, and either way asserts nothing")
                if reader != "api":
                    errors.append(f"{cid}/{tf_type} ({where}): satisfies '{verb}' is supported "
                                  f"on the `api` reader only, not '{reader}' — and "
                                  f"tools/lint_api_paths.rb can only resolve condition paths "
                                  f"for that reader, so an unchecked path is a control that "
                                  f"cannot fail")
            elif verb in ("equals", "not_equals", "greater_than", "at_least", "at_most",
                          "less_than", "includes", "excludes", "matches", "in_list",
                          "not_in_list") and holder.get("value") is None:
                errors.append(f"{cid}/{tf_type} ({where}): satisfies '{verb}' needs a value")
            if reader == "api":
                for t in spec:
                    if t not in live_specs and t not in merged["api_specs"]:
                        errors.append(f"{cid}/{t} ({where}): reader 'api' but no api spec "
                                      f"for {t}, here or live")
        if cid not in merged["metadata"] and cid not in live_meta and cid not in authored_meta:
            errors.append(f"{cid} ({where}): mapped with no metadata. render_controls "
                          f"indexes metadata[cid] unconditionally.")

    for cid, meta in merged["metadata"].items():
        where = owner["metadata"][cid]
        if cid in authored_meta:
            errors.append(f"{cid} ({where}): already in the AUTHORED control_metadata.")
        missing = [k for k in META_REQUIRED if not meta.get(k)]
        if missing:
            errors.append(f"{cid} ({where}): metadata missing {missing}")
        src = meta.get("nist_source")
        if src not in NIST_SOURCES:
            errors.append(f"{cid} ({where}): nist_source '{src}' not in {list(NIST_SOURCES)}")
        for key in ("nist", "nist_r4", "cci", "ksi"):
            if key in meta and not isinstance(meta[key], list):
                errors.append(f"{cid} ({where}): {key} must be a list")

    for tf_type, spec in merged["api_specs"].items():
        where = owner["api_specs"][tf_type]
        if tf_type in live_specs:
            errors.append(f"{tf_type} ({where}): api spec already live")
        missing = [k for k in SPEC_REQUIRED if not spec.get(k)]
        if missing:
            errors.append(f"{tf_type} ({where}): api spec missing {missing}")
        gem = spec.get("gem")
        if gem and gem not in gems:
            errors.append(f"{tf_type} ({where}): gem '{gem}' is not in the auditor image. "
                          f"A LoadError is rescued into unreadable_regions and the control "
                          f"reads as Not Applicable. Park it in api_specs_pending_gems.yml.")

    # A policy spec is validated the same way an api spec is, and for the same
    # reason: a missing gem, a missing member or a source declared twice all end
    # in a control that reads as an answer. The one extra rule is that the bake
    # in libraries/_policy_specs.rb is what the reader actually reads, so a merge
    # here must be followed by `python3 tools/render_policy_specs.py`.
    for source, spec in merged["policy_specs"].items():
        where = owner["policy_specs"][source]
        if source in live_policy_specs:
            errors.append(f"{source} ({where}): policy spec already live")
        missing = [k for k in SPEC_REQUIRED if not spec.get(k)]
        if missing:
            errors.append(f"{source} ({where}): policy spec missing {missing}")
        if not spec.get("document") and not spec.get("fetch"):
            errors.append(f"{source} ({where}): policy spec declares neither `document` nor "
                          f"`fetch`, so no policy is ever read and every asset is undecidable")
        gem = spec.get("gem")
        if gem and gem not in gems:
            errors.append(f"{source} ({where}): gem '{gem}' is not in the auditor image.")

    for cid in merged["fixes"]:
        if cid not in catalog:
            warnings.append(f"fix for {cid} ({owner['fixes'][cid]}): not in the catalogue")

    return errors, warnings


def write_merged(merged, dry_run):
    """Fold into the live files, preserving each file's leading comment header."""
    written = []
    for section, path in LIVE.items():
        additions = merged[section]
        if not additions:
            continue
        text = path.read_text() if path.is_file() else ""
        header = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                header.append(line)
            else:
                break
        doc = load_yaml(path)
        if section == "mappings":
            doc.setdefault("checks", {}).update(additions)
            count = len(additions)
        else:
            doc.update(additions)
            count = len(additions)
        # yaml_dump, not yaml.safe_dump: a plain scalar that wraps onto a line
        # beginning with ":" is a Ruby Symbol to Psych, and tools/lint_api_paths.rb
        # then cannot load the file at all.
        body = yaml_dump.dump(doc)
        out = "\n".join(header).rstrip("\n") + "\n" + body if header else body
        if not dry_run:
            path.write_text(out)
        written.append(f"  {path.name}: +{count}")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="validate and report, write nothing")
    ap.add_argument("--only", nargs="*", metavar="SLICE",
                    help="merge only these staging files (by stem)")
    args = ap.parse_args()

    if not STAGING.is_dir():
        print(f"::error::no staging directory at {STAGING}")
        return 1
    files = sorted(p for p in STAGING.glob("*.yml"))
    if args.only:
        files = [p for p in files if p.stem in args.only]
    if not files:
        print("no staging files — nothing to merge")
        return 0

    print(f"staging files: {', '.join(p.name for p in files)}")
    merged, owner, errors = collect(files)
    verbs = known_verbs()
    v_errors, warnings = validate(merged, owner, verbs)
    errors += v_errors

    for w in warnings:
        print(f"::warning::{w}")
    if errors:
        print(f"::error::{len(errors)} problem(s); nothing was written.")
        for e in errors:
            print(f"  {e}")
        return 1

    print("proposed: " + "  ".join(f"{k}={len(v)}" for k, v in merged.items()))
    written = write_merged(merged, args.dry_run)
    print(("would write" if args.dry_run else "wrote") + ":")
    print("\n".join(written) or "  (nothing)")

    if merged["skipped"] and not args.dry_run:
        lines = ["# Checks a drafting pass could not map, and why.", "",
                 "Carried out of the staging files by tools/merge_proposals.py so the",
                 "reason survives the merge — a check nobody could map is a finding",
                 "about the catalogue, and losing the reason means rediscovering it.", ""]
        for cid in sorted(merged["skipped"]):
            lines.append(f"- **{cid}** ({owner['skipped'][cid]}) — {merged['skipped'][cid]}")
        (STAGING / "SKIPPED.md").write_text("\n".join(lines) + "\n")
        print(f"  staging/SKIPPED.md: {len(merged['skipped'])} unmapped, with reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
