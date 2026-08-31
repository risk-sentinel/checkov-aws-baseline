#!/usr/bin/env python3
"""Fold per-slice staging files into the live data files, deterministically.

Why this exists rather than letting each drafting pass edit the data files
directly: every proposal lands in the SAME four files -- resource_map_derived,
api_specs, control_metadata_derived, fix_examples. Several passes running at
once therefore collide on all four, and the collisions are the silent kind:
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

Staging schema (all keys optional, check-id keyed):

    mappings:   {CKV_AWS_1: {aws_foo: {reader: stock, ...}}}
    api_specs:  {aws_foo: {client:, list:, collection:, id:, gem:, fields:}}
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

HERE = pathlib.Path(__file__).resolve().parent
STAGING = HERE / "staging"

LIVE = {
    "mappings":  HERE / "resource_map_derived.yml",
    "api_specs": HERE / "api_specs.yml",
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
}


def known_verbs():
    """The verbs matcher_for implements, read from the renderer rather than copied.

    A copy drifts: the renderer grew eight verbs in one commit and any list kept
    here by hand would have rejected all eight as unknown.
    """
    src = (HERE / "render_controls.py").read_text()
    body = src.split("def matcher_for(", 1)[1].split("\ndef ", 1)[0]
    import re
    return sorted(set(re.findall(r'satisfies == "([a-z_]+)"', body)))


def load_yaml(path, default=None):
    if not path.is_file():
        return default if default is not None else {}
    return yaml.safe_load(path.read_text()) or (default if default is not None else {})


def collect(files):
    """Read every staging file, refusing any check two of them both claim."""
    merged = {k: {} for k in ("mappings", "api_specs", "metadata", "fixes", "skipped")}
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
            # `satisfies` sits on the assert block for stock, on the body otherwise.
            holder = body.get("assert", body) if reader == "stock" else body
            verb = holder.get("satisfies", "equals")
            if verb not in verbs:
                errors.append(f"{cid}/{tf_type} ({where}): satisfies '{verb}' is not "
                              f"implemented. matcher_for knows: {', '.join(verbs)}")
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
        body = yaml.safe_dump(doc, sort_keys=True, default_flow_style=False, width=100,
                              allow_unicode=True)
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
