#!/usr/bin/env python3
"""Propose resource_map entries by matching Checkov checks to stock inspec-aws.

Mapping 442 checks by hand means reading 442 Checkov checks and 481 inspec-aws
resources and holding both in your head. This does the mechanical half: for every
check whose Terraform resource type has a stock inspec-aws resource, it lists the
properties that resource actually exposes and scores the ones whose names look
like the Terraform argument the check inspects.

It proposes; it does not decide. A name match is evidence, not proof -- Terraform
argument names and AWS API property names agree often enough to be a useful
starting point and disagree often enough that accepting them unreviewed would
produce controls that assert the wrong field with total confidence.

Usage:
    python3 tools/propose_mappings.py --service s3      # one service at a time
    python3 tools/propose_mappings.py --unmapped        # everything not yet mapped
"""
import argparse
import difflib
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

RESOURCE_NAME = re.compile(r"^\s*name\s+['\"]([a-z0-9_]+)['\"]", re.M)
# Public instance methods a control can call: predicates and plain readers.
METHOD = re.compile(r"^  def ([a-z_][a-z0-9_]*\??)", re.M)
COLUMN = re.compile(r"register_column\(:([a-z0-9_]+)", re.M)
ATTR = re.compile(r"^\s*attr_reader\s+(.+)$", re.M)


def stock_resources():
    """name -> {file, methods, columns} for every vendored inspec-aws resource."""
    out = {}
    for f in sorted(ROOT.glob("vendor/*/libraries/*.rb")):
        text = f.read_text()
        for name in RESOURCE_NAME.findall(text):
            methods = {m for m in METHOD.findall(text)
                       if not m.startswith(("fetch", "validate", "to_s"))}
            for line in ATTR.findall(text):
                methods |= {a.strip().lstrip(":") for a in line.split(",")}
            out[name] = {"file": f.name,
                         "methods": sorted(methods),
                         "columns": sorted(set(COLUMN.findall(text)))}
    return out


def candidates_for(tf_type, stock):
    """The plural (enumerate) and singular (assert) resources for a TF type."""
    singular = tf_type if tf_type in stock else None
    plural = next((n for n in (tf_type + "s", tf_type + "es") if n in stock), None)
    if singular is None and tf_type.startswith("aws_db_"):
        alt = tf_type.replace("aws_db_", "aws_rds_")
        singular = alt if alt in stock else None
        plural = plural or next((n for n in (alt + "s",) if n in stock), None)
    return singular, plural


def score(argument, method):
    """How much a property name looks like the Terraform argument it should answer."""
    a = argument.split("/")[0].strip("[]").lower()
    m = method.rstrip("?").lower()
    if not a:
        return 0.0
    if a == m:
        return 1.0
    if a in m or m in a:
        return 0.85
    return difflib.SequenceMatcher(None, a, m).ratio()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--service", help="limit to aws_<service>_* resource types")
    ap.add_argument("--unmapped", action="store_true", help="skip checks already mapped")
    ap.add_argument("--min-score", type=float, default=0.6)
    args = ap.parse_args()

    catalog = yaml.safe_load((HERE / "checkov_catalog.yml").read_text())["checks"]
    mapped = set(yaml.safe_load((HERE / "resource_map.yml").read_text())["checks"])
    stock = stock_resources()

    shown = 0
    for cid, e in sorted(catalog.items()):
        if args.unmapped and cid in mapped:
            continue
        types = [t for t in e["resources"] if t.startswith("aws_")]
        if args.service:
            types = [t for t in types if t.startswith(f"aws_{args.service}")]
        if not types:
            continue

        lines = []
        for t in types:
            singular, plural = candidates_for(t, stock)
            if not (singular or plural):
                continue
            argument = e["inspected_key"].get(t, "")
            props = stock.get(singular, {}).get("methods", [])
            ranked = sorted(((score(argument, p), p) for p in props), reverse=True)[:4]
            ranked = [(s, p) for s, p in ranked if s >= args.min_score]
            lines.append(f"    {t}:")
            lines.append(f"      # tf argument : {argument or '(custom check logic)'}")
            lines.append(f"      # enumerate   : {plural or '(no plural resource)'}"
                         f"  ids: {stock.get(plural, {}).get('columns', [])[:3]}")
            lines.append(f"      # assert on   : {singular or '(no singular resource)'}")
            if ranked:
                lines.append("      # candidates  : " +
                             ", ".join(f"{p} ({s:.2f})" for s, p in ranked))
            else:
                lines.append("      # candidates  : none above threshold — needs a human")
        if lines:
            shown += 1
            print(f"  {cid}:   # {e['name'][:70]}  [{e['kind']}]")
            print("\n".join(lines))

    print(f"\n# {shown} check(s) proposed. Nothing is written: curate into resource_map.yml.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
