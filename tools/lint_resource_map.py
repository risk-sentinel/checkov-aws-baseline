#!/usr/bin/env python3
"""Verify every stock mapping against the resource pack it claims to use.

The gap this closes: a control that reads a stock inspec-aws resource can only
be exec-validated in an account that HAS that resource type. An account with no
Redshift cluster skips the Redshift controls, and a wrong enumeration column
sits there indefinitely looking like a clean Not Applicable.

That is not hypothetical. Three mappings were written against plausible column
names and two were wrong:

    aws_rds_clusters                   .cluster_identifiers  -> .cluster_identifier
    aws_elasticache_replication_groups .replication_group_ids -> .ids

Both would have raised NoMethodError the first time a customer with those
resources ran the profile, and passed every test until then.

So the vendored pack is the authority, checked statically:

  * the plural resource named in `enumerate` exists
  * the column named in `ids` is registered on it -- or the resource populates
    its table dynamically from the API response, which is reported rather than
    silently accepted
  * the singular resource named in `assert` exists

What it cannot check is the PROPERTY on the singular resource: those come from
`create_resource_methods` over the API response at runtime, so they exist only
when a real response does. Those are named in the report as unverifiable, so the
distinction between "checked" and "unchecked" stays visible.
"""
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

NAME = re.compile(r"^\s*name\s+['\"]([a-z0-9_]+)['\"]", re.M)
COLUMN = re.compile(r"register_column\(:([a-z0-9_]+)")
DYNAMIC = "populate_filter_table_from_response"


def pack():
    """resource name -> {columns, dynamic} from the vendored resource pack."""
    out = {}
    for f in sorted(ROOT.glob("vendor/*/libraries/*.rb")):
        text = f.read_text()
        for n in NAME.findall(text):
            out[n] = {"columns": set(COLUMN.findall(text)), "dynamic": DYNAMIC in text}
    return out


def main() -> int:
    resources = pack()
    if not resources:
        print("::error::no vendored resource pack found — run `cinc-auditor vendor .` first. "
              "Without it this lint would pass by having nothing to check.")
        return 1

    mappings = yaml.safe_load((HERE / "resource_map.yml").read_text())["checks"]
    problems, unverifiable, checked = [], [], 0

    for cid, per_type in sorted(mappings.items()):
        for tf_type, spec in per_type.items():
            if spec.get("reader") != "stock":
                continue
            checked += 1
            enum, assertion = spec.get("enumerate", {}), spec.get("assert", {})
            plural, column = enum.get("resource"), enum.get("ids")
            singular, prop = assertion.get("resource"), assertion.get("property")

            if plural not in resources:
                problems.append(f"{cid}/{tf_type}: no resource named '{plural}' in the pack")
            elif column not in resources[plural]["columns"]:
                if resources[plural]["dynamic"]:
                    unverifiable.append(
                        f"{cid}/{tf_type}: {plural}.{column} — table is populated from the API "
                        f"response, so the column cannot be confirmed without a live call")
                else:
                    have = ", ".join(sorted(resources[plural]["columns"])[:8]) or "(none)"
                    problems.append(
                        f"{cid}/{tf_type}: {plural} has no column '{column}'. It registers: {have}")

            if singular not in resources:
                problems.append(f"{cid}/{tf_type}: no resource named '{singular}' in the pack")
            elif prop:
                unverifiable.append(
                    f"{cid}/{tf_type}: {singular}.{prop} — provided by create_resource_methods "
                    f"over the API response; only a live call can confirm it")

    print(f"stock mappings checked : {checked}")
    print(f"resources in the pack  : {len(resources)}")
    print(f"unverifiable statically: {len(unverifiable)} (property names, and dynamic id columns)")

    if problems:
        print("::error::a stock mapping names something the resource pack does not have.")
        for p in problems:
            print(f"  {p}")
        return 1

    print("OK — every stock mapping names a resource that exists, and every "
          "statically-checkable enumeration column is registered on it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
