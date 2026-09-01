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

# Required parameters are written four ways in the pack: [:a, :b], %i[a b],
# %i(a b), %w[a b]. A single loose pattern captured past the closing bracket and
# swallowed the next twenty lines of Ruby into an "argument name", which then
# rendered a control that could not parse. Each form is matched exactly, and
# every captured name must look like a parameter or it is discarded.
# `required:` means all of them; `require_any_of:` means at least one, and the
# first is as good an argument name as any. Both appear with [], %i[], %i() and
# %w[] bodies, which is why this is a list of exact patterns rather than one
# loose one -- a loose one already captured past a closing bracket and swallowed
# twenty lines of Ruby into an argument name.
REQUIRED_FORMS = [
    re.compile(r"\brequired:\s*\[([^\]]*)\]"),
    re.compile(r"\brequired:\s*%i\[([^\]]*)\]"),
    re.compile(r"\brequired:\s*%i\(([^)]*)\)"),
    re.compile(r"\brequired:\s*%w\[([^\]]*)\]"),
]
ANY_OF_FORMS = [
    re.compile(r"require_any_of:\s*\[([^\]]*)\]"),
    re.compile(r"require_any_of:\s*%i\[([^\]]*)\]"),
    re.compile(r"require_any_of:\s*%i\(([^)]*)\)"),
    re.compile(r"require_any_of:\s*%w\[([^\]]*)\]"),
]
MUST_PROVIDE = re.compile(r"`\[([^\]`]*)\]`\s*must be provided")
# Several resources in the pack do not declare their identifier to
# `validate_parameters` at all -- they hand it a computed list
# (`required: [query_arguments.keys.first]`), which reads as no requirement here,
# and then raise their own ArgumentError naming the parameter in prose:
#
#   raise ArgumentError, "...: `cache_cluster_id` must be provided." unless ...
#   raise ArgumentError, "...: `file_system_id` or `creation_token` must be provided."
#
# Without this the resource looked like it accepted anything, the `arg:` check
# below was skipped for it, and four mappings passed a keyword the resource
# rejects. That is an ArgumentError at exec, which InSpec does NOT rescue: it
# escapes the control and reports as a failed test, so a mapping that never ran
# reads as a real finding.
MUST_PROVIDE_LINE = re.compile(r"^.*must be provided.*$", re.M)
BACKTICKED = re.compile(r"`([a-z_][a-z0-9_]*)`")
PARAM_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


def required_params(text):
    """Parameters a resource refuses to run without.

    A resource with required parameters cannot enumerate an account -- there is
    nothing to pass it -- and a singular resource's required parameter is the
    argument name a control must use, which pluralising the resource name does
    not reliably produce.
    """
    found = set()
    for pattern in REQUIRED_FORMS:
        for m in pattern.finditer(text):
            found |= {p.strip().lstrip(":") for p in re.split(r"[,\s]+", m.group(1)) if p.strip()}
    for pattern in ANY_OF_FORMS:
        for m in pattern.finditer(text):
            # EVERY alternative, not just the first. This set is consumed as "the
            # arguments this resource accepts", and require_any_of means any one
            # of them is accepted -- keeping only the first reported
            # aws_flow_log as identifying its subject by flow_log_id alone and
            # rejected a mapping passing vpc_id, which the resource explicitly
            # allows (require_any_of: %i(flow_log_id subnet_id vpc_id)) and
            # which had already executed correctly against a live account.
            found |= {p.strip().lstrip(":") for p in re.split(r"[,\s]+", m.group(1)) if p.strip()}
    for m in MUST_PROVIDE.finditer(text):
        found |= {p.strip().lstrip(":") for p in m.group(1).split(",")}
    for line in MUST_PROVIDE_LINE.findall(text):
        found |= set(BACKTICKED.findall(line))
    return sorted(p for p in found if PARAM_NAME.fullmatch(p))


def pack():
    """resource name -> {columns, dynamic} from the vendored resource pack."""
    out = {}
    for f in sorted(ROOT.glob("vendor/*/libraries/*.rb")):
        text = f.read_text()
        for n in NAME.findall(text):
            out[n] = {"columns": set(COLUMN.findall(text)), "dynamic": DYNAMIC in text,
                      "required": required_params(text)}
    return out


def main() -> int:
    resources = pack()
    if not resources:
        print("::error::no vendored resource pack found — run `cinc-auditor vendor .` first. "
              "Without it this lint would pass by having nothing to check.")
        return 1

    # Both files, exactly as render_controls.load() merges them. The derived map
    # carries most of the mappings and used to go unchecked here, which is how
    # `ids: eks_cluster_identifiers` — a column aws_eks_clusters does not
    # register — survived long enough to be found by a live exec instead.
    mappings = yaml.safe_load((HERE / "resource_map.yml").read_text())["checks"]
    derived = HERE / "resource_map_derived.yml"
    if derived.is_file():
        for cid, spec in (yaml.safe_load(derived.read_text()) or {}).get("checks", {}).items():
            mappings.setdefault(cid, spec)
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
            elif resources[plural]["required"]:
                problems.append(
                    f"{cid}/{tf_type}: {plural} requires {resources[plural]['required']} and "
                    f"cannot enumerate an account — the control errors at exec instead of skipping")
            elif column not in resources[plural]["columns"]:
                if resources[plural]["dynamic"]:
                    unverifiable.append(
                        f"{cid}/{tf_type}: {plural}.{column} — table is populated from the API "
                        f"response, so the column cannot be confirmed without a live call")
                else:
                    have = ", ".join(sorted(resources[plural]["columns"])[:8]) or "(none)"
                    problems.append(
                        f"{cid}/{tf_type}: {plural} has no column '{column}'. It registers: {have}")

            # `exclude:` narrows the enumerated population before the ids are
            # read, and it does it through FilterTable's `where`. A column that
            # is not registered raises ArgumentError there, which is at least
            # loud — but at exec, on one control, in one region. Named here it
            # is loud before anyone runs it.
            for col in (enum.get("exclude") or {}):
                if plural in resources and col not in resources[plural]["columns"]:
                    if resources[plural]["dynamic"]:
                        unverifiable.append(
                            f"{cid}/{tf_type}: exclude on {plural}.{col} — table is populated "
                            f"from the API response, so the column cannot be confirmed here")
                    else:
                        problems.append(
                            f"{cid}/{tf_type}: {plural} has no column '{col}' to exclude on")

            # `resource(id, aws_region: region)` is two arguments and InSpec's
            # *args dispatch accepts one — "wrong number of arguments (given 2,
            # expected 0..1)" at exec, on 13 controls at once. A regional stock
            # mapping must name the parameter it passes.
            if spec.get("scope") != "global" and assertion.get("arg") in (None, "", "positional"):
                problems.append(
                    f"{cid}/{tf_type}: regional stock mapping passes a positional argument; "
                    f"it must name {singular}'s parameter so the region can travel with it")

            if singular not in resources:
                problems.append(f"{cid}/{tf_type}: no resource named '{singular}' in the pack")
            elif (req := resources[singular]["required"]) and assertion.get("arg") not in req + ["positional"]:
                problems.append(
                    f"{cid}/{tf_type}: {singular} identifies its subject by {req} "
                    f"(any one of them where there is more than one); the mapping passes "
                    f"'{assertion.get('arg')}', which the resource rejects with an "
                    f"ArgumentError before it makes a single API call")
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
