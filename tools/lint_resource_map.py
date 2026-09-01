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


# --- membership (join) mappings ------------------------------------------
#
# A stock mapping fails loudly when it names a column that does not exist:
# NoMethodError at exec. A MEMBERSHIP mapping does not. Name a key field the
# api spec does not carry and every key comes back nil, nothing matches, and
# every left asset reports as uncovered -- a 100% finding that reads exactly
# like a real one and that neither `check` nor `json` can see, because neither
# evaluates a control body.
#
# So the parts of a join that CAN be checked without an account are checked
# here: that both sides name an api spec that exists, that each key names a
# column that spec actually produces, that a declared filter names a field it
# actually carries, and that the two sides agree about region scope when the
# join pairs on region.
#
# What is NOT checkable, and is reported rather than assumed: whether the two
# key spaces intersect. That is a fact about real ARNs. The rendered control
# carries a runtime guard for it; this lint names the mappings that depend on
# that guard so the dependence stays visible.
MEMBERSHIP_KEY_FORMS = ("verbatim", "terminal_segment")
MEMBERSHIP_ASSERTIONS = ("every_left_covered",)

# Every key render_membership actually reads. A key outside these lists is not a
# harmless annotation: it is a fact the author believes is being enforced and
# that the generator silently drops, which lands the control in exactly the state
# this shape exists to prevent -- one that reports something other than what its
# mapping says. The specific one to fear is `where` on the LEFT side. Only the
# right side is filtered, so a left-side `where` reads perfectly, changes
# nothing, and leaves the control asserting over a population the rule does not
# apply to. `note` is the escape hatch for prose.
MEMBERSHIP_KEYS = frozenset((
    "reader", "assert", "match_region", "left", "right",
    "empty_right_means", "divergence", "uncovered_message", "note",
))
MEMBERSHIP_SIDE_KEYS = {
    "left": frozenset(("type", "key", "key_form", "noun", "noun_plural")),
    # `where` narrows the right side BEFORE keys are built. There is no left-side
    # equivalent -- see tools/proposals/graph.yml shape_notes gap_3, which is its
    # own piece of work.
    "right": frozenset(("type", "key", "key_form", "noun", "noun_plural", "where")),
}


def api_specs():
    return yaml.safe_load((HERE / "api_specs.yml").read_text()) or {}


def all_mappings():
    """Authored and derived mappings together.

    lint_resource_map's stock half reads only the authored file, which is the
    reviewed surface. A membership mapping is dangerous in a way a stock one is
    not -- it fails silently rather than loudly -- so the derived file is
    included here: an unreviewed join is exactly the one that most needs the
    static check.
    """
    merged = {}
    for name in ("resource_map.yml", "resource_map_derived.yml"):
        path = HERE / name
        if not path.is_file():
            continue
        for cid, spec in (yaml.safe_load(path.read_text()) or {}).get("checks", {}).items():
            merged.setdefault(cid, spec)
    return merged


def membership_columns(spec):
    """The row columns aws_api_assets writes for an api spec.

    `id`, `region`, `account_id` and `type` are on every row; `arn` only when
    the spec declares one; the rest are the declared fields.
    """
    columns = {"id", "region", "account_id", "type"}
    if spec.get("arn"):
        columns.add("arn")
    columns |= set(spec.get("fields") or {})
    return columns


def check_membership(problems, unverifiable):
    """Validate every membership mapping. Returns the number checked."""
    specs = api_specs()
    checked = 0

    for cid, per_type in sorted(all_mappings().items()):
        for tf_type, mapping in per_type.items():
            if mapping.get("reader") != "membership":
                continue
            checked += 1
            where = cid + "/" + tf_type

            if mapping.get("assert") not in MEMBERSHIP_ASSERTIONS:
                problems.append(f"{where}: assert '{mapping.get('assert')}' is not one of "
                                f"{', '.join(MEMBERSHIP_ASSERTIONS)}")
            if not str(mapping.get("empty_right_means") or "").strip():
                problems.append(
                    f"{where}: no `empty_right_means`. An empty right side is a FINDING — "
                    f"nothing is covered — and the control has to say so rather than let a "
                    f"reader assume absence of evidence")

            # An unrecognised key is a claim the generator does not honour.
            for key in sorted(set(mapping) - MEMBERSHIP_KEYS):
                problems.append(
                    f"{where}: `{key}` is not a key render_membership reads, so it would be "
                    f"silently ignored. Recognised: {', '.join(sorted(MEMBERSHIP_KEYS))}. Put "
                    f"prose in `note`")

            sides = {}
            for side in ("left", "right"):
                decl = mapping.get(side) or {}
                spec = specs.get(decl.get("type"))
                sides[side] = spec
                if spec is None:
                    problems.append(f"{where}: {side} names api spec '{decl.get('type')}', which "
                                    f"is not in tools/api_specs.yml")
                    continue
                if decl.get("key_form") not in MEMBERSHIP_KEY_FORMS:
                    problems.append(f"{where}: {side} key_form '{decl.get('key_form')}' is not one "
                                    f"of {', '.join(MEMBERSHIP_KEY_FORMS)}")
                columns = membership_columns(spec)
                if decl.get("key") not in columns:
                    problems.append(
                        f"{where}: {side} keys on '{decl.get('key')}', which "
                        f"{decl.get('type')} does not produce. It produces: "
                        f"{', '.join(sorted(columns))}. Every key would be nil and NOTHING would "
                        f"match, which renders as every asset uncovered")
                if not str(decl.get("noun") or "").strip():
                    problems.append(f"{where}: {side} has no `noun` for the control's prose")
                for key in sorted(set(decl) - MEMBERSHIP_SIDE_KEYS[side]):
                    extra = (" Only the right side is filtered: a left-side `where` would read as "
                             "scoping the population and would in fact do nothing."
                             if key == "where" and side == "left" else "")
                    problems.append(
                        f"{where}: {side} declares `{key}`, which render_membership does not "
                        f"read on that side, so it would be silently ignored. Recognised on "
                        f"{side}: {', '.join(sorted(MEMBERSHIP_SIDE_KEYS[side]))}.{extra}")
                if decl.get("key_form") == "terminal_segment":
                    unverifiable.append(
                        f"{where}: {side} reduces {decl['type']}.{decl['key']} to its terminal "
                        f"segment — whether the two key spaces then intersect is a fact about "
                        f"real ARNs, provable only at exec, and the control's key-space guard "
                        f"is what covers it")

            right_decl = mapping.get("right") or {}
            filters = right_decl.get("where") or {}
            if len(filters) > 1:
                problems.append(f"{where}: right.where takes exactly one field, got "
                                f"{sorted(filters)} — with more than one the rendered guard "
                                f"cannot say which of them selected nothing")
            if filters and sides.get("right"):
                field = next(iter(filters))
                columns = membership_columns(sides["right"])
                if field not in columns:
                    problems.append(
                        f"{where}: right.where filters on '{field}', which "
                        f"{right_decl.get('type')} does not produce. It produces: "
                        f"{', '.join(sorted(columns))}. The filter would select NOTHING and "
                        f"every asset would report uncovered")

            if mapping.get("match_region", True) and all(sides.values()):
                scopes = {side: (spec.get("scope") or "regional") for side, spec in sides.items()}
                if scopes["left"] != scopes["right"]:
                    problems.append(
                        f"{where}: the join pairs on region but the two sides disagree about "
                        f"scope (left {scopes['left']}, right {scopes['right']}). A global row is "
                        f"keyed 'global' and a regional one is not, so nothing would ever match")

    return checked


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

    membership = check_membership(problems, unverifiable)

    print(f"stock mappings checked : {checked}")
    print(f"membership joins checked: {membership}")
    print(f"resources in the pack  : {len(resources)}")
    print(f"unverifiable statically: {len(unverifiable)} (property names, and dynamic id columns)")

    if problems:
        print("::error::a mapping names something the resource pack or an api spec does not have.")
        for p in problems:
            print(f"  {p}")
        return 1

    print("OK — every stock mapping names a resource that exists, every "
          "statically-checkable enumeration column is registered on it, and every "
          "membership join keys both sides on a column its api spec produces.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
