#!/usr/bin/env python3
"""Derive stock mappings and compliance anchors for the checks nobody has reviewed.

442 checks cannot be hand-authored at review quality in one pass, and pretending
otherwise produces 400 confident-looking control files nobody actually read. This
derives what can be derived, writes it to SEPARATE files, and labels every
derived value so the reviewed set and the generated set never blur together:

    resource_map.yml            authored, reviewed
    resource_map_derived.yml    generated  <- this script
    control_metadata.yml        authored, reviewed
    control_metadata_derived.yml generated <- this script

An authored entry always wins; this never overwrites one.

What is derived, and how far it can be trusted
----------------------------------------------
**Mappings.** For a value/negative check whose Terraform resource type has both a
plural and singular stock resource, the inspected key's first path segment is
taken as the property, after an alias table for the divergences already found by
hand: Terraform's `ca_cert_identifier` is `ca_certificate_identifier` on the API,
`database_name` is `db_name`, `subnet_group_name` is `cache_subnet_group_name`.
Three divergences in the first thirty checks says there are more, so a derived
mapping is a starting point, not an answer.

`tools/lint_resource_map.py` verifies the resource and column exist. It cannot
verify the property: those come from `create_resource_methods` over a live API
response. A wrong one raises at exec, visibly, against an account that has the
resource — which is what the honeypot and early-access runs are for.

**Anchors.** Checkov ships no NIST mapping, no CCI and no severity. Derived
anchors come from the check's own category — ENCRYPTION to SC-28, LOGGING to
AU-12, and so on — which is a defensible family-level claim and NOT the
control-level precision a reviewed anchor carries. Every derived control is
tagged `nist_source: 'category-derived'`; reviewed ones say `'reviewed'`. The
tag is the honest part: it lets a consumer filter to the anchors a person
actually checked.
"""
import argparse
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

# Terraform argument -> AWS API response field, where they diverge. Each entry
# here was found by reading the API, and each one would otherwise have produced a
# control asserting on a method that does not exist.
ALIASES = {
    "ca_cert_identifier": "ca_certificate_identifier",
    "database_name": "db_name",
    "subnet_group_name": "cache_subnet_group_name",
    "name": "name",
}

# Category -> (NIST Rev 5, CCI, KSI). Family-level, and labelled as such.
CATEGORY_ANCHORS = {
    "ENCRYPTION":          (["SC-28", "SC-28 (1)"], ["CCI-001199", "CCI-002475"], ["KSI-SVC-CER"]),
    "LOGGING":             (["AU-2", "AU-12"],      ["CCI-000169", "CCI-000172"], ["KSI-MLA-LOG"]),
    "NETWORKING":          (["SC-7", "SC-7 (5)"],   ["CCI-001097", "CCI-002080"], ["KSI-CNA-NDS"]),
    "IAM":                 (["AC-3", "AC-6"],       ["CCI-000213", "CCI-002233"], ["KSI-IAM-CTL"]),
    "BACKUP_AND_RECOVERY": (["CP-9", "CP-10"],      ["CCI-000535", "CCI-000553"], ["KSI-RPL-ABO"]),
    "GENERAL_SECURITY":    (["CM-6"],               ["CCI-000366"],               ["KSI-CMT-CFG"]),
    "SECRETS":             (["IA-5 (7)", "SC-28"],  ["CCI-000196"],               ["KSI-SVC-KMG"]),
    "KUBERNETES":          (["CM-6", "SC-7"],       ["CCI-000366"],               ["KSI-CMT-CFG"]),
    "APPLICATION_SECURITY":(["SA-11", "SI-10"],     ["CCI-003173"],               ["KSI-SCR-MIT"]),
    "SUPPLY_CHAIN":        (["SR-3"],               ["CCI-005080"],               ["KSI-SCR-MIT"]),
    "AI_AND_ML":           (["CM-6"],               ["CCI-000366"],               ["KSI-CMT-CFG"]),
    "GRAPH":               (["CM-6"],               ["CCI-000366"],               ["KSI-CMT-CFG"]),
}
SEVERITY = {"ENCRYPTION": ("high", 0.7), "IAM": ("high", 0.7), "NETWORKING": ("high", 0.7),
            "SECRETS": ("high", 0.7), "LOGGING": ("medium", 0.5),
            "BACKUP_AND_RECOVERY": ("medium", 0.5)}

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
            alts = [p.strip().lstrip(":") for p in re.split(r"[,\s]+", m.group(1)) if p.strip()]
            if alts:
                found.add(alts[0])
    for m in MUST_PROVIDE.finditer(text):
        # "One of `[:key_id, :alias]` must be provided" lists ALTERNATIVES: any
        # one satisfies the resource. Treating them as a conjunction made the
        # deriver give up and guess an argument name that did not exist.
        alternatives = [p.strip().lstrip(":") for p in m.group(1).split(",")]
        found |= {alternatives[0]} if alternatives else set()
    return sorted(p for p in found if PARAM_NAME.fullmatch(p))


def pack():
    out = {}
    for f in sorted(ROOT.glob("vendor/*/libraries/*.rb")):
        text = f.read_text()
        for n in NAME.findall(text):
            out[n] = {"columns": set(COLUMN.findall(text)), "dynamic": DYNAMIC in text,
                      "required": required_params(text)}
    return out


def id_column(plural, singular, resources):
    """The column a plural resource exposes as its identifier."""
    cols = resources[plural]["columns"]
    for guess in (f"{singular.removeprefix('aws_')}_identifiers",
                  f"{singular.removeprefix('aws_')}_identifier",
                  f"{singular.removeprefix('aws_')}_names", f"{singular.removeprefix('aws_')}_name",
                  "ids", "names", "arns"):
        if guess in cols:
            return guess
    for c in sorted(cols):
        if c.endswith(("_identifiers", "_identifier", "_names", "_name", "_ids", "_id")):
            return c
    # A dynamically populated table has no registered columns to choose from; the
    # convention in inspec-aws is the pluralised response field.
    return None if not resources[plural]["dynamic"] else f"{singular.removeprefix('aws_')}_identifiers"


def singular_arg(singular):
    return f"{singular.removeprefix('aws_')}_identifier"


# Checks the deriver must not attempt, with the reason. Being explicit here
# beats a silent absence: a reader can see that this was considered.
EXCLUDED = {
    "CKV_AWS_238": "aws_guardduty_detectors yields non-String ids, so the singular "
                   "resource rejects them — needs a hand-written enumeration",
}


def derive(catalog, authored_map, authored_meta, resources):
    mappings, metadata, skipped = {}, {}, []
    for cid, e in sorted(catalog.items()):
        if cid in authored_map:
            continue
        if cid in EXCLUDED:
            skipped.append((cid, EXCLUDED[cid]))
            continue
        if e["kind"] not in ("value", "negative"):
            skipped.append((cid, f"kind={e['kind']} — needs a person"))
            continue
        chosen = None
        for tf in e["resources"]:
            if not tf.startswith("aws_"):
                continue
            singular = tf if tf in resources else None
            plural = next((n for n in (tf + "s", tf + "es") if n in resources), None)
            if not (singular and plural):
                continue
            # A plural that requires a parameter cannot enumerate an account:
            # aws_api_gateway_stages needs a rest_api_id, aws_s3_bucket_objects a
            # bucket_name. There is nothing to pass it at control scope, and the
            # control errors at exec rather than skipping.
            if resources[plural]["required"]:
                skipped.append((cid, f"{plural} requires {resources[plural]['required']} — "
                                     "cannot enumerate an account"))
                continue
            key = (e["inspected_key"].get(tf) or "").split("/")[0]
            if not key:
                continue
            prop = ALIASES.get(key, key)
            column = id_column(plural, singular, resources)
            if not column:
                continue
            expected = e.get("expected") or []
            forbidden = e.get("forbidden") or []
            if expected == ["CKV_ANY"]:
                sat, val = "not_empty", None
            elif expected and expected[0] in ("True", "true"):
                sat, val = "equals", True
            elif expected and expected[0] in ("False", "false"):
                sat, val = "equals", False
            elif forbidden and forbidden[0] in ("True", "true"):
                sat, val = "equals", False
            elif forbidden and forbidden[0] in ("False", "false"):
                sat, val = "equals", True
            elif forbidden == ["0"]:
                sat, val = "greater_than", 0
            elif expected and all(re.fullmatch(r"[A-Za-z0-9._:-]+", str(v)) for v in expected):
                sat, val = "in_list", [str(v) for v in expected]
            elif expected:
                # Checkov stores some expected values as a stringified list, e.g.
                # "['secrets']". Rendering that into a Ruby array literal produces
                # a syntax error, and guessing what it meant produces a control
                # asserting something nobody chose. Left for a person.
                skipped.append((cid, "expected value is not a plain scalar — needs a person"))
                continue
            else:
                continue
            chosen = (tf, {"reader": "stock",
                           "enumerate": {"resource": plural, "ids": column},
                           "assert": {"resource": singular,
                                      "arg": (resources[singular]["required"][0]
                                              if len(resources[singular]["required"]) == 1
                                              else singular_arg(singular)),
                                      "property": prop, "satisfies": sat,
                                      **({"value": val} if val is not None else {})}})
            break
        if not chosen:
            skipped.append((cid, "no stock plural+singular pair with an inspected key"))
            continue
        mappings[cid] = {chosen[0]: chosen[1]}

        cats = e["categories"] or ["GRAPH"]
        nist, cci, ksi = CATEGORY_ANCHORS.get(cats[0], CATEGORY_ANCHORS["GENERAL_SECURITY"])
        sev, impact = SEVERITY.get(cats[0], ("medium", 0.5))
        metadata[cid] = {
            "severity": sev, "impact": impact,
            "nist": nist, "nist_r4": nist, "cci": cci, "ksi": ksi,
            "nist_source": "category-derived",
            "rationale": (f"{e['name'].rstrip('.')}. Anchors derived from the check's "
                          f"{cats[0].replace('_', ' ').lower()} category, not reviewed "
                          f"control by control."),
        }
    return mappings, metadata, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    catalog = yaml.safe_load((HERE / "checkov_catalog.yml").read_text())["checks"]
    authored_map = yaml.safe_load((HERE / "resource_map.yml").read_text())["checks"]
    authored_meta = yaml.safe_load((HERE / "control_metadata.yml").read_text())
    resources = pack()
    if not resources:
        raise SystemExit("no vendored resource pack — run `cinc-auditor vendor .` first")

    mappings, metadata, skipped = derive(catalog, authored_map, authored_meta, resources)
    print(f"authored (reviewed) : {len(authored_map)}")
    print(f"derived             : {len(mappings)}")
    print(f"still unmappable    : {len(skipped)}")
    reasons = {}
    for _, why in skipped:
        reasons[why.split(' —')[0]] = reasons.get(why.split(' —')[0], 0) + 1
    for why, n in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"    {n:>4}  {why}")

    if not args.write:
        print("\ndry run; nothing written")
        return 0
    (HERE / "resource_map_derived.yml").write_text(
        "# Generated by tools/derive_mappings.py — DERIVED, NOT REVIEWED.\n"
        "# An entry here asserts on a property name taken from the Terraform argument.\n"
        "# tools/lint_resource_map.py confirms the resource and column exist; the\n"
        "# property itself is only confirmed by a live run against that resource type.\n"
        + yaml.safe_dump({"checks": mappings}, sort_keys=True, width=100))
    (HERE / "control_metadata_derived.yml").write_text(
        "# Generated by tools/derive_mappings.py — DERIVED, NOT REVIEWED.\n"
        "# Anchors come from the check's category, which is a family-level claim.\n"
        "# Every control built from this carries nist_source: 'category-derived'.\n"
        + yaml.safe_dump(metadata, sort_keys=True, width=100))
    print(f"\nwrote resource_map_derived.yml and control_metadata_derived.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
