#!/usr/bin/env python3
"""Derive the Checkov AWS check catalogue this profile is generated from.

Where this lives and why
------------------------
Derive from the authority, commit the result, do not ship the authority.
Checkov is a large dependency with a hard `boto3` pin that conflicts with the
AWS CLI in a shared environment, so it is not a runtime dependency of this
profile and not vendored here. This script runs by hand, or in CI from an
isolated environment, and what gets reviewed and committed is the YAML it emits.

Run it from a virtualenv holding exactly the pinned release:

    python3 -m venv .venv-checkov
    .venv-checkov/bin/pip install checkov==3.3.16
    .venv-checkov/bin/python tools/build_catalog.py --write

What it records, and why each field is here
-------------------------------------------
``resources``      the check's own ``supported_resources``. This is the
                   applicability contract: one check applies to 1..n resource
                   types, and the ruleset says which. 60 of the 362 AWS checks
                   apply to more than one.

``inspected_key``  per resource type, because it VARIES by type. CKV_AWS_88
                   inspects ``associate_public_ip_address`` on an instance and
                   ``network_interfaces/[0]/associate_public_ip_address`` on a
                   launch template. A catalogue keyed only by check would lose
                   that and every generated control would inspect the wrong
                   field for one of its types.

``expected`` /     the value the check demands or refuses. Present only for the
``forbidden``      value-shaped checks; a custom ``scan_resource_conf`` has no
                   declarative answer to record.

``kind``           value | negative | custom | policy. This is the triage axis:
                   *value* and *negative* scaffold themselves, *custom* must be
                   read and translated by hand, *policy* needs real IAM policy
                   document parsing.

``tf_docs``        derived, not published. Checkov's OSS distribution carries NO
                   guideline URL — 0 of 362 — so the link back to the provider
                   documentation is built from the resource type and the first
                   segment of the inspected key. The argument path is
                   authoritative; the anchor is a best effort and is worth
                   eyeballing during catalogue review.

Not recorded here: NIST anchors, CCIs and severity. Checkov ships none of them
(OSS attaches no severity to a check), so they are assigned during catalogue
review and live in tools/nist_anchors.yml, where they can be reviewed as
compliance claims rather than hidden inside 362 control files.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "checkov_catalog.yml"

# The provider whose resources these checks describe. Part of the derived
# documentation URL, and a constant rather than an argument.
PROVIDER_DOCS = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources"


def docs_url(resource_type: str, inspected_key: str) -> str:
    """Provider documentation for the argument a check inspects.

    `aws_instance` + `metadata_options/[0]/http_tokens`
        -> .../resources/instance#metadata-options

    The first path segment is the argument or block the fix touches. Terraform
    anchors a nested block with dashes and a plain argument with its own name,
    which is why this is a heuristic: the resource page is always right, the
    fragment usually is.
    """
    resource = resource_type.removeprefix("aws_")
    if not inspected_key:
        return f"{PROVIDER_DOCS}/{resource}"
    head = inspected_key.split("/")[0]
    anchor = head if "_" not in head else head.replace("_", "-")
    return f"{PROVIDER_DOCS}/{resource}#{anchor}"


def classify(check) -> str:
    bases = {b.__name__ for b in type(check).__mro__}
    if "BaseResourceValueCheck" in bases:
        return "value"
    if "BaseResourceNegativeValueCheck" in bases:
        return "negative"
    if "BaseTerraformCloudsplainingResourceIAMCheck" in bases:
        return "policy"
    return "custom"


def call(check, method, entity_type=None):
    """Call a check accessor, tolerating the ones that raise or are absent."""
    if not hasattr(check, method):
        return None
    if entity_type is not None:
        # Several checks branch on entity_type inside get_inspected_key.
        check.entity_type = entity_type
    try:
        return getattr(check, method)()
    except Exception:
        return None


def graph_resource_types(node, found=None):
    """Every `resource_types` named anywhere in a graph check's definition."""
    found = set() if found is None else found
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "resource_types" and isinstance(v, list):
                found.update(x for x in v if isinstance(x, str))
            else:
                graph_resource_types(v, found)
    elif isinstance(node, list):
        for v in node:
            graph_resource_types(v, found)
    return found


def build_graph_checks():
    """The JSON graph checks, which the resource registry does not contain."""
    import json
    import checkov
    root = (pathlib.Path(checkov.__file__).parent
            / "terraform" / "checks" / "graph_checks" / "aws")
    out = {}
    for f in sorted(root.glob("*.json")):
        doc = json.loads(f.read_text())
        meta = doc.get("metadata", {})
        cid = meta.get("id")
        if not cid:
            continue
        types = sorted(t for t in graph_resource_types(doc.get("definition", {}))
                       if t.startswith("aws_"))
        out[cid] = {
            "name": meta.get("name", ""),
            "categories": sorted({str(meta.get("category", "")).upper()} - {""}),
            "kind": "graph",
            "resources": types,
            "inspected_key": {t: "" for t in types},
            "tf_docs": {t: docs_url(t, "") for t in types},
        }
    return out


def build():
    from checkov.terraform.runner import Runner  # noqa: F401 — populates registries
    from checkov.terraform.checks.resource.registry import resource_registry

    catalog: dict[str, dict] = {}
    for res_type, checks in resource_registry.checks.items():
        if not res_type.startswith("aws_"):
            continue
        for c in checks:
            entry = catalog.setdefault(c.id, {
                "name": getattr(c, "name", ""),
                "categories": sorted({getattr(x, "name", str(x)) for x in getattr(c, "categories", [])}),
                "kind": classify(c),
                "resources": [],
                "inspected_key": {},
                "tf_docs": {},
            })
            if res_type in entry["resources"]:
                continue
            entry["resources"].append(res_type)
            key = call(c, "get_inspected_key", res_type) or ""
            entry["inspected_key"][res_type] = key
            entry["tf_docs"][res_type] = docs_url(res_type, key)
            expected = call(c, "get_expected_values")
            forbidden = call(c, "get_forbidden_values")
            if expected:
                entry["expected"] = [str(v) for v in expected]
            if forbidden:
                entry["forbidden"] = [str(v) for v in forbidden]
    for entry in catalog.values():
        entry["resources"].sort()

    # Graph checks last, and never overwriting a resource check of the same id.
    for cid, entry in build_graph_checks().items():
        catalog.setdefault(cid, entry)
    return catalog


def dump(catalog, version):
    def scalar(v):
        return "'" + str(v).replace("'", "''") + "'"

    lines = [
        "# Generated by tools/build_catalog.py -- do not edit by hand.",
        "#",
        "# One entry per Checkov AWS check. `resources` is the check's own",
        "# applicability contract; `inspected_key` and `tf_docs` are per resource",
        "# type because the inspected argument varies by type.",
        "#",
        "# kind: value | negative -> the assertion scaffolds from expected/forbidden",
        "#       custom           -> scan_resource_conf must be read and translated",
        "#       policy           -> needs IAM policy document parsing",
        f"_source: {{tool: checkov, version: {scalar(version)}, framework: terraform}}",
        "checks:",
    ]
    for cid, e in sorted(catalog.items()):
        lines.append(f"  {cid}:")
        lines.append(f"    name: {scalar(e['name'])}")
        lines.append(f"    kind: {e['kind']}")
        lines.append(f"    categories: [{', '.join(e['categories'])}]")
        lines.append(f"    resources: [{', '.join(e['resources'])}]")
        if e.get("expected"):
            lines.append(f"    expected: [{', '.join(scalar(v) for v in e['expected'])}]")
        if e.get("forbidden"):
            lines.append(f"    forbidden: [{', '.join(scalar(v) for v in e['forbidden'])}]")
        lines.append("    inspected_key:")
        for r in e["resources"]:
            lines.append(f"      {r}: {scalar(e['inspected_key'].get(r, ''))}")
        lines.append("    tf_docs:")
        for r in e["resources"]:
            lines.append(f"      {r}: {scalar(e['tf_docs'][r])}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true",
                    help=f"write {OUT.name}; otherwise report and change nothing")
    args = ap.parse_args()

    try:
        from checkov.version import version
    except ImportError:
        raise SystemExit("checkov is not importable here — run this from a virtualenv "
                         "holding the pinned release (see the module docstring)")

    catalog = build()
    kinds: dict[str, int] = {}
    for e in catalog.values():
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    types = {r for e in catalog.values() for r in e["resources"]}
    multi = sum(1 for e in catalog.values() if len(e["resources"]) > 1)

    print(f"checkov {version}")
    print(f"  AWS checks           : {len(catalog)}")
    print(f"  aws_ resource types  : {len(types)}")
    print(f"  applying to 2+ types : {multi}")
    print(f"  by kind              : {dict(sorted(kinds.items()))}")

    if not args.write:
        print(f"\ndry run; {OUT.name} not written")
        return 0
    OUT.write_text(dump(catalog, version), encoding="utf-8")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
