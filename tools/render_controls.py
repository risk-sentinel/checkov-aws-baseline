#!/usr/bin/env python3
"""Render controls/CKV_*.rb from the committed data files.

Why generated
-------------
There are 362 AWS checks. Hand-writing 362 control files means 362 chances to
drift from the rule each one claims to implement, and no way to tell which ones
did. Generating them means the drift is impossible by construction and the
review surface is four data files instead of 362 Ruby files.

    tools/checkov_catalog.yml    derived   what Checkov asserts, per resource type
    tools/resource_map.yml       authored  which deployed field answers it
    tools/control_metadata.yml   authored  compliance anchors, severity, rationale
    tools/fix_examples.yml       authored  remediation, per resource type

The generated file is committed so a reader of the repository sees the controls
without running anything, and `--check` fails when the two disagree.

Remediation is Terraform-first
------------------------------
An organisation that manages its estate through Terraform cannot act on an
`aws ec2 modify-...` command: running it either fails a policy gate or is
reverted by the next apply. So every control carries a complete Terraform block
for each resource type it applies to, and the CLI is the secondary path -- for an
estate not under Terraform, or for closing an exposure before the next apply.
Where there is no in-place fix at all, the control says so rather than implying
one exists.

Usage:
    python3 tools/render_controls.py            # rewrite controls/CKV_*.rb
    python3 tools/render_controls.py --check    # exit 1 if any is stale
"""
import argparse
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CONTROLS = ROOT / "controls"

CATALOG = HERE / "checkov_catalog.yml"
RESOURCE_MAP = HERE / "resource_map.yml"
METADATA = HERE / "control_metadata.yml"
FIXES = HERE / "fix_examples.yml"

PROSE = {
    "aws_instance": "instances",
    "aws_launch_template": "launch templates",
    "aws_launch_configuration": "launch configurations",
}


def load():
    catalog = yaml.safe_load(CATALOG.read_text())
    return (catalog["_source"]["version"], catalog["checks"],
            yaml.safe_load(RESOURCE_MAP.read_text())["checks"],
            yaml.safe_load(METADATA.read_text()),
            yaml.safe_load(FIXES.read_text()))


def block(text, indent):
    """Re-indent an authored block for the heredoc it lands in."""
    pad = " " * indent
    lines = [l.rstrip() for l in str(text).strip("\n").split("\n")]
    return "\n".join(pad + l if l else "" for l in lines)


def wrap(text, indent, width=76):
    pad = " " * indent
    words, lines, cur = str(text).split(), [], pad
    for w in words:
        if len(cur) + len(w) + 1 > width and cur.strip():
            lines.append(cur.rstrip())
            cur = pad + w
        else:
            cur = f"{cur}{'' if cur == pad else ' '}{w}"
    if cur.strip():
        lines.append(cur.rstrip())
    return "\n".join(lines)


def check_prose(entry, meta):
    """What Checkov looks for, derived where the catalogue can say it."""
    if meta.get("what"):
        return meta["what"]
    kinds = []
    for res in entry["resources"]:
        key = entry["inspected_key"].get(res) or ""
        if not key:
            continue
        if entry.get("expected"):
            kinds.append(f"{res}: {key} is {' or '.join(entry['expected'])}")
        elif entry.get("forbidden"):
            kinds.append(f"{res}: {key} is not {' or '.join(entry['forbidden'])}")
    return "; ".join(kinds) or entry["name"]


def render_fix(cid, entry, fixes):
    """Terraform per resource type, then the out-of-band path, then caveats."""
    out = []
    per_type = fixes.get(cid, {})
    for res in entry["resources"]:
        example = per_type.get(res)
        if not example:
            continue
        out.append(f"Terraform — {res}:")
        out.append("")
        out.append(block(example["terraform"], 2))
        out.append("")
        if example.get("cli"):
            out.append(f"Out of band — {res}:")
            out.append("")
            out.append(block(example["cli"], 2))
            out.append("")
        if example.get("note"):
            out.append(wrap(f"Note ({res}): {example['note']}", 0))
            out.append("")
    if not out:
        out = [f"See {list(entry['tf_docs'].values())[0]}"]
    return "\n".join(l for l in out).rstrip()


def render(cid, version, entry, mapping, meta, fixes):
    types = [r for r in entry["resources"] if r in mapping]
    fields = {mapping[r]["field"] for r in types}
    if len(fields) != 1:
        raise SystemExit(f"{cid}: resource_map must use one field per check, got {fields}")
    field = fields.pop()
    satisfies = {mapping[r]["satisfies"] for r in types}.pop()
    assertion = {"empty": "be_empty", "equals": None}[satisfies]
    if assertion is None:
        value = mapping[types[0]].get("value")
        assertion = f"be {str(value).lower()}"

    names = [PROSE.get(t, t) for t in types]
    prose = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    types_rb = "%w[" + " ".join(types) + "]"

    stronger = ""
    if meta.get("stronger"):
        stronger = "\n\n" + wrap(meta["stronger"], 4)

    return f'''# Generated by tools/render_controls.py — edit the data files, not this file.
#
# Rule:        {cid} (checkov {version})
# Applies to:  {", ".join(types)}
# Answered by: aws_compute_assets#{field}
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {{}})['{cid}'] || []
applies_to   = {types_rb}

control '{cid}' do
  title '{entry["name"].rstrip(".").replace("'", "''")}'

  desc <<~DESC
{wrap(f"Checkov asserts this against Terraform. This profile asserts it against the {prose} that actually exist.", 4)}{stronger}
  DESC

  desc 'rationale', <<~RATIONALE
{wrap(meta["rationale"], 4)}
  RATIONALE

  desc 'check', <<~CHECK
{wrap("Checkov looks for: " + check_prose(entry, meta), 4)}
  CHECK

  desc 'fix', <<~'FIX'
{block(render_fix(cid, entry, fixes), 4)}
  FIX

  tag checkov_id:       '{cid}'
  tag checkov_category: '{"/".join(entry["categories"])}'
  tag checkov_version:  '{version}'
  tag checkov_kind:     '{entry["kind"]}'
  tag tf_resources:     {types_rb}
  tag tf_argument:      '{entry["inspected_key"].get(types[0]) or "(custom check logic)"}'
  tag tf_docs:          '{entry["tf_docs"][types[0]]}'
  tag nist:             {meta["nist"]}
  tag nist_r4:          {meta["nist_r4"]}
  tag cci:              {meta["cci"]}
  tag ksi:              {meta["ksi"]}
  tag severity:         '{meta["severity"]}'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all — a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to, exempt: exempt)
                   .reject {{ |a| a[:{field}].nil? }}

  applicable = !in_scope.empty?

  # Two statements, not a ternary: InSpec's AST impact collector calls `.value`
  # on the argument node, and a ternary is an IfNode with none — it aborts
  # `check` for the whole profile before a single control runs.
  impact {meta["impact"]}
  impact 0.0 unless applicable

  only_if("no #{{applies_to.join(', ')}} in scope expressing this setting") {{ applicable }}

  in_scope.each do |asset|
    describe "#{{asset[:type]}} #{{asset[:id]}} (#{{asset[:account_id]}}/#{{asset[:region]}})" do
      subject {{ asset[:{field}] }}
      it {{ should {assertion} }}
    end
  end
end
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any generated control is stale; write nothing")
    args = ap.parse_args()

    version, checks, resource_map, metadata, fixes = load()

    stale, written = [], 0
    for cid in sorted(resource_map):
        if cid not in checks:
            raise SystemExit(f"{cid}: mapped but not defined by checkov {version}")
        if cid not in metadata:
            raise SystemExit(f"{cid}: mapped but has no entry in control_metadata.yml")
        body = render(cid, version, checks[cid], resource_map[cid], metadata[cid], fixes)
        target = CONTROLS / f"{cid}.rb"
        if args.check:
            if not target.is_file() or target.read_text() != body:
                stale.append(target.name)
            continue
        if not target.is_file() or target.read_text() != body:
            target.write_text(body)
            written += 1

    if args.check:
        if stale:
            print("::error::generated controls are stale — run "
                  "`python3 tools/render_controls.py` and commit the result.")
            for s in stale:
                print(f"  {s}")
            return 1
        print(f"{len(resource_map)} generated control(s) are in sync with the data files.")
        return 0

    print(f"rendered {len(resource_map)} control(s); {written} changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
