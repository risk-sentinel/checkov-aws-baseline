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

Asserting over a COLLECTION
---------------------------
`satisfies` normally extracts one scalar by dotted path and compares it once.
Three verbs -- `any_of`, `all_of`, `none_of` -- instead judge each ELEMENT of a
collection-valued field and roll the element verdicts up. They are supported on
the `api` reader, whose rows are the API response as plain nested hashes.

    CKV_AWS_24:
      aws_security_group:
        reader: api
        field: ip_permissions        # the collection on the asset row
        satisfies: none_of           # any_of | all_of | none_of
        conditions:                  # a CONJUNCTION, applied to each element
        - path: from_port            # a string, or a list of strings
          satisfies: at_most         # any scalar verb matcher_for knows
          value: 22
          when_absent: true          # the verdict when the path reaches nothing
        - path:
          - ip_ranges.cidr_ip        # several paths: the same test, any of them
          - ipv_6_ranges.cidr_ipv_6
          satisfies: in_list
          value: ['0.0.0.0/0', '::/0']

Four things a data pass has to know, because each one is a way to write a
mapping that cannot fail:

  * Conditions are ANDed. There is no disjunction between two DIFFERENT
    comparisons. `path:` as a list covers "the same test, several places",
    which is what the v4/v6 pair here and the three-log-destinations shape
    elsewhere actually need; anything beyond that is not expressible and must
    not be faked by dropping a condition.
  * A condition is EXISTENTIAL over its paths: it holds when some reachable
    value satisfies it. An array met part-way down a path fans out; an array at
    the end of a path arrives whole, so `empty`/`not_empty` still describe the
    collection rather than its members.
  * `when_absent` is the verdict when a path reaches nothing, default false. It
    exists to give an API's OMISSION its documented meaning -- an EC2
    IpPermission with IpProtocol "-1" carries no FromPort or ToPort, and AWS
    means "every port" by that. Do not use it to paper over a path you have not
    confirmed: it turns an unverified field name into a decided answer.
  * `none_of` and `all_of` are vacuously TRUE over an empty collection, and a
    condition whose path never resolves takes its `when_absent` verdict on every
    element. Either one, applied to the whole population, is a control that
    CANNOT fail and therefore reads as 100% compliant. Two different guards,
    because the two mistakes are not the same kind of thing. A `field:` the API
    does not return is answered at runtime, by a control-scope expectation that
    some in-scope asset exposed it. A misspelled path INSIDE a condition is
    answered statically, by tools/lint_api_paths.rb, which resolves every
    declared path against the AWS SDK's own response model — run it in the
    auditor image whenever you touch these files. Neither `check` nor `json`
    evaluates a control body, so nothing else in the pipeline sees either.

Usage:
    python3 tools/render_controls.py            # rewrite controls/CKV_*.rb
    python3 tools/render_controls.py --check    # exit 1 if any is stale
"""
import argparse
import pathlib
import sys

import yaml

PROVIDER_DOCS = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs"

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


PLANNED_TEMPLATE = """# Generated by tools/render_controls.py — edit the data files, not this file.
#
# Rule:        {cid} (checkov {version})
# Applies to:  {types}
# Status:      PLANNED — no deployed-asset reader exists for {needs} yet.
#
# This control is present so the rule is accounted for. It asserts nothing, and
# it carries no NIST/CCI/KSI tags, because a compliance claim it cannot evaluate
# would be worse than an absent one.

control '{cid}' do
  impact 0.0
  title '{title}'

  desc <<~DESC
    Catalogued from Checkov {version}, not yet assessed here: no reader
    enumerates {needs} in this profile, so there is nothing to assert against.

    This is a gap, not a pass, and not a Not Applicable. tools/lint_catalog_drift.py
    counts it every run.
  DESC

  desc 'check', <<~CHECK
    Checkov looks for: {what}
  CHECK

  desc 'fix', <<~'FIX'
    See {docs}
  FIX

  tag checkov_id:            '{cid}'
  tag checkov_category:      '{cat}'
  tag checkov_version:       '{version}'
  tag checkov_kind:          '{kind}'
  tag tf_resources:          {types_rb}
  tag tf_docs:               '{docs}'
  tag implementation_status: 'planned'

  describe "{cid} — no deployed-asset reader for {needs}" do
    skip 'catalogued from Checkov, not yet implemented in this profile'
  end
end
"""


STOCK_TEMPLATE = """# Generated by tools/render_controls.py — edit the data files, not this file.
#
# Rule:        {cid} (checkov {version})
# Applies to:  {tf_type}
# Read with:   {plural} -> {singular} (stock inspec-aws, no custom reader)
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {{}})['{cid}'] || []

control '{cid}' do
  title '{title}'

  desc <<~DESC
{desc}
  DESC

  desc 'rationale', <<~RATIONALE
{rationale}
  RATIONALE

  desc 'check', <<~CHECK
{what}
  CHECK

  desc 'fix', <<~'FIX'
{fix}
  FIX

  tag checkov_id:            '{cid}'
  tag checkov_category:      '{cat}'
  tag checkov_version:       '{version}'
  tag checkov_kind:          '{kind}'
  tag tf_resources:          {types_rb}
  tag tf_docs:               '{docs}'
  tag nist:                  {nist}
  tag nist_r4:               {nist_r4}
  tag cci:                   {cci}
  tag ksi:                   {ksi}
  tag severity:              '{sev}'
  tag severity_source:       'assessed'
  tag nist_source:           '{nist_source}'
  tag implementation_status: 'implemented'

  # Enumerated at control scope, then each asset asserted on its own. The
  # resource is an ARGUMENT to `describe`, which evaluates on the control --
  # calling it inside the block would defer it into the example.
  #
  # Every call carries aws_region: a stock resource otherwise reads only the
  # region the connection was built with, and every other region's resources
  # report as absent, which renders Not Applicable rather than unexamined.
{enumeration}

  # A plural resource whose table is built from the API response returns nil for
  # a column that does not exist, rather than raising. Passing that on gives
  # "`[:x]` must be provided" and kills the control. Blank ids are separated out
  # and asserted on below, so a wrong `ids` column is a visible failure rather
  # than a crash or a silent Not Applicable.
  unusable = found.count {{ |id, _r| "#{{id}}".strip.empty? }}
  found = found.reject {{ |id, _r| "#{{id}}".strip.empty? }}
  in_scope = found.reject {{ |id, _r| checkov_exempt?(id: id, type: '{tf_type}', rules: exempt) }}

  if unusable.positive?
    describe "{tf_type} enumeration" do
      it 'produced usable identifiers' do
        expect(unusable).to eq(0),
          "#{{unusable}} row(s) had a blank id — the `ids` column in resource_map.yml "\
          'likely names a field this resource does not expose'
      end
    end
  end

  # `unusable.positive?` keeps the control APPLICABLE when every id came back
  # blank. Without it only_if skips the control, and the wrong-column case this
  # guard exists to catch is exactly the case it would suppress — a Not
  # Applicable that means "the enumeration is broken".
  applicable = !in_scope.empty? || unusable.positive?
  impact {impact}
  impact 0.0 unless applicable
  only_if('no {tf_type} in scope') {{ applicable }}

  in_scope.each do |id, region|
    describe {singular}({arg_expr}) do
      its('{prop}') {{ {matcher} }}
    end
  end
end
"""


API_TEMPLATE = """# Generated by tools/render_controls.py — edit the data files, not this file.
#
# Rule:        {cid} (checkov {version})
# Applies to:  {tf_type}
# Read with:   aws_api_assets (declarative spec, tools/api_specs.yml)
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {{}})['{cid}'] || []
{conditions_block}
control '{cid}' do
  title '{title}'

  desc <<~DESC
{desc}{stronger}
  DESC

  desc 'rationale', <<~RATIONALE
{rationale}
  RATIONALE

  desc 'check', <<~CHECK
{what}
  CHECK

  desc 'fix', <<~'FIX'
{fix}
  FIX

  tag checkov_id:            '{cid}'
  tag checkov_category:      '{cat}'
  tag checkov_version:       '{version}'
  tag checkov_kind:          '{kind}'
  tag tf_resources:          {types_rb}
  tag tf_docs:               '{docs}'
  tag nist:                  {nist}
  tag nist_r4:               {nist_r4}
  tag cci:                   {cci}
  tag ksi:                   {ksi}
  tag severity:              '{sev}'
  tag severity_source:       'assessed'
  tag nist_source:           '{nist_source}'
  tag implementation_status: 'implemented'

  assets = aws_api_assets(type: '{tf_type}', regions: scan_regions)

  # A region — or a whole service — that could not be READ is not the same as
  # one with nothing in it. A missing SDK gem, a denied call or an unreachable
  # endpoint all end up here, and without this assertion they render as "no
  # assets" and the control reports Not Applicable: the worst case reported as
  # "does not apply here".
  unreadable = assets.unreadable_regions
  unless unreadable.empty?
    describe "{tf_type} enumeration" do
      it 'read every region it attempted' do
        expect(unreadable.map {{ |r| "#{{r[:region]}}: #{{r[:error]}}" }}).to be_empty
      end
    end
  end

  # A blank id means the spec's `id` column names a member this response does
  # not carry. tools/lint_resource_map.py cannot see that statically, and the
  # damage is silent: every describe is titled with a blank where the identity
  # belongs, and `exempt_assets` entries keyed by id stop matching. Asserted,
  # not filtered — filtering renders Not Applicable, which is the same silence.
  enumerated = assets.assets(exempt: exempt)
  unusable = enumerated.count {{ |a| "#{{a[:id]}}".strip.empty? }}
  if unusable.positive?
    describe "{tf_type} enumeration" do
      it 'produced usable identifiers' do
        expect(unusable).to eq(0),
          "#{{unusable}} row(s) had a blank id — the `id` for {tf_type} in "\\
          'tools/api_specs.yml likely names a member this API does not return'
      end
    end
  end

{nil_filter_comment}
  in_scope = enumerated{nil_filter}
{collection_guard}
  # `applicable` is a CLAIM that this rule does not apply to this boundary, and
  # only an enumeration that succeeded can earn it. An unreadable region or a
  # blank id column keeps the control applicable so the assertions above are
  # reported; without that, only_if skips the whole control — the two guards
  # included — and the worst case, "every region denied", renders as Not
  # Applicable. The stock template already carries the `unusable` half of this.
  applicable = !in_scope.empty? || !unreadable.empty? || unusable.positive?
  impact {impact}
  impact 0.0 unless applicable
  only_if('no {tf_type} in scope expressing this setting') {{ applicable }}

  in_scope.each do |asset|
    describe "{tf_type} #{{asset[:id]}} (#{{asset[:account_id]}}/#{{asset[:region]}})" do
      subject {{ asset[:{field}] }}
      it {{ {matcher} }}
    end
  end
end
"""


SINGLETON_TEMPLATE = """# Generated by tools/render_controls.py — edit the data files, not this file.
#
# Rule:        {cid} (checkov {version})
# Applies to:  {tf_type}
# Read with:   {resource} — an account-level singleton, so there is nothing to enumerate
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

control '{cid}' do
  title '{title}'

  desc <<~DESC
{desc}
  DESC

  desc 'rationale', <<~RATIONALE
{rationale}
  RATIONALE

  desc 'check', <<~CHECK
{what}
  CHECK

  desc 'fix', <<~'FIX'
{fix}
  FIX

  tag checkov_id:            '{cid}'
  tag checkov_category:      '{cat}'
  tag checkov_version:       '{version}'
  tag checkov_kind:          '{kind}'
  tag tf_resources:          {types_rb}
  tag tf_docs:               '{docs}'
  tag nist:                  {nist}
  tag nist_r4:               {nist_r4}
  tag cci:                   {cci}
  tag ksi:                   {ksi}
  tag severity:              '{sev}'
  tag severity_source:       'assessed'
  tag nist_source:           '{nist_source}'
  tag implementation_status: 'implemented'

  subject_resource = {resource}

  # Always applicable. An account with no policy at all is the NON-COMPLIANT
  # state for this rule, not an inapplicable one — rendering it Not Applicable
  # would report the worst case as "does not apply here".
  impact {impact}

  describe '{tf_type}' do
    it 'is configured for this account' do
      expect(subject_resource.exists?).to eq(true),
        'no account-level policy is set, so nothing constrains this'
    end
  end
{guard_block}
  if {guard_condition}
    describe subject_resource do
      its('{prop}') {{ {matcher} }}
    end
  end
end
"""


def load():
    """Reviewed data first, derived data second — and an authored entry always wins.

    The two are separate files on purpose. A derived mapping asserts on a property
    name taken from the Terraform argument, and a derived anchor is a family-level
    claim from the check's category. Merging them into the authored files would
    erase the only signal a reader has for which is which.
    """
    catalog = yaml.safe_load(CATALOG.read_text())
    resource_map = yaml.safe_load(RESOURCE_MAP.read_text())["checks"]
    metadata = yaml.safe_load(METADATA.read_text())

    derived_map = HERE / "resource_map_derived.yml"
    if derived_map.is_file():
        for cid, spec in (yaml.safe_load(derived_map.read_text()) or {}).get("checks", {}).items():
            resource_map.setdefault(cid, spec)
    derived_meta = HERE / "control_metadata_derived.yml"
    if derived_meta.is_file():
        for cid, meta in (yaml.safe_load(derived_meta.read_text()) or {}).items():
            metadata.setdefault(cid, meta)

    return (catalog["_source"]["version"], catalog["checks"], resource_map, metadata,
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

    # f-string template below, so these must be locals rather than format args.
    nist_source = meta.get("nist_source", "reviewed")
    nil_filter, nil_filter_comment = nil_filter_for(satisfies, field)

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
  tag nist_source:      '{nist_source}'
  tag implementation_status: 'implemented'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all — a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
{nil_filter_comment}
  in_scope = assets.assets_of(applies_to, exempt: exempt){nil_filter}

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


def render_stock(cid, version, entry, mapping, meta, fixes):
    """A control that reads a stock inspec-aws resource, with no custom library.

    Roughly a third of Checkov's AWS checks land on a resource type inspec-aws
    already enumerates. Writing a bespoke reader for those would be duplicating
    a maintained resource pack in order to answer the same question slightly
    differently.
    """
    tf_type = next(iter(mapping))
    spec = mapping[tf_type]
    enum, assertion = spec["enumerate"], spec["assert"]
    # One matcher implementation, shared with render_api. This block used to be a
    # duplicate of it and drifted: the shared one learned to quote strings, this
    # one did not, so a stock mapping with a string value would still render a
    # bare lowercased identifier — a NameError that reads as a finding.
    satisfies = assertion.get("satisfies", "equals")
    matcher = matcher_for(cid, satisfies, assertion.get("value"))

    return STOCK_TEMPLATE.format(
        cid=cid, version=version, tf_type=tf_type,
        title=entry["name"].rstrip(".").replace("'", "''"),
        desc=wrap(f"Checkov asserts this against Terraform. This profile asserts it against "
                  f"the {tf_type} resources that actually exist, read through the stock "
                  f"inspec-aws {assertion['resource']} resource.", 4),
        rationale=wrap(meta["rationale"], 4),
        what=wrap("Checkov looks for: " + check_prose(entry, meta), 4),
        fix=block(render_fix(cid, entry, fixes), 4),
        cat="/".join(entry["categories"]) or "GRAPH",
        kind=entry["kind"],
        types_rb="%w[" + " ".join(t for t in entry["resources"] if t.startswith("aws_")) + "]",
        docs=entry["tf_docs"].get(tf_type, PROVIDER_DOCS),
        nist=meta["nist"], nist_r4=meta["nist_r4"], cci=meta["cci"], ksi=meta["ksi"],
        sev=meta["severity"], impact=meta["impact"],
        nist_source=meta.get("nist_source", "reviewed"),
        plural=enum["resource"], ids_column=enum["ids"],
        enumeration=enumeration_for(spec, enum),
        singular=assertion["resource"],
        arg_expr=(("id, aws_region: region" if spec.get("scope") != "global" else "id")
                  if assertion.get("arg") in (None, "", "positional")
                  else (f"{assertion['arg']}: id, aws_region: region"
                        if spec.get("scope") != "global"
                        else f"{assertion['arg']}: id")),
        prop=assertion["property"], matcher=matcher)


def ruby_literal(value):
    """A value as Ruby source.

    `str(value).lower()` was wrong for anything but a boolean: an expected value
    of "IMMUTABLE" rendered as the bare word `immutable`, which is a NameError at
    exec and reports as a FAILED control rather than an errored one — a broken
    control that reads as a finding.

    The quote escape is `\\'`, not `''`. `''` is the SQL escape; Ruby reads
    `'a''b'` as two adjacent literals and concatenates them to "ab", silently
    DROPPING the quote — so a value containing an apostrophe would be compared
    against a string that is not the one authored, and the control would fail
    (or pass) on a value nobody wrote. A backslash has to be escaped first or it
    would eat the escape that follows it. tools/render_api_specs.py's `ruby()`
    already had this right; this is the same rule in the other renderer.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def enumeration_for(spec, enum):
    """How a stock control enumerates its assets.

    Global services — S3, IAM, CloudFront, Route 53 — return the same objects
    from any region, so walking regions would assess every bucket once per
    region and multiply both the API calls and the results. They are enumerated
    once, with no `aws_region:` at all: passing a placeholder would hand the SDK
    a region that does not exist.
    """
    if spec.get("scope") == "global":
        return (f"  # Global service: the same objects come back from any region, so this is\n"
                f"  # enumerated once rather than once per region.\n"
                f"  found = {enum['resource']}.{enum['ids']}.to_a.map {{ |id| [id, nil] }}")
    return (f"  found = checkov_scan_regions(scan_regions).flat_map do |region|\n"
            f"    {enum['resource']}(aws_region: region).{enum['ids']}.to_a"
            f".map {{ |id| [id, region] }}\n"
            f"  end")


def nil_filter_for(satisfies, field):
    """Whether a nil field means "out of scope" or "this is the failure".

    For a value comparison, a field the API did not return means the asset does
    not express the setting: out of scope, not in breach. For a PRESENCE check
    (`not_empty`), nil is precisely the failing state, and filtering it first
    made the control structurally unfailable — it silently rendered Not
    Applicable for every asset that should have failed.
    """
    if satisfies in COLLECTION_VERBS:
        # A collection roll-up must see every asset. Filtering the nil ones out
        # removes the population `collection_guard_for` counts to prove the
        # mapping names a field this API actually returns, and for `any_of` it
        # removes exactly the assets that fail.
        return ("", "  # A collection roll-up is not nil-filtered: an asset that does not\n"
                    "  # express the field is part of the population the guard below counts,\n"
                    "  # and for any_of it is precisely the failing case.")
    if satisfies in ("not_empty", "empty"):
        return ("", "  # A nil field is the FAILING state for a presence check, so it is\n"
                    "  # deliberately not filtered out here.")
    return (f"\n                        .reject {{ |a| a[:{field}].nil? }}",
            "  # A field the API did not return is nil, and nil is not a failing value:\n"
            "  # the asset does not express this setting, so it is out of scope for this\n"
            "  # check rather than in breach of it.")


def ruby_string(text):
    """A double-quoted Ruby string literal.

    ruby_literal() writes single-quoted Ruby and escapes an embedded quote as
    `''`, which is the SQL escape, not Ruby's: Ruby reads `'a''b'` as two
    adjacent literals and concatenates them to "ab", losing the quote. That is
    invisible for the values it is used on today, all of which are AWS enum
    strings. Matcher descriptions are prose built from user data, so they are
    written double-quoted with real escapes instead. `#` is escaped too — only
    a `#` followed by `{`, `$` or `@` interpolates, but escaping every `#` is
    one rule instead of three.
    """
    out = str(text).replace("\\", "\\\\").replace('"', '\\"').replace("#", "\\#")
    return '"' + out + '"'


# The comparison vocabulary, in one place. Every verb here must be renderable
# BOTH as an RSpec matcher (matcher_for, used when the asset's own field is the
# subject) and as a Ruby lambda (predicate_for, used inside a collection walk,
# where RSpec matchers are not available). main() asserts that, so a verb added
# to one and forgotten in the other fails the render rather than the exec.
SCALAR_VERBS = ("equals", "not_equals", "empty", "not_empty", "greater_than",
                "less_than", "at_least", "at_most", "in_list", "not_in_list",
                "includes", "excludes", "matches")

# Roll-up verbs: these take a `conditions:` list instead of a `value:`, and they
# assert over the ELEMENTS of a collection-valued field rather than over the
# field itself. See libraries/_checkov_collection.rb for the semantics.
COLLECTION_VERBS = ("any_of", "all_of", "none_of")

# How the roll-up reads in a failure message. RSpec prefixes "expected <...> to".
ROLLUP_PROSE = {
    "any_of": "have an element where",
    "all_of": "have only elements where",
    "none_of": "have no element where",
}


def matcher_for(cid, satisfies, value):
    """The RSpec matcher a `satisfies` maps to, shared by the stock and API shapes."""
    if satisfies in COLLECTION_VERBS:
        raise SystemExit(
            f"{cid}: '{satisfies}' asserts over the elements of a collection and needs a "
            f"`conditions:` list, so it cannot be rendered as a plain matcher. It is "
            f"supported on the `api` reader only — see collection_matcher_for.")
    if satisfies == "equals":
        return f"should eq {ruby_literal(value)}"
    if satisfies == "not_empty":
        # "is set" — nil and an empty string/array all fail. `should_not be_empty`
        # alone raises on nil, and filtering nil out beforehand removes exactly the
        # population that fails.
        return ("should satisfy('be set') { |v| "
                "!v.nil? && !(v.respond_to?(:empty?) && v.empty?) }")
    if satisfies == "empty":
        return ("should satisfy('be unset or empty') { |v| "
                "v.nil? || (v.respond_to?(:empty?) && v.empty?) }")
    if satisfies == "greater_than":
        return f"should be > {ruby_literal(value)}"
    if satisfies == "in_list":
        return "should be_in [" + ", ".join(ruby_literal(v) for v in value) + "]"
    if satisfies == "not_equals":
        return f"should_not eq {ruby_literal(value)}"
    if satisfies == "not_in_list":
        return "should_not be_in [" + ", ".join(ruby_literal(v) for v in value) + "]"
    if satisfies == "at_least":
        # `greater_than` is strict, so a policy demanding "at least 14" failed on
        # exactly 14 — the boundary the requirement names.
        return f"should be >= {ruby_literal(value)}"
    if satisfies == "at_most":
        return f"should be <= {ruby_literal(value)}"
    if satisfies == "less_than":
        return f"should be < {ruby_literal(value)}"
    if satisfies == "includes":
        return f"should include {ruby_literal(value)}"
    if satisfies == "excludes":
        return f"should_not include {ruby_literal(value)}"
    if satisfies == "matches":
        return f"should match(/{value}/)"
    raise SystemExit(f"{cid}: unknown satisfies '{satisfies}'")


def predicate_for(cid, satisfies, value):
    """The same verb as a Ruby lambda, for use inside a collection walk.

    An element condition cannot use an RSpec matcher: it runs inside a plain
    Ruby predicate in libraries/_checkov_collection.rb, called from a `satisfy`
    block. The obvious alternative — a table of the thirteen verbs on the Ruby
    side — would make the walker a SECOND authority on what `at_most` means, and
    the one time this repository kept two copies of the verb logic they drifted
    (see render_stock). So the verb vocabulary stays here, and the walker
    receives it already compiled.

    Nothing guards against a type mismatch (`'yes' <= 22`). That raises inside
    the example, which reports as an ERRORED control — visible, and the honest
    outcome for a mapping that compares a string to a number. Swallowing it into
    `false` would make the condition unsatisfiable and the roll-up unfailable.
    """
    if satisfies == "equals":
        return f"->(v) {{ v == {ruby_literal(value)} }}"
    if satisfies == "not_equals":
        return f"->(v) {{ v != {ruby_literal(value)} }}"
    if satisfies == "not_empty":
        return "->(v) { !v.nil? && !(v.respond_to?(:empty?) && v.empty?) }"
    if satisfies == "empty":
        return "->(v) { v.nil? || (v.respond_to?(:empty?) && v.empty?) }"
    if satisfies == "greater_than":
        return f"->(v) {{ v > {ruby_literal(value)} }}"
    if satisfies == "less_than":
        return f"->(v) {{ v < {ruby_literal(value)} }}"
    if satisfies == "at_least":
        return f"->(v) {{ v >= {ruby_literal(value)} }}"
    if satisfies == "at_most":
        return f"->(v) {{ v <= {ruby_literal(value)} }}"
    if satisfies == "in_list":
        return "->(v) { [" + ", ".join(ruby_literal(v) for v in value) + "].include?(v) }"
    if satisfies == "not_in_list":
        return "->(v) { ![" + ", ".join(ruby_literal(v) for v in value) + "].include?(v) }"
    if satisfies == "includes":
        return f"->(v) {{ v.include?({ruby_literal(value)}) }}"
    if satisfies == "excludes":
        return f"->(v) {{ !v.include?({ruby_literal(value)}) }}"
    if satisfies == "matches":
        return f"->(v) {{ v.to_s.match?(/{value}/) }}"
    raise SystemExit(f"{cid}: unknown satisfies '{satisfies}'")


def verb_prose(satisfies, value):
    """The verb as it reads in a failure message."""
    if satisfies in ("empty", "not_empty"):
        return "is unset or empty" if satisfies == "empty" else "is set"
    if satisfies in ("in_list", "not_in_list"):
        joined = ", ".join(str(v) for v in value)
        return f"{'is' if satisfies == 'in_list' else 'is not'} one of [{joined}]"
    symbol = {"equals": "==", "not_equals": "!=", "greater_than": ">", "less_than": "<",
              "at_least": ">=", "at_most": "<=", "includes": "includes",
              "excludes": "excludes", "matches": "matches"}[satisfies]
    return f"{symbol} {value}"


def condition_parts(cid, condition):
    """One authored condition, as (ruby_hash_source, prose).

    The schema is deliberately the EXISTING one, one level down: `path`,
    `satisfies` and `value` mean inside an element exactly what they mean on an
    asset. `path` also accepts a list, which is "the same test, in any of these
    places" — the security-group v4/v6 pair and the MSK three-log-destinations
    case are both that, and without it they would need a disjunction the
    conjunction semantics cannot express.
    """
    if not isinstance(condition, dict):
        raise SystemExit(f"{cid}: each entry of `conditions` must be a mapping, got {condition!r}")
    unknown = set(condition) - {"path", "satisfies", "value", "when_absent", "note"}
    if unknown:
        raise SystemExit(f"{cid}: unknown key(s) in a condition: {sorted(unknown)}")
    paths = condition.get("path")
    if not paths:
        raise SystemExit(f"{cid}: a condition needs a `path`")
    paths = [paths] if isinstance(paths, str) else list(paths)
    satisfies = condition.get("satisfies")
    if satisfies not in SCALAR_VERBS:
        raise SystemExit(f"{cid}: a condition's `satisfies` must be one of {list(SCALAR_VERBS)}, "
                         f"got '{satisfies}' — a roll-up verb cannot nest inside a condition")
    when_absent = condition.get("when_absent", False)
    if not isinstance(when_absent, bool):
        raise SystemExit(f"{cid}: `when_absent` is the VERDICT when the path reaches nothing, "
                         f"so it must be true or false, got {when_absent!r}")
    if satisfies == "empty" and "when_absent" not in condition:
        # `empty` is the one verb the default inverts. An API member the response
        # OMITTED is the strongest form of "empty", and the default verdict says
        # it is not — so `path: x, satisfies: empty` silently answers the opposite
        # of what it reads like on exactly the elements it most needs to catch.
        # Every other verb's default is the safe direction; this one has to be
        # said out loud.
        raise SystemExit(f"{cid}: a condition using `empty` must state `when_absent` "
                         f"explicitly — an omitted member is the strongest case of empty, "
                         f"and the default verdict (false) says it is not")

    where = paths[0] if len(paths) == 1 else "(" + " or ".join(paths) + ")"
    prose = f"{where} {verb_prose(satisfies, condition.get('value'))}"
    if when_absent:
        prose += " (or absent)"

    fields = ["paths: [" + ", ".join(ruby_literal(p) for p in paths) + "]"]
    if when_absent:
        fields.append("when_absent: true")
    fields.append("test: " + predicate_for(cid, satisfies, condition.get("value")))
    return fields, prose


def conditions_block_for(cid, satisfies, conditions):
    """The file-scope `element_conditions` literal a collection control closes over.

    Hoisted out of the matcher because the matcher lands inside `it { ... }` on
    one line, and three conditions with their lambdas do not fit there legibly.
    A file-scope local is captured lexically by the describe/it/satisfy blocks
    below it — the same mechanism `scan_regions` and `exempt` already rely on.
    """
    if satisfies not in COLLECTION_VERBS:
        return ""
    if not conditions:
        raise SystemExit(f"{cid}: '{satisfies}' needs a non-empty `conditions:` list — a "
                         f"roll-up with no conditions matches every element or none of them, "
                         f"and either way asserts nothing")

    lines = [
        "",
        "# Conditions applied to each ELEMENT of the collection this check judges.",
        "# An element matches when EVERY condition holds; a condition holds when SOME",
        "# value reachable at ANY of its paths satisfies the test. `when_absent` is the",
        "# verdict when a path reaches nothing at all, which is how a member the API",
        "# omits is given its documented meaning. Generated from resource_map.yml by",
        "# tools/render_controls.py; the walk is libraries/_checkov_collection.rb.",
        "element_conditions = [",
    ]
    for condition in conditions:
        fields, prose = condition_parts(cid, condition)
        lines.append(f"  # {prose}")
        lines.append("  { " + fields[0] + ",")
        for field in fields[1:-1]:
            lines.append("    " + field + ",")
        lines.append("    " + fields[-1] + " },")
    lines.append("].freeze")
    return "\n".join(lines) + "\n"


def collection_matcher_for(cid, satisfies, conditions):
    """The matcher for a roll-up: a `satisfy` block delegating to the walker.

    `::CheckovCollection` is reached by CONSTANT and never included into
    ::Inspec::Rule. A module included into Rule lives on the CONTROL, and this
    call is inside a `satisfy` block, which is deferred into the example — the
    exact scope mismatch tools/lint_resource_scope.py exists to catch.

    The leading `::` is load-bearing. InSpec instance_evals both library files
    and control files in ANONYMOUS eval contexts, so an unqualified
    `CheckovCollection` is looked up under the control's own context and is not
    found — "uninitialized constant #<Class:#<Inspec::ControlEvalContext>>::
    CheckovCollection", at exec, on every asset. `check` and `json` never
    evaluate a control body, so neither one sees it.
    """
    prose = [condition_parts(cid, c)[1] for c in conditions]
    label = ROLLUP_PROSE[satisfies] + " " + " and ".join(prose)
    return (f"should satisfy({ruby_string(label)}) "
            f"{{ |v| ::CheckovCollection.{satisfies}?(v, element_conditions) }}")


def collection_guard_for(satisfies, tf_type, field):
    """The expectation that stops a roll-up from being structurally unfailable.

    `none_of` and `all_of` are both vacuously TRUE over an empty collection. For
    one asset that genuinely has no elements that is the right answer; when it is
    EVERY asset, the control cannot fail, and a control that cannot fail reads as
    a clean pass rather than as a broken mapping. A `field:` this API does not
    return produces exactly that, and nothing else in the pipeline sees it —
    `check` and `json` do not evaluate a control body.

    So it is asserted, not filtered — filtering removes the population and
    renders Not Applicable, which is the same silence wearing a different label.

    The question asked is whether ANY in-scope asset exposed the field, not
    whether every one did. A field name that is wrong is wrong for the whole
    population, so one asset carrying it settles the mapping; an individual nil
    is a real state — a security group with no ingress rules, an ELB with no
    listeners — and it passes for the same reason a nil scalar is filtered out of
    scope under the other verbs. Demanding it of every asset would fail a
    compliant account for being empty.

    Rendered under all three verbs. `any_of` cannot pass vacuously (an absent
    collection satisfies nothing, so a wrong field shows up as every asset
    failing), but a diagnosed mass failure beats an undiagnosed one.

    The paths INSIDE a condition are NOT guarded here. A typo there is the same
    catastrophe one level down, and the runtime version of this guard was written
    for it and then removed: asking the population whether a path ever resolved
    cannot tell a typo from a tidy account, and `ip_ranges.cidr_ip` reaches
    nothing in an account whose rules all reference peer security groups — an
    account that is COMPLIANT and would have been failed for it. That question is
    static and exact, and it lives in tools/lint_api_paths.rb, which resolves
    every declared path against the AWS SDK's own response model.
    """
    if satisfies not in COLLECTION_VERBS:
        return ""
    return f"""
  # {satisfies} is vacuously TRUE over an empty collection, so an asset that did
  # not carry this field passes without being examined. For one asset with no
  # elements that is the right answer; when it is EVERY asset the control can no
  # longer fail, and a control that cannot fail reads as compliant rather than as
  # a mapping naming a field this API does not return. The condition paths one
  # level down are checked statically instead — tools/lint_api_paths.rb.
  exposing = in_scope.count {{ |a| !a[:{field}].nil? }}

  describe '{tf_type} {field}' do
    it 'was returned for at least one asset in scope' do
      expect(exposing).to be_positive,
        'no asset in scope exposed {field}, so the roll-up below cannot fail: '\\
        'either tools/api_specs.yml names a field this API does not return, or '\\
        'nothing in this boundary expresses it'
    end
  end
"""


def render_api(cid, version, entry, mapping, meta, fixes):
    """A control reading a type described in tools/api_specs.yml.

    This is also the only shape that can roll a verdict up over a
    COLLECTION-valued field. The api reader hands back plain nested hashes taken
    straight from the API response, so an element walk is a walk over data; a
    stock mapping's property is whatever create_resource_methods built over the
    response, reachable only one asset at a time, and the vacuous-pass guard
    below would cost one API call per asset to compute.
    """
    tf_type = next(iter(mapping))
    spec = mapping[tf_type]
    satisfies = spec.get("satisfies", "equals")
    conditions = spec.get("conditions") or []
    if conditions and satisfies not in COLLECTION_VERBS:
        raise SystemExit(f"{cid}: `conditions:` only means something under a roll-up verb "
                         f"({', '.join(COLLECTION_VERBS)}), not under '{satisfies}'")
    matcher = (collection_matcher_for(cid, satisfies, conditions)
               if satisfies in COLLECTION_VERBS
               else matcher_for(cid, satisfies, spec.get("value")))
    stronger = "\n\n" + wrap(meta["stronger"], 4) if meta.get("stronger") else ""

    return API_TEMPLATE.format(
        cid=cid, version=version, tf_type=tf_type,
        title=entry["name"].rstrip(".").replace("'", "''"),
        desc=wrap(f"Checkov asserts this against Terraform. This profile asserts it against "
                  f"the {tf_type} resources that actually exist, enumerated through the "
                  f"declarative API spec.", 4),
        stronger=stronger,
        rationale=wrap(meta["rationale"], 4),
        what=wrap("Checkov looks for: " + check_prose(entry, meta), 4),
        fix=block(render_fix(cid, entry, fixes), 4),
        cat="/".join(entry["categories"]) or "GRAPH", kind=entry["kind"],
        types_rb="%w[" + " ".join(t for t in entry["resources"] if t.startswith("aws_")) + "]",
        docs=entry["tf_docs"].get(tf_type, PROVIDER_DOCS),
        nist=meta["nist"], nist_r4=meta["nist_r4"], cci=meta["cci"], ksi=meta["ksi"],
        sev=meta["severity"], impact=meta["impact"],
        nist_source=meta.get("nist_source", "reviewed"),
        field=spec["field"],
        conditions_block=conditions_block_for(cid, satisfies, conditions),
        collection_guard=collection_guard_for(satisfies, tf_type, spec["field"]),
        nil_filter=nil_filter_for(satisfies, spec["field"])[0],
        nil_filter_comment=nil_filter_for(satisfies, spec["field"])[1],
        matcher=matcher)


def render_singleton(cid, version, entry, mapping, meta, fixes):
    """A control for an account-level singleton: one object, nothing to enumerate.

    The IAM account password policy is the case that forced this. It has no
    plural because the API returns one object per account, and two of its
    readers RAISE rather than return nil when the corresponding feature is off:
    `max_password_age_in_days` raises unless `expire_passwords?`. So a guard is
    declared, asserted as its own expectation — because "passwords never expire"
    is itself the finding — and the guarded property is only read when it is
    safe to read.
    """
    tf_type = next(iter(mapping))
    spec = mapping[tf_type]
    guard = spec.get("guard")
    guard_block = ""
    condition = "subject_resource.exists?"
    if guard:
        guard_block = (f"\n  describe '{tf_type} — {guard.rstrip('?').replace('_', ' ')}' do\n"
                       f"    it 'is enabled, so the value below is meaningful' do\n"
                       f"      expect(subject_resource.exists? && subject_resource.{guard}).to eq(true),\n"
                       f"        'the policy does not enable this, so the threshold it should "
                       f"satisfy is unenforced'\n"
                       f"    end\n  end\n")
        condition = f"subject_resource.exists? && subject_resource.{guard}"
    return SINGLETON_TEMPLATE.format(
        cid=cid, version=version, tf_type=tf_type, resource=spec["resource"],
        title=entry["name"].rstrip(".").replace("'", "''"),
        desc=wrap(f"Checkov asserts this against Terraform. This profile asserts it against "
                  f"the account's own {tf_type}, which is a single object rather than a "
                  f"collection.", 4),
        rationale=wrap(meta["rationale"], 4),
        what=wrap("Checkov looks for: " + check_prose(entry, meta), 4),
        fix=block(render_fix(cid, entry, fixes), 4),
        cat="/".join(entry["categories"]) or "IAM", kind=entry["kind"],
        types_rb="%w[" + " ".join(t for t in entry["resources"] if t.startswith("aws_")) + "]",
        docs=entry["tf_docs"].get(tf_type, PROVIDER_DOCS),
        nist=meta["nist"], nist_r4=meta["nist_r4"], cci=meta["cci"], ksi=meta["ksi"],
        sev=meta["severity"], impact=meta["impact"],
        nist_source=meta.get("nist_source", "reviewed"),
        guard_block=guard_block, guard_condition=condition,
        prop=spec["property"],
        matcher=matcher_for(cid, spec.get("satisfies", "equals"), spec.get("value")))


def render_planned(cid, version, entry, meta):
    """A rule that is catalogued but has no reader.

    It asserts nothing and claims nothing: no NIST, CCI or KSI tags, because a
    compliance anchor on a control that cannot evaluate is a claim the profile
    has not earned. Those arrive with the reader.
    """
    types = [r for r in entry["resources"] if r.startswith("aws_")]
    # A graph check's resource types are inferred from its definition, and 29 of
    # them name none it can reach -- they match on attributes or on connections
    # whose ends are not declared as resource_types. An empty list is a real
    # state, not a parse failure, and it must not index off the end.
    needs = ", ".join(types) if types else "the resources this graph check connects"
    docs = entry["tf_docs"][types[0]] if types else PROVIDER_DOCS
    return PLANNED_TEMPLATE.format(
        cid=cid, version=version,
        title=entry["name"].rstrip(".").replace("'", "''"),
        types=", ".join(types) or "(not derivable from the graph definition)",
        types_rb="%w[" + " ".join(types) + "]",
        needs=needs,
        what=check_prose(entry, meta).replace('"', "'"),
        cat="/".join(entry["categories"]) or "GRAPH",
        kind=entry["kind"],
        docs=docs)


def check_verb_vocabulary():
    """Every scalar verb must render both ways, and neither name space may overlap.

    A verb that has a matcher and no predicate is invisible until the first
    mapping uses it inside a condition, at which point the render dies mid-run
    with a partial controls/ directory. A verb name reused as a roll-up would be
    worse: the mapping would silently take one branch and assert the other
    thing. Both are cheap to rule out here.
    """
    clash = set(SCALAR_VERBS) & set(COLLECTION_VERBS)
    if clash:
        raise SystemExit(f"verb name(s) declared both scalar and roll-up: {sorted(clash)}")
    probe = {"in_list": ["a"], "not_in_list": ["a"], "matches": "x"}
    for verb in SCALAR_VERBS:
        value = probe.get(verb, 1)
        matcher_for("verb-vocabulary", verb, value)
        predicate_for("verb-vocabulary", verb, value)
        verb_prose(verb, value)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any generated control is stale; write nothing")
    args = ap.parse_args()
    check_verb_vocabulary()

    version, checks, resource_map, metadata, fixes = load()

    stale, written = [], 0
    for cid in sorted(checks):
        if cid in resource_map:
            if cid not in metadata:
                raise SystemExit(f"{cid}: mapped but has no entry in control_metadata.yml")
            mapping = resource_map[cid]
            if any(v.get("reader") == "singleton" for v in mapping.values()):
                body = render_singleton(cid, version, checks[cid], mapping, metadata[cid], fixes)
            elif any(v.get("reader") == "api" for v in mapping.values()):
                body = render_api(cid, version, checks[cid], mapping, metadata[cid], fixes)
            elif any(v.get("reader") == "stock" for v in mapping.values()):
                body = render_stock(cid, version, checks[cid], mapping, metadata[cid], fixes)
            else:
                body = render(cid, version, checks[cid], mapping, metadata[cid], fixes)
        else:
            body = render_planned(cid, version, checks[cid], metadata.get(cid, {}))
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
        print(f"{len(checks)} generated control(s) are in sync with the data files "
                  f"({len(resource_map)} implemented, {len(checks) - len(resource_map)} planned).")
        return 0

    print(f"rendered {len(checks)} control(s) "
              f"({len(resource_map)} implemented, {len(checks) - len(resource_map)} planned); "
              f"{written} changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
