# checkov-aws-baseline

**Checkov's Terraform AWS checks, asserted against deployed assets.**

Checkov answers *"would this Terraform create a compliant resource?"*. This
profile answers *"is the resource that actually exists still compliant with what
that check asserted?"*

## Why this exists

A passing Checkov scan is a statement about code, at the moment it was scanned.
Between that scan and today, the plan may not have been applied, someone may have
changed the resource in the console, a volume may have been attached by hand, or
the module may have been overridden by a caller Checkov never rendered. Each of
those leaves the IaC scan green and the estate non-compliant.

So the proposed Terraform fix is treated as the **specification**, and the
deployed asset is what gets **assessed**.

Sometimes that is strictly stronger. `CKV_AWS_8` reads the block devices declared
in HCL; here it reads `DescribeVolumes`, so a volume attached later, outside
Terraform, is assessed too — and that is the volume most likely to be
unencrypted. Where a control covers more than its Checkov original, the control
says so in its own description.

## Quick start

```bash
# 1. Pull the profile's dependencies (inspec-aws).
docker run --rm -v "$PWD:/work" -w /work \
  risksentinel/sparc-auditor:v0.5.0 vendor . --overwrite

# 2. Run it. Nothing in inputs.yml is required for a first run: the defaults
#    enumerate every enabled region in the Commercial partition.
docker run --rm -v "$PWD:/work" -w /work \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  risksentinel/sparc-auditor:v0.5.0 \
  exec . -t aws:// --input-file inputs.yml --reporter cli json:hdf.json
```

Read the results with any HDF viewer, or ship `hdf.json` to your evidence store.

**Scoping the run** — edit `inputs.yml`:

| input | what it does |
|---|---|
| `scan_regions` | regions to enumerate; empty means every enabled region |
| `aws_partition` | `aws` or `aws-us-gov` |
| `exempt_assets` | documented exceptions, as `{CHECK_ID: [asset-id]}` — an exception is data with an owner, not an edited control |

A control for a service the boundary does not use renders **Not Applicable** with
a stated reason. A region that could not be read is reported as a failure, not as
emptiness — "we did not look" and "there is nothing there" are different answers.

## How this profile is built

Controls are **generated**, not hand-written. There are 362 AWS checks; hand
authoring them means 362 chances to drift from the rule each one claims to
implement, and no way to tell which ones did.

```
     checkov 3.3.16 (pinned, isolated venv)
              │  tools/build_catalog.py
              ▼
     tools/checkov_catalog.yml ─── derived: 362 checks, per-type inspected keys
              │
              ├── tools/resource_map.yml ──── authored: which deployed field answers it
              ├── tools/control_metadata.yml  authored: NIST/CCI/KSI, severity, rationale
              └── tools/fix_examples.yml ──── authored: Terraform + CLI, per resource type
                          │
                          │  tools/render_controls.py
                          ▼
                  controls/CKV_AWS_*.rb   (committed, and drift-checked in CI)
```

| file | source | what it contributes |
|---|---|---|
| `checkov_catalog.yml` | **derived** from Checkov | check name, categories, `supported_resources`, inspected key and docs URL **per resource type**, expected/forbidden values, and the check's kind |
| `resource_map.yml` | authored | `(check, tf type)` → which `aws_compute_assets` field answers it and how it is judged |
| `control_metadata.yml` | authored | NIST Rev 5 + Rev 4 anchors, CCI, KSI, severity, rationale — and `stronger` where the deployed assertion exceeds the IaC one |
| `fix_examples.yml` | authored | a complete Terraform block per resource type, plus the out-of-band CLI path and any "this cannot be fixed in place" caveat |

Everything derived is regenerable; everything authored is a judgement a reviewer
can argue with. That split is the point: the review surface is four data files,
not 362 Ruby files.

### Remediation is Terraform-first

An organisation that manages its estate through Terraform cannot act on an
`aws ec2 modify-...` command — running it either fails a policy gate or is
reverted by the next apply. So every control carries a **complete, copy-pasteable
Terraform block for each resource type it applies to**, and the CLI is the
secondary path: for an estate not under Terraform, or for closing an exposure
before the next apply.

Where there is no in-place fix, the control says so. `CKV_AWS_88` on a running
instance cannot be remediated at all without replacing the instance, and pretending
otherwise wastes the reader's time.

### One check, many assets

A Checkov check declares the resource types it applies to, and **60 of the 362
declare more than one**. A control therefore asserts against every deployed asset
of every type it declares — several `describe` blocks per control is the normal
shape here.

The inspected argument can differ per type. `CKV_AWS_88` reads
`associate_public_ip_address` on an instance and
`network_interfaces[0].associate_public_ip_address` on a launch template, which is
why both the catalogue and the resource map are keyed by *(check, resource type)*.
Keyed by check alone, a generated control would inspect the wrong field for one of
its types and still look correct.

### The rule id is the identity

| where | value |
|---|---|
| file name | `controls/CKV_AWS_79.rb` |
| control id | `control 'CKV_AWS_79' do` |
| tag | `tag checkov_id: 'CKV_AWS_79'` |

`tools/lint_catalog_drift.py` asserts the three agree, and that the id is one the
pinned Checkov release still defines.

## Partitions

Targets **AWS Commercial** (`aws`) and **AWS GovCloud US, non-DoD**
(`aws-us-gov`), selected by the `aws_partition` input.

Partitions are separate AWS universes — separate account namespaces, endpoints,
service availability and ARN prefixes. Two consequences here:

- a check whose service does not exist in the partition renders **Not
  Applicable** with a stated reason, never a silent pass;
- asset ARNs are built with the partition prefix, so an exemption written
  against `arn:aws:` will not match a GovCloud asset. The profile derives the
  prefix from the region rather than trusting the input, because a resource
  cannot read inputs and the region already carries the answer.

## Status

| | |
|---|---|
| Checkov release pinned | **3.3.16** |
| AWS checks in the catalogue | **362** over 194 resource types |
| checks applying to 2+ resource types | 60 |
| controls written | **6** — the `aws_instance` tranche |

CI prints that coverage on every run, so "we cover Checkov" is never claimable
without a number beside it.

## Adding a check

1. Add its `(check, tf type)` entry to `resource_map.yml`, naming the
   `aws_compute_assets` field that answers it — adding the field to the library
   first if it does not exist.
2. Add anchors, severity and rationale to `control_metadata.yml`.
3. Add a Terraform block per resource type to `fix_examples.yml`.
4. `python3 tools/render_controls.py` and commit the generated control.

If a check has **no deployed analogue** — provider version pinning, lifecycle
`prevent_destroy`, backend configuration — it still gets an entry, declared as
inapplicable with the reason. A missing control and a control that cannot apply
look identical in a coverage count, and only one of them is honest.

## Refreshing the catalogue

Checkov is **not** a runtime dependency and is not vendored: it is large and
hard-pins `boto3`, which conflicts with the AWS CLI in a shared environment.

```bash
python3 -m venv .venv-checkov
.venv-checkov/bin/pip install checkov==3.3.16
.venv-checkov/bin/python tools/build_catalog.py --write
```

Review the diff, then bump `checkov_version` in `inspec.yml` and re-render. A
release that adds a check shows up as a coverage drop with no change in control
count — `3.2.521 → 3.3.16` added exactly one (`CKV_AWS_393`), which is the shape
the drift gate exists to catch.

## What Checkov does not ship

- **No guideline URLs.** 0 of 362 checks carry one in the OSS distribution; the
  field belongs to the commercial platform. The link to the provider docs is
  derived from the inspected argument path instead.
- **No severity.** Every control tags `severity_source: 'assessed'` — claiming a
  severity from Checkov would attribute a value it never published.
- **No NIST mapping.** Anchors are assigned at catalogue review and carried as
  `nist` / `nist_r4` / `cci` / `ksi`, the same tag structure as the rest of the
  fleet.

## Layout

```
inspec.yml                        name carries the pinned Checkov release
inputs.yml                        reference inputs — clone-to-results
controls/inventory.rb             what the scan found, and where it could not look
controls/CKV_AWS_*.rb             generated — one per rule
libraries/aws_compute_assets.rb   deployed assets + the fields checks assert on
tools/build_catalog.py            derive the catalogue from a pinned Checkov
tools/render_controls.py          render controls from the data files (--check for drift)
tools/checkov_catalog.yml         derived
tools/resource_map.yml            authored
tools/control_metadata.yml        authored
tools/fix_examples.yml            authored
tools/lint_catalog_drift.py       controls <-> catalogue, both directions
tools/lint_control_tags.py        fleet tag gate
tools/lint_resource_scope.py      fleet scope gate
```
