# checkov-aws-baseline

InSpec profile that asserts Checkov's Terraform AWS checks against **deployed
assets**.

Checkov answers *"would this Terraform create a compliant resource?"*. This
profile answers *"is the resource that actually exists still compliant with what
that check asserted?"* — same intent, different evidence. The proposed Terraform
fix is the specification; the deployed asset is what gets assessed.

That difference is not always a downgrade. `CKV_AWS_8` reads the block devices
declared in HCL; here it reads `DescribeVolumes`, so a volume attached later, by
hand, outside Terraform is assessed too — and that is the volume most likely to
be unencrypted.

## Status

Wireframe. The catalogue is complete, the control set is not.

| | |
|---|---|
| Checkov release pinned | **3.3.16** |
| AWS checks in the catalogue | **362** over 194 resource types |
| checks applying to 2+ resource types | 60 |
| controls written | **6** (the `aws_instance` tranche) |

`tools/lint_catalog_drift.py` prints that coverage on every CI run, so the gap
is stated rather than implied.

## Run it

```bash
docker run --rm -v "$PWD:/work" -w /work \
  risksentinel/sparc-auditor:v0.5.0 vendor . --overwrite

docker run --rm -v "$PWD:/work" -w /work \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  risksentinel/sparc-auditor:v0.5.0 \
  exec . -t aws:// --input-file inputs.yml --reporter cli json:hdf.json
```

Nothing in `inputs.yml` is required for a first run: the defaults enumerate every
enabled region in the Commercial partition and exempt nothing.

## How a control is built

One file per Checkov rule, and the rule id is the identity in all three places:

| where | value |
|---|---|
| file name | `controls/CKV_AWS_79.rb` |
| control id | `control 'CKV_AWS_79' do` |
| tag | `tag checkov_id: 'CKV_AWS_79'` |

`tools/lint_catalog_drift.py` asserts the three agree, and that the id is one the
pinned Checkov release still defines.

A check declares the resource types it applies to, and 60 of the 362 declare more
than one — so a control asserts against **every deployed asset of every type it
declares**. Several assertions per control is the normal shape here, not a smell.
The inspected argument can differ per type: `CKV_AWS_88` reads
`associate_public_ip_address` on an instance and
`network_interfaces[0].associate_public_ip_address` on a launch template, which
is why `tools/resource_map.yml` is keyed by *(check, resource type)*.

## Layout

```
inspec.yml                    name carries the pinned Checkov release
inputs.yml                    reference inputs — clone-to-results
controls/inventory.rb         what the scan found, and where it could not look
controls/CKV_AWS_*.rb         one per rule
libraries/aws_compute_assets.rb   deployed assets + the attributes checks assert on
tools/build_catalog.py        derive the catalogue from a pinned Checkov
tools/checkov_catalog.yml     the committed result — 362 checks
tools/resource_map.yml        (check, tf type) -> asset field + how it is judged
tools/lint_catalog_drift.py   controls <-> catalogue, both directions
tools/lint_control_tags.py    fleet tag gate
tools/lint_resource_scope.py  fleet scope gate
```

## Refreshing the catalogue

Checkov is **not** a runtime dependency and is not vendored: it is large and
hard-pins `boto3`, which conflicts with the AWS CLI in a shared environment. Run
the generator from an isolated environment holding exactly the pinned release:

```bash
python3 -m venv .venv-checkov
.venv-checkov/bin/pip install checkov==3.3.16
.venv-checkov/bin/python tools/build_catalog.py --write
```

Then review the diff. A release that adds a check shows up as a coverage drop
with no control count change — `3.2.521 → 3.3.16` added exactly one
(`CKV_AWS_393`), which is the shape this gate exists to catch.

## What Checkov does not ship

- **No guideline URLs.** 0 of 362 checks carry one in the OSS distribution; the
  field belongs to the commercial platform. The link back to the provider
  documentation is derived from the inspected argument path instead.
- **No severity.** Every control tags `severity_source: 'assessed'`, because
  claiming a severity from Checkov would attribute a value it never published.
- **No NIST mapping.** Anchors are assigned during catalogue review and carried
  as `nist` / `nist_r4` / `cci` / `ksi`, the same tag structure as the rest of
  the fleet.
