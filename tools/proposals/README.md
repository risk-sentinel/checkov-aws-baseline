# Proposals — drafted, not merged

Research output from parallel drafting passes over the Checkov catalogue. Each
file proposes mappings, API specs, compliance anchors and remediation for a slice
of the checks, plus a per-check reason for everything it could NOT map.

**Nothing here is live.** A proposal becomes real only when it is merged into
`resource_map*.yml` / `api_specs.yml` / `control_metadata*.yml` / `fix_examples.yml`,
rendered, linted and exec-validated. Several proposals in these files were merged
and then REMOVED after a live run proved them broken — the removals are recorded
at the top of `tools/resource_map_derived.yml`.

| file | slice | outcome |
|---|---|---|
| `batch1-4.yml` | the 264 non-graph checks, split by service | 55 merged, 2 later removed at exec |
| `specs.yml` | value/negative checks with no stock reader | 8 proposed |
| `parentchild.yml` | checks whose list call needs a parent id | 38 proposed; reader BUILT, 27 expressible, 3 merged |
| `graph.yml` | the 74 relationship checks | 40 single-field / 19 join / 15 unreachable |
| `custom.yml` | the 104 custom-logic checks | 6 ready, 88 need a named verb, 10 unreachable |

## Why these are kept

They are the expensive half. Each entry records which AWS API field answers a
check, confirmed against botocore rather than remembered, plus the Terraform
argument it diverges from. Re-deriving that is hours of work; merging one entry
is minutes.

They also record judgements worth preserving: checks that are **vacuous when
assessed deployed** (a field AWS always populates, so the control can never
fail), and several places where Checkov's own logic is wrong — `CKV_AWS_334`
reads a key called `privilege` where the API member is `privileged`, so it can
never fire.

## `parentchild.yml` — what the reader now supports

`libraries/aws_api_assets.rb` reads a spec that declares `parent:` in two steps.
27 of the 38 drafted mappings are expressible with it as built; 3 are merged
(`CKV_AWS_39`, `CKV_AWS_73`, `CKV_AWS_238`) and the other 24 are a data pass.

The remaining 11 are blocked on extensions the proposal's `schema_gaps` names,
none of which are implemented and all of which `tools/lint_api_specs.py` now
REFUSES rather than ignoring — copying one out of the proposal fails the lint
instead of producing a spec that quietly does nothing:

| blocked | needs |
|---|---|
| CKV_AWS_53/54/55/56, CKV_AWS_144 | `absent_errors:` **and** per-parent region routing (S3 answers 301 off-region) |
| CKV_AWS_78, 311, 316 | `batch:` — CodeBuild `BatchGetProjects` takes a LIST |
| CKV_AWS_223 | `args:` + `batch:` — ECS `DescribeClusters` |
| CKV2_AWS_38 | `absent_errors:` — private zones reject `GetDNSSEC` |
| CKV_AWS_335 | a bound on parent count; ECS task definition REVISIONS are unbounded |

`absent_errors:` is the one to think about before building: a row of nils is
removed again by a value check's nil filter, so it needs a verb rule with it or
it re-creates the failure it was added to fix.

## Reading order for whoever picks this up

`custom.yml`'s `needs_verb` section is ranked by how many checks each verb
unlocks — that is the highest-leverage list in this directory. `graph.yml`'s
`shape_notes` gives a build order for the join shape.
