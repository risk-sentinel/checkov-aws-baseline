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
| `parentchild.yml` | checks whose list call needs a parent id | 38 proposed, needs a two-step reader |
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

## Reading order for whoever picks this up

`custom.yml`'s `needs_verb` section is ranked by how many checks each verb
unlocks — that is the highest-leverage list in this directory. `graph.yml`'s
`shape_notes` gives a build order for the join shape.
