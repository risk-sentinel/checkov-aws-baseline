# Proving the `membership` reader shape

    bash tests/membership/run.sh

No AWS credentials. Needs Docker and the auditor image
(`SPARC_AUDITOR_IMAGE` overrides the pinned default).

## Why this directory exists at all

The proof obligations for a generated control in this profile are
`render_controls.py --check`, `ruby -c`, the five linters, and
`cinc-auditor check` + `json`. Between them they establish that the data is
consistent, that the Ruby parses, and that the profile loads.

None of them evaluates a control body. For most reader shapes that is a
tolerable gap, because a mistake in a one-asset assertion shows up the first
time anyone reads the results. For a membership join it is not, and the reason
is specific:

> The two sides speak different identifier spaces. `ec2 DescribeVolumes`
> returns `vol-0abc` and `Aws::EC2::Types::Volume` has no ARN member at all;
> AWS Backup returns `arn:aws:ec2:us-east-1:1234:volume/vol-0abc`.

Get the reduction wrong in one direction and **nothing** matches: every asset
reports uncovered, which renders as a 100% finding that is indistinguishable
from a real one. Get it wrong in the other direction and **everything**
matches: a control that cannot fail, which this profile treats as worse than
having no control. Both are valid Ruby. Both pass `check` and `json`. Neither
is visible to a reader of the results.

So the shape is proved the only way it can be proved without an account: by
running the real generated control against fabricated rows.

## What runs

**`reducer_test.rb`** — `libraries/_checkov_membership.rb` directly, with a
two-line stand-in for `::Inspec::Rule`. It pins the key reduction (`verbatim`,
`terminal_segment` over both `/` and `:`), that an unkeyable row reduces to
`nil` rather than to a blank key two rows could share, that an unknown
`key_form` raises instead of quietly defaulting, that region pairing rejects a
same-id match from another region, and — the one that matters — that the
CKV2_AWS_9 keying matches a covered volume across the id/ARN boundary **and
still leaves an uncovered one unmatched**.

**`run.sh` scenarios** — the generated `controls/CKV2_AWS_9.rb`, unmodified,
against `harness/libraries/aws_api_assets.rb`: a stand-in with the same surface
as the real reader (`assets`, `assets(exempt:)`, `unreadable_regions`) that
returns rows chosen by `$SCENARIO`.

| scenario | fabricated state | must produce |
|---|---|---|
| `mixed` | one covered volume, one not | 1 passed 1 failed |
| `empty_right` | volumes exist, AWS Backup protects nothing | 2 failed — **never Not Applicable** |
| `broken_keys` | right side keyed in another region | 3 failed, incl. the key-space guard |
| `bad_filter` | `resource_type` spelled `EBSVolume` | 3 failed, incl. the filter guard, printing what the API really returned |
| `unkeyable` | a volume with a blank id | 1 failed — unjudgeable, not compliant |
| `no_left` | no volumes at all | skipped — the *only* Not Applicable |
| `unread_right` | AWS Backup returns AccessDenied | 1 failed — an unread side is not an empty one |

`empty_right` and `no_left` are the pair worth staring at: they are the
difference between "nothing is protected", which is the finding, and "there is
nothing here to protect", which is not. A join that renders the first as the
second reports a catastrophe as a clean scan.

The control and the reducer are copied out of the repo at run time, never
vendored into `harness/`, so this cannot pass against a stale copy.

## Not wired into CI

`.github/workflows/profile-lint.yml` sweeps `controls/` and `libraries/` only,
so nothing here runs on a push. Adding it is a workflow change and needs the
owner's approval; until then it is a gate anyone touching
`libraries/_checkov_membership.rb`, `render_membership`, or a `membership`
mapping should run by hand.

## Adding a scenario

Add a branch to the `case` in `harness/libraries/aws_api_assets.rb` and an
`EXPECT_<name>` line plus the name in the loop in `run.sh`. Keep the expected
verdict written out as a literal: a harness that computes what it expects from
the same code it is testing proves nothing.
