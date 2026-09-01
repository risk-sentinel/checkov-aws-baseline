# libraries/_checkov_membership.rb, exercised directly. No AWS, no InSpec run.
#
# The reducer is the single point where this profile decides whether a bare
# `vol-0abc` and an `arn:aws:ec2:...:volume/vol-0abc` are the same thing. Get
# that wrong and the control it feeds either fails everything or cannot fail at
# all, and `check` and `json` see neither, because neither evaluates a body.
#
# The real file ends in `::Inspec::Rule.include(CheckovMembership)`, which is
# what puts the helpers in CONTROL scope at exec. Standing that constant up is
# the whole reason for the stub below; including into Object instead just makes
# the helpers callable here at top level.
#
# Run through tests/membership/run.sh, which mounts the repo at /work.
module Inspec; class Rule; def self.include(m); Object.include(m); end; end; end
load "/work/libraries/_checkov_membership.rb"

$fail = 0
def eq(label, got, want)
  ok = got == want
  $fail += 1 unless ok
  puts "#{ok ? 'ok  ' : 'FAIL'} #{label}: got #{got.inspect}#{ok ? '' : " want #{want.inspect}"}"
end

VOL_ARN = "arn:aws:ec2:us-east-1:111122223333:volume/vol-0abc"
CLU_ARN = "arn:aws:rds:us-east-1:111122223333:cluster:prod"
EFS_ARN = "arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-0abc"

# --- key_form reduction -------------------------------------------------
eq "verbatim keeps the string",
   checkov_membership_key({ id: VOL_ARN, region: "us-east-1" }, field: :id, key_form: "verbatim"),
   ["us-east-1", VOL_ARN]
eq "terminal_segment of an ARN with '/'",
   checkov_membership_key({ id: VOL_ARN, region: "us-east-1" }, field: :id, key_form: "terminal_segment"),
   ["us-east-1", "vol-0abc"]
eq "terminal_segment of an ARN with ':'",
   checkov_membership_key({ id: CLU_ARN, region: "us-east-1" }, field: :id, key_form: "terminal_segment"),
   ["us-east-1", "prod"]
eq "terminal_segment of a path",
   checkov_membership_key({ id: "/hostedzone/Z1234", region: "us-east-1" }, field: :id, key_form: "terminal_segment"),
   ["us-east-1", "Z1234"]

# --- unkeyable rows are nil, never a blank that matches another blank ----
eq "nil field yields no key",
   checkov_membership_key({ arn: nil, region: "us-east-1" }, field: :arn, key_form: "verbatim"), nil
eq "missing field yields no key",
   checkov_membership_key({ region: "us-east-1" }, field: :arn, key_form: "verbatim"), nil
eq "blank field yields no key",
   checkov_membership_key({ arn: "   ", region: "us-east-1" }, field: :arn, key_form: "verbatim"), nil
eq "two blank rows do not collide (both nil, both counted)",
   [checkov_membership_key({ arn: "", region: "r" }, field: :arn, key_form: "verbatim"),
    checkov_membership_key({ arn: nil, region: "r" }, field: :arn, key_form: "verbatim")],
   [nil, nil]

# --- an unknown key_form is loud, not silently "verbatim" ---------------
begin
  checkov_membership_key({ id: "x", region: "r" }, field: :id, key_form: "arn_suffix")
  eq "unknown key_form raises", "no raise", "ArgumentError"
rescue ArgumentError => e
  eq "unknown key_form raises", e.class.to_s, "ArgumentError"
end

# --- THE JOIN THIS SHAPE EXISTS FOR: CKV2_AWS_9 -------------------------
left  = [{ id: "vol-0abc", region: "us-east-1" }, { id: "vol-0dead", region: "us-east-1" }]
right = [{ id: VOL_ARN, region: "us-east-1", resource_type: "EBS" },
         { id: CLU_ARN, region: "us-east-1", resource_type: "Aurora" }]

narrowed = checkov_membership_where(right, { resource_type: ["EBS"] })
eq "where narrows to the declared type", narrowed.length, 1
rk = checkov_membership_keys(narrowed, field: :id, key_form: "terminal_segment")
lk = left.map { |r| checkov_membership_key(r, field: :id, key_form: "verbatim") }
eq "the covered volume matches across the ARN/id boundary", rk.key?(lk[0]), true
eq "the uncovered volume does NOT match -- the control can still fail", rk.key?(lk[1]), false

# --- the inversion that would make the control unable to fail ------------
raw = checkov_membership_keys(narrowed, field: :id, key_form: "verbatim")
eq "keying the right side verbatim matches NOTHING (the bug the guard catches)",
   left.map { |r| raw.key?(checkov_membership_key(r, field: :id, key_form: "verbatim")) },
   [false, false]

# --- region pairing ------------------------------------------------------
other = [{ id: VOL_ARN.sub("us-east-1", "us-west-2"), region: "us-west-2", resource_type: "EBS" }]
rk2 = checkov_membership_keys(other, field: :id, key_form: "terminal_segment")
eq "same id in another region does not cover (match_region: true)", rk2.key?(lk[0]), false
rk3 = checkov_membership_keys(other, field: :id, key_form: "terminal_segment", match_region: false)
lk3 = checkov_membership_key(left[0], field: :id, key_form: "verbatim", match_region: false)
eq "match_region: false lets it cover", rk3.key?(lk3), true

# --- CKV2_AWS_8 / _18: verbatim ARN on both sides ------------------------
eq "cluster ARN matches the backup ARN verbatim",
   checkov_membership_keys([{ id: CLU_ARN, region: "us-east-1" }], field: :id, key_form: "verbatim")
     .key?(checkov_membership_key({ arn: CLU_ARN, region: "us-east-1" }, field: :arn, key_form: "verbatim")),
   true
eq "efs ARN matches the backup ARN verbatim",
   checkov_membership_keys([{ id: EFS_ARN, region: "us-east-1" }], field: :id, key_form: "verbatim")
     .key?(checkov_membership_key({ arn: EFS_ARN, region: "us-east-1" }, field: :arn, key_form: "verbatim")),
   true

# --- diagnostics used by the guards --------------------------------------
eq "observed lists what the API really returned",
   checkov_membership_observed(right, :resource_type), ["Aurora", "EBS"]
eq "observed drops blanks rather than printing an empty string",
   checkov_membership_observed([{ resource_type: nil }, { resource_type: "EBS" }], :resource_type), ["EBS"]
eq "sample renders region/key so a region mismatch is visible",
   checkov_membership_sample(rk.keys), ["us-east-1/vol-0abc"]
eq "sample caps at three",
   checkov_membership_sample((1..9).map { |i| ["r", "k#{i}"] }), ["r/k1", "r/k2", "r/k3"]
eq "where with no filters is a no-op, not an empty set",
   checkov_membership_where(right, {}).length, 2
eq "where compares as strings, so a boolean-ish value still matches",
   checkov_membership_where([{ f: true }], { f: ["true"] }).length, 1

puts($fail.zero? ? "\nALL PASS" : "\n#{$fail} FAILURE(S)")
exit($fail.zero? ? 0 : 1)
