#!/usr/bin/env bash
# Executable proof for the `membership` reader shape. No AWS credentials needed.
#
# WHY THIS EXISTS
# ---------------
# `cinc-auditor check` and `cinc-auditor json` load a profile; neither evaluates
# a control body. For every other reader in this profile that gap is tolerable,
# because a mistake shows up as an obviously broken assertion. For a membership
# join it is not: the two sides speak different identifier spaces, and getting
# the reduction wrong produces a control in which either NOTHING matches (every
# asset fails — a 100% finding indistinguishable from a real one) or EVERYTHING
# matches (a control that cannot fail, which this profile treats as worse than
# having no control at all). Both are perfectly valid Ruby and both pass check
# and json.
#
# So the shape is proved the only way it can be: by running the REAL generated
# control against fabricated rows, through a stand-in for aws_api_assets with
# the same surface. The control and the reducer are copied from the repo at run
# time, never vendored here, so this cannot pass against a stale copy.
#
#   bash tests/membership/run.sh
#
# Exit 0 means: the reducer behaves as documented, and CKV2_AWS_9 passes a
# covered volume, FAILS an uncovered one, fails every volume when nothing is
# backed up, and is Not Applicable ONLY when there are no volumes.
set -euo pipefail

IMAGE="${SPARC_AUDITOR_IMAGE:-risksentinel/sparc-auditor:v1.2.0}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The control under test is the GENERATED one, taken live.
cp -R "$REPO/tests/membership/harness/." "$WORK/"
# The harness ships libraries/ but no controls/, and the copies below name
# them as destination DIRECTORIES -- without this, cp reports "Not a
# directory" and the suite fails before it runs a single assertion.
mkdir -p "$WORK/controls" "$WORK/libraries"
cp "$REPO/libraries/_checkov_membership.rb" "$WORK/libraries/"
cp "$REPO/controls/CKV2_AWS_9.rb"           "$WORK/controls/"

echo "── reducer unit tests ─────────────────────────────────────────────"
docker run --rm -v "$REPO:/work" -v "$REPO/tests/membership:/t" \
  --entrypoint ruby "$IMAGE" /t/reducer_test.rb

echo
echo "── the generated CKV2_AWS_9 body, against fabricated rows ─────────"
# scenario                     what the run must produce
EXPECT_mixed="1 passed 1 failed"
EXPECT_empty_right="2 failed"
EXPECT_broken_keys="3 failed"
EXPECT_bad_filter="3 failed"
EXPECT_unkeyable="1 failed"
EXPECT_no_left="skipped"
EXPECT_unread_right="1 failed"

fail=0
for s in mixed empty_right broken_keys bad_filter unkeyable no_left unread_right; do
  # `inspec exec` exits 100 when a control fails, and MOST of these scenarios are
  # supposed to fail — that is the point. So the exit code is deliberately
  # discarded and the verdict is read from the JSON: under `set -e` a bare
  # pipeline here would abort the harness on its own successful cases.
  json="$(docker run --rm -e "SCENARIO=$s" -v "$WORK:/prof" -w /prof "$IMAGE" \
            exec . -t local:// --reporter json 2>/dev/null || true)"
  out="$(printf '%s' "$json" | python3 "$REPO/tests/membership/summarise.py")"
  want_var="EXPECT_$s"; want="${!want_var}"
  if [ "$out" = "$want" ]; then
    printf 'ok   %-14s %s\n' "$s" "$out"
  else
    printf 'FAIL %-14s got "%s" want "%s"\n' "$s" "$out" "$want"; fail=1
  fi
done

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
