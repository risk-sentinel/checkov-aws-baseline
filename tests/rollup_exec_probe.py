#!/usr/bin/env python3
"""Execute the generated collection roll-up against stubbed rows.

    python3 tests/rollup_exec_probe.py

Why this exists
---------------
`cinc-auditor check` and `json` LOAD a control file; they never evaluate a
control body. Every defect this profile has shipped in a roll-up was invisible to
both — the worst of them a bare `module CheckovCollection`, which is defined
under InSpec's anonymous library eval context and raises

    uninitialized constant #<Class:#<Inspec::ControlEvalContext>>::CheckovCollection

on the first assertion, at exec, in an account, after check and json both passed.
There are no AWS credentials in this repo's CI, so the only way to evaluate a
body is to keep the reader out of it.

So this lifts the assertion machinery out of controls/CKV_AWS_24.rb VERBATIM —
the `element_conditions` literal and everything from the field guard to the
`satisfy` block — substitutes literal rows for `aws_api_assets`, and runs it
under `-t local://` in the auditor image. What it proves is everything between
the rows and the verdict: constant resolution from inside a deferred block, the
file-scope conditions closing over into `satisfy`, `when_absent`, the two-
statement `impact`, and the field guard firing on a field the API did not return.
What it cannot prove is the reader — that needs an account.

Lifted rather than copied, so it cannot drift from what the generator emits. If
the shape of the generated control changes, this fails to find its landmarks and
says so; it does not quietly test an older shape.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = "risksentinel/sparc-auditor:v1.2.0"
SOURCE = ROOT / "controls" / "CKV_AWS_24.rb"

# id -> (rows literal, expected control status). "failed" on a compliant-looking
# row is the point of `nofield`: the roll-up passes vacuously and the guard does
# not, which is the whole reason the guard is rendered.
CASES = {
    "good": ("""[{ id: 'sg-good', account_id: '1', region: 'us-east-1',
       ip_permissions: [{ ip_protocol: 'tcp', from_port: 22, to_port: 22,
                          ip_ranges: [{ cidr_ip: '10.0.0.0/8' }] }] }]""", "passed"),
    "open": ("""[{ id: 'sg-open', account_id: '1', region: 'us-east-1',
       ip_permissions: [{ ip_protocol: 'tcp', from_port: 22, to_port: 22,
                          ip_ranges: [{ cidr_ip: '0.0.0.0/0' }] }] }]""", "failed"),
    "v6": ("""[{ id: 'sg-v6', account_id: '1', region: 'us-east-1',
       ip_permissions: [{ ip_protocol: 'tcp', from_port: 20, to_port: 25, ip_ranges: [],
                          ipv_6_ranges: [{ cidr_ipv_6: '::/0' }] }] }]""", "failed"),
    # IpProtocol "-1" carries no FromPort or ToPort at all: `when_absent: true`
    # is what makes AWS's omission mean "every port" instead of "not assessed".
    "allproto": ("""[{ id: 'sg-any', account_id: '1', region: 'us-east-1',
       ip_permissions: [{ ip_protocol: '-1', ip_ranges: [{ cidr_ip: '0.0.0.0/0' }] }] }]""", "failed"),
    # A group with no ingress rules is COMPLIANT, and must not be failed for it.
    "empty": ("""[{ id: 'sg-none', account_id: '1', region: 'us-east-1',
       ip_permissions: [] }]""", "passed"),
    # The field the API never returned: vacuously clean roll-up, loud guard.
    "nofield": ("""[{ id: 'sg-nil', account_id: '1', region: 'us-east-1' }]""", "failed"),
}


def landmark(text, start, end, what):
    try:
        a = text.index(start)
        b = text.index(end, a)
    except ValueError:
        sys.exit(f"::error::could not find {what} in {SOURCE.name}. The generated shape "
                 f"changed; update tests/rollup_exec_probe.py rather than skipping it — "
                 f"an unrun probe is the silence it exists to prevent.")
    return text[a:b + len(end)]


def main():
    src = SOURCE.read_text()
    conditions = landmark(src, "element_conditions = [", "].freeze", "the element_conditions literal")
    body = landmark(src, "  # none_of is vacuously TRUE", "  end\nend\n", "the assertion body")
    body = body[:body.rindex("end\nend\n") + len("end\n")]

    parts = [conditions, ""]
    for case, (rows, _) in CASES.items():
        scoped = re.sub(r"\bin_scope\b", f"in_scope_{case}", body)
        scoped = scoped.replace("exposing", f"exposing_{case}")
        scoped = scoped.replace("aws_security_group ip_permissions",
                                f"[{case}] aws_security_group ip_permissions")
        scoped = scoped.replace('describe "aws_security_group #{asset[:id]}',
                                f'describe "[{case}] aws_security_group #{{asset[:id]}}')
        parts.append(f"""control 'probe_{case}' do
  title 'collection roll-up probe: {case}'
  unreadable = []
  unusable   = 0
  in_scope_{case} = {rows}
{scoped}
end
""")

    work = pathlib.Path(tempfile.mkdtemp(prefix="rollup-probe-"))
    try:
        (work / "controls").mkdir()
        (work / "libraries").mkdir()
        shutil.copy(ROOT / "libraries" / "_checkov_collection.rb", work / "libraries")
        (work / "inspec.yml").write_text(
            "name: rollup-exec-probe\ntitle: collection roll-up exec probe\n"
            "version: 0.0.1\nsupports:\n  - platform: os\n")
        (work / "controls" / "probe.rb").write_text("\n".join(parts))

        run = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/work", "-w", "/work", IMAGE,
             "exec", ".", "-t", "local://", "--reporter", "json", "--no-distinct-exit"],
            capture_output=True, text=True)
        try:
            report = json.loads(run.stdout)
        except json.JSONDecodeError:
            sys.exit(f"::error::the probe profile did not run.\n{run.stdout[-2000:]}\n{run.stderr[-2000:]}")

        results = {}
        for control in report["profiles"][0]["controls"]:
            # An exception raised inside an example is reported as status
            # "failed" like any other, so collapsing the two would let a control
            # that BLEW UP satisfy a `want failed` case -- and four of the six
            # cases here want failed. Planting `from_port: 'x'` (which makes
            # `'x' <= 22` raise) proved that: the probe printed ok on a control
            # that never evaluated the roll-up at all. The reporter distinguishes
            # them by an `exception`/`backtrace` pair on the result, so an error
            # is classified as one and matches no expectation.
            errored = any(r.get("exception") or r.get("backtrace") for r in control["results"])
            statuses = {r["status"] for r in control["results"]}
            results[control["id"]] = ("errored" if errored
                                      else "failed" if "failed" in statuses else "passed")

        bad = []
        for case, (_, want) in CASES.items():
            got = results.get(f"probe_{case}", "MISSING")
            print(f"  {case:<9} want {want:<6} got {got:<8} "
                  f"{'ok' if got == want else 'FAIL'}")
            if got != want:
                bad.append(case)
        if bad:
            sys.exit(f"::error::the generated roll-up does not behave as documented: "
                     f"{', '.join(bad)}. Nothing static sees this — check and json both pass.")
        print("OK — the generated collection roll-up evaluates as documented under exec.")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
