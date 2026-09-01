"""One InSpec JSON run -> a one-line verdict for the control under test.

Deliberately reports SKIPPED rather than folding it into "0 failed": a
membership control that renders Not Applicable when it should have failed is
the exact defect this harness exists to catch, and a summary that cannot tell
those apart would let it through.
"""
import collections
import json
import sys

control = json.load(sys.stdin)["profiles"][0]["controls"][0]
counts = collections.Counter(r["status"] for r in control["results"])
if counts.get("skipped") and not counts.get("failed") and not counts.get("passed"):
    print("skipped")
else:
    print(" ".join(f"{counts[s]} {s}" for s in ("passed", "failed") if counts.get(s)))
