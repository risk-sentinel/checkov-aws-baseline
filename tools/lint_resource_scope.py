#!/usr/bin/env python3
"""Fail on InSpec resource calls made in a `describe` BODY.

A describe body is an RSpec example GROUP, not an example. Calling a resource
there raises at exec time:

    RSpec::Core::ExampleGroup::WrongScopeError
    `aws_ecr_repository` is not available on an example group

Neither `cinc-auditor check` nor `json` evaluates control bodies, so both pass
on the broken code. This shipped in v0.1.4 and broke the consumer's exec leg.

LEGAL, and must not be flagged:
    describe aws_ecr_repository(name: n) do   # resource is an ARGUMENT
    subject { aws_ecr_repository(name: n) }   # deferred into an example
    it { ... }  /  before  /  let

ILLEGAL:
    describe 'x' do
      aws_ecr_repository(name: n).something   # bare call in the group body
    end

Implementation note: a naive depth counter is wrong. Decrementing on every
`end` lets the `end` of an inner `it ... do` block close the describe frame,
after which the rest of the body goes unchecked — that mistake made the first
version of this linter pass the very code it was written to catch. A stack is
required so each `end` pops the frame it actually belongs to.

SECOND RULE — a control-scope HELPER called inside a deferred block.

The mirror image of the first, and it caught nothing until it existed:

    describe 'EBS volumes with encryption disabled' do
      subject { aws_ebs_volumes_multi_region(regions: compute_scan_regions)... }

    undefined local variable or method 'compute_scan_regions'
      for #<RSpec::ExampleGroups::EBSVolumesWithEncryptionDisabled>

`subject { }` is deferred into the example, which is exactly why calling a
RESOURCE there is legal. A helper is different: helpers reach controls through
`::Inspec::Rule.include(SomeModule)`, so they exist on the control, and the
example is not the control. Deferring the call moves it out of the scope that
has the method.

The helper names are not hard-coded. They are read from `libraries/`: every
module passed to `::Inspec::Rule.include(...)`, and every public method it
defines above `private`. So a new helper is covered the moment it is included,
and a private one — which controls cannot call anyway — is not.

The same call is LEGAL at control scope, which is where the working call sites
put it:

    describe aws_ecs_task_sets(regions: compute_scan_regions) do   # argument
    inv = aws_lightsail_inventory(regions: compute_scan_regions)   # local

Both defects shipped in a tagged release and were invisible to `check` and
`json`, which load control files without evaluating a single control body.
"""
import re
import sys
from pathlib import Path

RESOURCE = re.compile(r"\baws_[a-z0-9_]+\(")
# A block opener: a trailing `do` (with optional |args|), or a keyword that
# opens a block needing `end`. Anchored at line start so a MODIFIER form
# (`impact 0.0 if repos.empty?`) does not push a frame.
# The optional block-args group absorbs its own leading whitespace, so there
# are never two adjacent variable-length matchers to backtrack between. `[ \t]`
# rather than `\s` because this is matched per-line.
DO_BLOCK = re.compile(r"\bdo\b(?:[ \t]*\|[^|]*\|)?[ \t]*$")
KEYWORD_BLOCK = re.compile(r"^(if|unless|case|begin|def|class|module|while|until)\b")
END = re.compile(r"^end\b")
DESCRIBE = re.compile(r"^(describe|context)\b")
DEFERRED = re.compile(r"^(it|its|subject|before|after|let|let!|specify|example)\b")

DESCRIBE_FRAME = "describe"
DEFERRED_FRAME = "deferred"
OTHER_FRAME = "other"


RULE_INCLUDE = re.compile(r"::?Inspec::Rule\.include\(\s*([A-Z]\w*)")
MODULE_DEF = re.compile(r"^module\s+([A-Z]\w*)\s*$", re.M)
DEF_LINE = re.compile(r"^\s+def\s+([a-z_][a-z0-9_]*[?!]?)", re.M)
PRIVATE_LINE = re.compile(r"^\s+private\s*$", re.M)


def control_scope_helpers(roots):
    """Every method a control can call because a module was included into Rule.

    Only the public ones: a `private` method is unreachable from a control body
    in the first place, so flagging it would be noise. Read from the source
    rather than listed here, so this does not need editing when a helper is
    added.
    """
    names = set()
    for root in roots:
        for lib in sorted(Path(root).rglob("*.rb")):
            text = lib.read_text()
            included = set(RULE_INCLUDE.findall(text))
            if not included:
                continue
            for m in MODULE_DEF.finditer(text):
                if m.group(1) not in included:
                    continue
                body = text[m.end():]
                end = re.search(r"^end\s*$", body, re.M)
                body = body[:end.start()] if end else body
                cut = PRIVATE_LINE.search(body)
                if cut:
                    body = body[:cut.start()]
                names.update(DEF_LINE.findall(body))
    return names


def helper_calls(line, helpers):
    """Helper names invoked on this line, ignoring definitions and receivers."""
    hits = []
    for name in helpers:
        if re.search(rf"(?<![.\w:]){re.escape(name)}\b", line) and not re.match(
            rf"\s*def\s+{re.escape(name)}\b", line
        ):
            hits.append(name)
    return sorted(hits)


def _classify(line: str) -> str:
    """Which kind of frame this line would open, if it opens one."""
    if DESCRIBE.match(line):
        return DESCRIBE_FRAME
    if DEFERRED.match(line):
        return DEFERRED_FRAME
    return OTHER_FRAME


def _opens_block(line: str) -> bool:
    return bool(DO_BLOCK.search(line)) or bool(KEYWORD_BLOCK.match(line))


def _in_describe_body(stack) -> bool:
    """True when the innermost enclosing example group is a describe.

    A deferred frame (it/subject/let) between here and the describe means the
    code runs inside an EXAMPLE, where resources are available.
    """
    for frame in reversed(stack):
        if frame == DEFERRED_FRAME:
            return False
        if frame == DESCRIBE_FRAME:
            return True
    return False


def _in_deferred(stack) -> bool:
    """True when this line runs inside an EXAMPLE rather than on the control.

    Any deferred frame anywhere in the stack is enough: once execution is inside
    an `it`/`subject`/`let`, a nested `if` or `each` is still the example.
    """
    return DEFERRED_FRAME in stack


def _is_violation(line: str, kind: str, stack) -> bool:
    # A resource on the `describe ... do` line is an ARGUMENT — legal.
    # A resource on an it/subject/let line is deferred — legal.
    return kind == OTHER_FRAME and _in_describe_body(stack) and bool(RESOURCE.search(line))


def violations(path: Path, helpers=frozenset()):
    """(lineno, line, kind) for each violation; kind is 'resource' or 'helper'."""
    stack = []
    out = []

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        kind = _classify(line)
        if _is_violation(line, kind, stack):
            out.append((lineno, line, "resource"))

        # A deferred ONE-LINER never opens a frame — `subject { ... }` closes on
        # its own line — so it has to be judged here rather than by the stack.
        deferred_here = kind == DEFERRED_FRAME and "{" in line
        if helpers and (deferred_here or _in_deferred(stack)):
            for name in helper_calls(line, helpers):
                out.append((lineno, f"{line}   [helper: {name}]", "helper"))

        if END.match(line) and stack:
            stack.pop()
        elif _opens_block(line):
            stack.append(kind)

    return out


def main(argv):
    targets = []
    for root in argv[1:] or ["controls", "libraries"]:
        targets.extend(Path(root).rglob("*.rb"))

    helpers = control_scope_helpers(["libraries"])
    if not helpers:
        # Say it out loud. A profile can legitimately have none — helpers reached
        # through a constant (`SomeHelper.method`) resolve in any scope and carry
        # no hazard — but "found nothing to check" and "checked and found nothing
        # wrong" must not print the same way.
        print("::notice::no modules are included into ::Inspec::Rule under libraries/, "
              "so the deferred-helper rule has nothing to check in this profile.")

    found = {"resource": [], "helper": []}
    for f in sorted(targets):
        for lineno, line, kind in violations(f, helpers):
            found[kind].append(f"{f}:{lineno}: {line[:110]}")

    if found["resource"]:
        print("::error::InSpec resource called in a describe body — raises "
              "WrongScopeError at exec. Resolve it at control scope instead.")
        for f in found["resource"]:
            print(f"  {f}")
    if found["helper"]:
        print("::error::control-scope helper called inside a deferred block — raises "
              "NameError at exec, because the example is not the control. Resolve it "
              "at control scope and close over the value.")
        for f in found["helper"]:
            print(f"  {f}")
    if found["resource"] or found["helper"]:
        return 1

    print(f"OK — no resource calls in describe bodies and no control-scope helpers "
          f"in deferred blocks ({len(targets)} file(s), {len(helpers)} helper(s) known)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
