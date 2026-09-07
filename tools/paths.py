#!/usr/bin/env python3
"""One place that decides whether a path is one of ours.

Every tool here reads and writes files inside the repository, and several take a
path from the command line. A path assembled from an argument can escape the
tree — `--image-gems ../../etc/passwd` is read exactly as asked — and these tools
are increasingly invoked by automation rather than by a person who would notice.

So the rule is stated once, applied at every read and write, and refuses rather
than warns. A tool that quietly reads the wrong file produces a confident wrong
answer, which is the failure this repository spends most of its effort avoiding.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


class PathOutsideRepo(ValueError):
    """A path resolved outside the repository."""


def inside_repo(path, what="path"):
    """`path` resolved, guaranteed to live under the repository root.

    Symlinks are resolved BEFORE the check (`strict=False`, so a file that does
    not exist yet is still checked), because a link pointing out of the tree is
    exactly the case a string-prefix test misses.
    """
    resolved = pathlib.Path(path).resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise PathOutsideRepo(
            f"{what} resolves outside the repository and will not be used: "
            f"{resolved} is not under {ROOT}")
    return resolved
