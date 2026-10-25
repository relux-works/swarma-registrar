#!/usr/bin/env python3
"""Reject attribution metadata in tracked content and changed added lines."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


# Character classes keep the gate's own source free of literal metadata markers.
MARKERS = re.compile(
    rb"claude[.]ai|session[_]|Claude[-]Session|Generated[ ]with|Co[-]Authored[-]By",
    re.IGNORECASE,
)


def git(*args):
    return subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="", help="Base commit for added-line checks")
    args = parser.parse_args()
    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip())
    failed = False
    for name in git("ls-files", "-z").split(b"\0"):
        if not name:
            continue
        path = root / os.fsdecode(name)
        # A tracked link's content is its target string; never follow it.
        content = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        if MARKERS.search(content):
            print(f"Attribution metadata in tracked file: {os.fsdecode(name)!r}", file=sys.stderr)
            failed = True
    if args.base:
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.base) is None:
            raise ValueError("invalid base commit")
        # An initial push has no predecessor; scanning all tracked files covers it.
        if set(args.base) != {"0"}:
            patch = git(
                "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0",
                f"{args.base}...HEAD", "--",
            )
            in_hunk = False
            for line in patch.splitlines():
                if line.startswith(b"diff --git "):
                    in_hunk = False
                elif line.startswith(b"@@ "):
                    in_hunk = True
                elif in_hunk and line.startswith(b"+") and MARKERS.search(line[1:]):
                    print("Attribution metadata in added lines", file=sys.stderr)
                    failed = True
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("Hygiene check unavailable", file=sys.stderr)
        sys.exit(2)
