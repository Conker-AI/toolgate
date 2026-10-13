"""Fail when a source file grows past the size limit.

Run from the repository root: python toolgate/scripts/check_file_sizes.py
Tracked source files may have at most LIMIT lines. Files that were already larger when the
check arrived are listed in file-size-allowlist.txt with their line count at that time; they
may shrink but never grow, and an entry must be deleted once its file is back under the limit,
so the list only ever gets shorter.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

LIMIT = 600
SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs")
ALLOWLIST = Path("file-size-allowlist.txt")


def tracked_sources() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [path for path in out.splitlines() if path.endswith(SUFFIXES)]


def allowlist() -> dict[str, int]:
    if not ALLOWLIST.exists():
        return {}
    entries = {}
    for line in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            path, count = line.rsplit(maxsplit=1)
            entries[path] = int(count)
    return entries


def main() -> int:
    allowed = allowlist()
    problems = []
    for path in tracked_sources():
        lines = Path(path).read_text(encoding="utf-8", errors="replace").count("\n")
        ceiling = allowed.pop(path, None)
        if ceiling is None and lines > LIMIT:
            problems.append(f"{path}: {lines} lines, limit {LIMIT}. Split it by concern.")
        elif ceiling is not None and lines > ceiling:
            problems.append(f"{path}: grew to {lines} lines; it is allowlisted at {ceiling} and may only shrink.")
        elif ceiling is not None and lines <= LIMIT:
            problems.append(f"{path}: now {lines} lines, under the limit; delete its line from {ALLOWLIST}.")
        elif ceiling is not None and lines < ceiling:
            problems.append(f"{path}: shrank to {lines} lines; lower its entry in {ALLOWLIST} from {ceiling}.")
    problems += [f"{path}: listed in {ALLOWLIST} but no longer tracked; delete the line." for path in allowed]
    if problems:
        print("\n".join(problems))
        return 1
    print(f"file sizes ok (limit {LIMIT}, {len(allowlist())} allowlisted files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
