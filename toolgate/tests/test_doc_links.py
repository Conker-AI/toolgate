"""Checks every relative link in a tracked markdown file points at a real file.

Docs drift: a page is renamed or a section moved and the links pointing at it rot silently,
because no test read them. This walks every tracked `*.md`, takes the inline links outside
fenced code blocks, ignores web, mail and pure-anchor targets, and resolves the rest against
the linking file's folder. A link that used to be broken and was left that way on purpose is
listed in KNOWN_BROKEN with a reason; the set may only shrink, and an entry that now resolves
fails the test like any other stale list.
"""

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

LINK = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
FENCE = re.compile(r"^\s*(?:```|~~~)")
TITLE = re.compile(r'\s+"[^"]*"$')
IGNORED_PREFIXES = ("http://", "https://", "mailto:")

# Links left broken on purpose, as (file, line text, target); each needs a reason.
KNOWN_BROKEN: set[tuple[str, str, str]] = set()


def tracked_markdown() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return out.splitlines()


def relative_targets(text: str) -> list[tuple[int, str, str]]:
    """(line number, line text, path) for each inline link outside fenced code blocks."""
    found = []
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in LINK.finditer(line):
            target = TITLE.sub("", match.group(2).strip()).strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            if not target or target.startswith(IGNORED_PREFIXES) or target.startswith("#"):
                continue
            path = target.split("#", 1)[0]
            if path:
                found.append((number, line, path))
    return found


def test_relative_doc_links_resolve():
    broken = []
    seen = set()
    for name in tracked_markdown():
        file = REPO / name
        for number, line, target in relative_targets(file.read_text(encoding="utf-8")):
            if (file.parent / target).exists():
                continue
            entry = (name, line, target)
            seen.add(entry)
            if entry not in KNOWN_BROKEN:
                broken.append(f"{name}:{number}: broken link to {target!r} on line: {line.strip()}")
    stale = KNOWN_BROKEN - seen
    problems = [
        *broken,
        *(
            f"{name}: link to {target!r} now resolves; drop it from KNOWN_BROKEN."
            for name, _, target in sorted(stale)
        ),
    ]
    assert not problems, "\n".join(problems)
