"""Fail when a test skip or xfail marker grows or has no reason.

Run from the repository root: python scripts/check_skips.py
Counts pytest skip, skipif and xfail marks, pytest.skip(), pytest.xfail(), pytest.importorskip() and
unittest skips in the tracked test files, per file, and compares them with skip-baseline.txt. A file's
count may shrink but never grow, and a line must be lowered or deleted once its file has fewer skips,
so the list only ever gets shorter. Every marker needs a non-empty reason, and an xfail mark needs an
explicit strict= so a test that starts passing is noticed. `--write` rewrites the baseline from the
current counts: use it only to lower counts, never to accept new skips.
The same file is copied into each Conker repository; keep the copies identical.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

BASELINE = Path("skip-baseline.txt")
HEADER = (
    "# Test skip/xfail markers per file; counts may only shrink (scripts/check_skips.py).\n"
    "# Lower or delete a line when its file improves; never add a line or raise a count.\n"
)
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".test-tmp", ".test-runs"}
MARKS = {"skip", "skipif", "xfail"}
FUNCTIONS = {"skip", "xfail", "importorskip"}
UNITTEST = {"skip", "skipIf", "skipUnless"}


def is_test_file(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    if not name.endswith(".py") or IGNORED_DIRS.intersection(parts):
        return False
    return (
        name == "conftest.py"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in parts[:-1]
    )


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", "*.py"], capture_output=True, text=True, check=True
        ).stdout
        return [path for path in out.split("\0") if path]
    except (OSError, subprocess.CalledProcessError):
        found = [p.as_posix() for p in Path(".").rglob("*.py")]
        return [path.removeprefix("./") for path in found]


def dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def empty_text(node: ast.expr | None) -> bool:
    """True when there is no reason, or the reason is a literal blank string."""
    if node is None:
        return True
    return isinstance(node, ast.Constant) and not (
        isinstance(node.value, str) and node.value.strip()
    )


def keyword(call: ast.Call | None, name: str) -> ast.expr | None:
    if call is None:
        return None
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def classify(node: ast.Attribute) -> str:
    """Return the marker kind for an attribute node, or an empty string."""
    base = dotted(node.value)
    if node.attr in MARKS and base in ("pytest.mark", "mark"):
        return f"mark.{node.attr}"
    if node.attr in FUNCTIONS and base == "pytest":
        return f"pytest.{node.attr}"
    if node.attr == "skipTest":
        return "skipTest"
    if node.attr in UNITTEST and base == "unittest":
        return f"unittest.{node.attr}"
    return ""


def problem_for(kind: str, call: ast.Call | None) -> str:
    """Describe what is wrong with one marker, or return an empty string."""
    args = call.args if call is not None else []
    if kind.startswith("mark."):
        if empty_text(keyword(call, "reason")):
            return "has no reason= text"
        if kind == "mark.xfail" and keyword(call, "strict") is None:
            return "xfail needs an explicit strict="
    elif kind == "pytest.importorskip":
        if empty_text(keyword(call, "reason")):
            return "has no reason= text"
    elif kind in ("pytest.skip", "pytest.xfail"):
        given = keyword(call, "reason") or (args[0] if args else None)
        if empty_text(given):
            return "has no reason text"
    elif kind == "skipTest" or kind == "unittest.skip":
        if empty_text(args[0] if args else keyword(call, "reason")):
            return "has no reason text"
    elif kind in ("unittest.skipIf", "unittest.skipUnless"):
        given = args[1] if len(args) > 1 else keyword(call, "reason")
        if empty_text(given):
            return "has no reason text"
    return ""


def scan(path: str) -> tuple[int, list[str]]:
    """Count the markers in one file and describe the ones that break the rules."""
    try:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path)
    except (OSError, SyntaxError, UnicodeDecodeError) as error:
        return 0, [f"{path}: cannot be parsed ({error.__class__.__name__})"]
    calls: dict[int, ast.Call] = {}
    inner: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls[id(node.func)] = node
        if isinstance(node, ast.Attribute):
            inner.add(id(node.value))
    count = 0
    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or id(node) in inner:
            continue
        kind = classify(node)
        if not kind:
            continue
        count += 1
        issue = problem_for(kind, calls.get(id(node)))
        if issue:
            problems.append(f"{path}:{node.lineno}: {dotted(node)} {issue}.")
    return count, problems


def read_baseline() -> dict[str, int]:
    allowed: dict[str, int] = {}
    if not BASELINE.exists():
        return allowed
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        name, _, number = text.rpartition(" ")
        if not name or not number.isdigit():
            print(f"{BASELINE}: malformed entry: {line!r}")
            raise SystemExit(1)
        allowed[name] = int(number)
    return allowed


def write_baseline(counts: dict[str, int]) -> None:
    body = "".join(f"{path} {counts[path]}\n" for path in sorted(counts))
    BASELINE.write_text(HEADER + body, encoding="utf-8", newline="\n")
    print(f"wrote {BASELINE}: {sum(counts.values())} markers in {len(counts)} files")


def main(argv: list[str]) -> int:
    counts: dict[str, int] = {}
    problems: list[str] = []
    for path in sorted(tracked_files()):
        if not is_test_file(path):
            continue
        found, issues = scan(path)
        problems.extend(issues)
        if found:
            counts[path] = found
    if "--write" in argv:
        write_baseline(counts)
        return 1 if problems else 0
    allowed = read_baseline()
    for path, found in sorted(counts.items()):
        ceiling = allowed.get(path, 0)
        if found > ceiling:
            problems.append(
                f"{path}: {found} skip/xfail markers, baseline {ceiling}. Remove the new ones "
                "or turn them into real tests; the baseline never grows."
            )
    for path, ceiling in sorted(allowed.items()):
        found = counts.get(path, 0)
        if found < ceiling:
            target = "delete its line" if found == 0 else f"lower it to {found}"
            problems.append(f"{path}: down to {found} markers; {target} in {BASELINE}.")
    if problems:
        print("\n".join(problems))
        return 1
    print(f"skips ok ({sum(counts.values())} baselined markers in {len(counts)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
