"""Fail when pyright (basic mode) finds a type error that is not in the baseline.

Run from the repository root: python toolgate/scripts/check_types.py
pyrightconfig.json sets the mode and the checked folders. Errors that already existed when the
check arrived are counted per file in type-baseline.txt; a file's count may shrink but never
grow, and a line must be lowered or deleted once its file has fewer errors, so the list only
ever gets shorter. `--write` rewrites the baseline from the current errors: use it only to
lower counts, never to accept new errors.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

BASELINE = Path("type-baseline.txt")
HEADER = (
    "# pyright basic-mode errors per file when the type check arrived; counts may only shrink.\n"
    "# Lower or delete a line when its file improves (toolgate/scripts/check_types.py says which).\n"
)


def current_errors() -> Counter[str]:
    run = subprocess.run(
        [sys.executable, "-m", "pyright", "--outputjson"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(run.stdout)
    except json.JSONDecodeError:
        print(run.stdout + run.stderr)
        print("pyright did not produce a JSON report.")
        sys.exit(2)
    root = Path.cwd().resolve()
    counts: Counter[str] = Counter()
    for item in report.get("generalDiagnostics", []):
        if item.get("severity") == "error":
            path = Path(item["file"]).resolve().relative_to(root).as_posix()
            counts[path] += 1
    return counts


def baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    entries = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.rsplit(maxsplit=1)
        if len(parts) != 2 or not parts[1].isdigit():
            print(f"{BASELINE}: malformed entry: {line!r}")
            sys.exit(1)
        entries[parts[0]] = int(parts[1])
    return entries


def write(counts: Counter[str]) -> None:
    lines = [f"{path} {count}" for path, count in sorted(counts.items())]
    BASELINE.write_text(HEADER + "".join(f"{line}\n" for line in lines), encoding="utf-8")
    print(f"wrote {BASELINE}: {sum(counts.values())} errors in {len(counts)} files")


def main() -> int:
    counts = current_errors()
    if "--write" in sys.argv[1:]:
        write(counts)
        return 0
    allowed = baseline()
    problems = []
    for path in sorted(set(counts) | set(allowed)):
        found, ceiling = counts.get(path, 0), allowed.get(path, 0)
        if found > ceiling:
            problems.append(
                f"{path}: {found} type errors, baseline {ceiling}. Fix the new ones "
                "(python -m pyright " + path + ")."
            )
        elif found < ceiling:
            target = "delete its line" if found == 0 else f"lower it to {found}"
            problems.append(f"{path}: down to {found} type errors; {target} in {BASELINE}.")
    if problems:
        print("\n".join(problems))
        return 1
    print(f"types ok ({sum(counts.values())} baselined errors in {len(counts)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
