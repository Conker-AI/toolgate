"""Prove boundary tests detect broken authority, archival and approval integrity, in disposable copies.

Run from the repository root: python toolgate/scripts/mutation_check.py
No live source, database, vault, or gate configuration is modified.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mutations_core import MUTANTS as CORE_MUTANTS
from mutations_owner import MUTANTS as OWNER_MUTANTS

ROOT = Path(__file__).resolve().parents[2]
# Failures from a mutant that cannot run, not from the behaviour it changes.
BROKEN_MUTANT = ("NameError", "ImportError", "SyntaxError", "IndentationError")

MUTANTS = [*CORE_MUTANTS, *OWNER_MUTANTS]


def run_tests(root: Path, tests: list[str], name: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *tests,
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            # Beside the copy, not inside it: the tests refuse a temporary directory in the tree
            # they test (toolgate/tests/conftest.py).
            f"--basetemp={root.parent / 'runs' / name}",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def stale_anchors() -> list[str]:
    return [
        f"{label} ({file}: anchor found {count}x, expected 1)"
        for label, file, before, _after, _test in MUTANTS
        if (count := (ROOT / file).read_text(encoding="utf-8").count(before)) != 1
    ]


def main() -> int:
    if stale := stale_anchors():
        print("Mutation anchors changed; update the drill before relying on it:")
        print("\n".join(f"  {line}" for line in stale))
        return 1
    with tempfile.TemporaryDirectory(prefix="toolgate-mutations-") as directory:
        root = Path(directory) / "source"
        (root.parent / "runs").mkdir()  # pytest creates --basetemp itself, but not its parent
        for source in (ROOT / "toolgate").rglob("*.py"):
            destination = root / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        try:
            baseline = run_tests(root, sorted({m[4] for m in MUTANTS}), "baseline")
        except subprocess.TimeoutExpired:
            print("Baseline timed out; fix the behavior before testing mutations.")
            return 1
        if baseline.returncode:
            print(baseline.stdout + baseline.stderr)
            print("Baseline failed; fix the behavior before testing mutations.")
            return 1
        print("Baseline passed", flush=True)
        for index, (label, file, before, after, test) in enumerate(MUTANTS):
            path = root / file
            original = path.read_text(encoding="utf-8")
            if original.count(before) != 1:
                raise RuntimeError(
                    f"Mutation anchor changed: {label}. Update the drill before relying on it."
                )
            path.write_text(original.replace(before, after), encoding="utf-8")
            try:
                result = run_tests(root, [test], f"mutant-{index}")
            except subprocess.TimeoutExpired:
                print(f"TIMED OUT: {label}")
                return 1
            finally:
                path.write_text(original, encoding="utf-8")
            output = result.stdout + result.stderr
            if any(crash in output for crash in BROKEN_MUTANT):
                # A test failing on the mutant's own crash proves nothing about the behaviour.
                print(output)
                print(f"BROKEN MUTANT (it crashes instead of changing behaviour): {label}")
                return 1
            if result.returncode != 1 or f"FAILED {test}" not in result.stdout:
                print(result.stdout + result.stderr)
                print(f"NOT CAUGHT: {label}")
                return 1
            print(f"Caught: {label}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
