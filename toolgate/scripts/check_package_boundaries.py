"""Fail when ToolGate's packages gain a dependency nobody decided on.

Run from the repository root: python toolgate/scripts/check_package_boundaries.py
Every module under toolgate/ lives in a package named for its type (toolgate/api,
toolgate/core, toolgate/executors, ...). Two rules hold without exception: no module sits loose
in toolgate/ (only toolgate/__init__.py), and only toolgate/scripts imports toolgate.api (it
exports the OpenAPI document). Every other import that crosses packages must be listed in
package-boundaries.txt. The edges that existed when the check arrived are listed there; an
edge that disappears must be deleted, so the list only gets shorter unless someone adds a
line on purpose, with the reason in the commit.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ALLOWLIST = Path("package-boundaries.txt")
SOURCES = (Path("toolgate"),)


def owner(path: Path) -> str:
    """The package a file belongs to (api, core, ...), or "" for toolgate/__init__.py."""
    return path.parts[1] if len(path.parts) > 2 else ""


def imported_packages(path: Path) -> set[str]:
    package = list(path.parent.parts)
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[: len(package) - node.level + 1] if node.level else []
            module = ".".join([*base, *(node.module or "").split(".")]).strip(".")
            # `from toolgate import core` names the package in the alias.
            modules = (
                [f"toolgate.{a.name}" for a in node.names] if module == "toolgate" else [module]
            )
        else:
            continue
        for module in modules:
            parts = module.split(".")
            if parts[0] == "toolgate" and len(parts) > 1:
                found.add(parts[1])
    return found


def edges() -> dict[tuple[str, str], list[str]]:
    found: dict[tuple[str, str], list[str]] = {}
    for root in SOURCES:
        for path in sorted(root.rglob("*.py")):
            if path.parts[1] == "tests":
                continue
            source = owner(path)
            for target in imported_packages(path) - {source}:
                found.setdefault((source, target), []).append(path.as_posix())
    return found


def allowlist() -> set[tuple[str, str]]:
    entries = set()
    for line in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            source, target = (part.strip() for part in line.split("->"))
            entries.add((source, target))
    return entries


def main() -> int:
    problems = [
        f"{path.as_posix()}: modules live in a package named for their type, not loose in toolgate/."
        for path in Path("toolgate").glob("*.py")
        if path.name != "__init__.py"
    ]
    allowed = allowlist()
    found = edges()
    for (source, target), paths in sorted(found.items()):
        where = ", ".join(paths[:3]) + (" ..." if len(paths) > 3 else "")
        if target == "api" and source != "scripts":
            problems.append(
                f"{source} -> api ({where}): only toolgate/scripts may import toolgate.api."
            )
        elif (source, target) not in allowed:
            problems.append(
                f"{source} -> {target} ({where}): a new cross-package import. Move the code to "
                f"the package it belongs to, or add the edge to {ALLOWLIST} and say why."
            )
    problems += [
        f"{source} -> {target}: listed in {ALLOWLIST} but no longer imported; delete the line."
        for source, target in sorted(allowed - set(found))
    ]
    if problems:
        print("\n".join(problems))
        return 1
    print(f"package boundaries ok ({len(found)} cross-package edges, all listed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
