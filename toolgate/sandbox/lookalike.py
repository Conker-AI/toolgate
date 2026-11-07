"""The lookalike check: refuse an install name one typo away from a popular package.

Typo-squatting aims at agents: a name like `reqeusts` or `crossenv` hopes the agent installing
it meant `requests` or `cross-env`. Given the manager (`"pip"` or `"npm"`) and a requested name,
`resemble` returns the popular name it probably meant - a distance-one typo, a separator or
confusable fold, or an added or removed affix - against the ranked top lists beside this module.
The caller refuses the install and shows the suggestion.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

SEPARATORS = re.compile(r"[-_.]+")
_FILES = {"pip": "popular-pypi.txt", "npm": "popular-npm.txt"}
# Affixes from the spec, reduced to their bare (separator-free) forms, split by position:
# pip prefixes python-/py-/py and suffixes -python/-py/-cli/-dev; npm prefixes node-/js- and
# suffixes -js/.js/js/-node/-cli/-dev. `-cli` and `-dev` are suffixes for both managers.
PIP_PREFIXES = frozenset({"python", "py"})
PIP_SUFFIXES = frozenset({"python", "py", "cli", "dev"})
NPM_PREFIXES = frozenset({"node", "js"})
NPM_SUFFIXES = frozenset({"js", "node", "cli", "dev"})


def normalize(manager: str, name: str) -> str:
    """Lowercase; pip also collapses runs of -_. to one - (PEP 503)."""
    lower = name.lower()
    if manager == "pip":
        return SEPARATORS.sub("-", lower)
    return lower


def bare(manager: str, name: str) -> str:
    """Remove separators; for npm a leading @scope/ is kept as is."""
    if manager == "npm" and name.startswith("@"):
        scope, slash, rest = name.partition("/")
        return f"{scope}/{SEPARATORS.sub('', rest)}" if slash else SEPARATORS.sub("", scope)
    return SEPARATORS.sub("", name)


def fold(manager: str, name: str) -> str:
    """Confusable fold (rn→m, vv→w, 0→o, 1→l, 3→e, 5→s), then bare."""
    text = name.replace("rn", "m").replace("vv", "w").translate(str.maketrans("0135", "oles"))
    return bare(manager, text)


@functools.cache
def _table(manager: str) -> tuple[tuple[str, str, str, str], ...]:
    """(as written, normalized, bare, fold) for every popular name, in rank order."""
    entries = []
    for line in Path(__file__).with_name(_FILES[manager]).read_text(encoding="utf-8").splitlines():
        written = line.strip()
        if not written or written.startswith("#"):
            continue
        lowered = written.lower()
        entries.append(
            (written, normalize(manager, lowered), bare(manager, lowered), fold(manager, lowered))
        )
    return tuple(entries)


@functools.cache
def _popular_set(manager: str) -> frozenset[str]:
    return frozenset(normalized for _, normalized, _, _ in _table(manager))


def popular(manager: str) -> tuple[str, ...]:
    """The popular names, normalized, most downloaded first."""
    return tuple(normalized for _, normalized, _, _ in _table(manager))


def popular_rank(manager: str, name: str) -> int | None:
    """The 1-based rank of the normalized name, or None if it is not popular."""
    target = normalize(manager, name)
    for rank, (_, normalized, _, _) in enumerate(_table(manager), 1):
        if normalized == target:
            return rank
    return None


def _edit_close(left: str, right: str) -> bool:
    """True when the Damerau-Levenshtein (optimal string alignment) distance is exactly 1.

    Equivalent to the full DP whenever that distance is 1: after the common prefix, the remainders
    must be one substitution, one adjacent transposition, or one leading insertion or deletion.
    Lengths differing by more than one are rejected up front, per the spec.
    """
    la, lb = len(left), len(right)
    if la - lb > 1 or lb - la > 1:
        return False
    i = 0
    while i < la and i < lb and left[i] == right[i]:
        i += 1
    a, b = left[i:], right[i:]
    la, lb = len(a), len(b)
    if not a or not b:
        return la != lb
    if la == lb:
        return a[1:] == b[1:] or (la > 1 and a[0] == b[1] and a[1] == b[0] and a[2:] == b[2:])
    if la == lb + 1:
        return a[1:] == b
    return b[1:] == a


def _affixed(nbare: str, pbare: str, prefixes: frozenset[str], suffixes: frozenset[str]) -> bool:
    """True when one bare name is the other with one allowed affix added at either end.

    A prefix (`python-`, `js-`) is stripped from the start of a bare name; a suffix (`-py`,
    `.js`, `-cli`) from its end. The affix text must actually be there - stripping by length
    alone would match unrelated names.
    """
    if nbare == pbare:
        return False
    for prefix in prefixes:
        if nbare.startswith(prefix) and nbare[len(prefix):] == pbare:
            return True
        if pbare.startswith(prefix) and pbare[len(prefix):] == nbare:
            return True
    for suffix in suffixes:
        if nbare.endswith(suffix) and nbare[: len(nbare) - len(suffix)] == pbare:
            return True
        if pbare.endswith(suffix) and pbare[: len(pbare) - len(suffix)] == nbare:
            return True
    return False


def resemble(manager: str, name: str) -> str | None:
    """The popular name this requested name probably meant, or None if none is close."""
    n = normalize(manager, name)
    if n in _popular_set(manager):
        return None
    nbare, nfold = bare(manager, n), fold(manager, n)
    if manager == "pip":
        prefixes, suffixes = PIP_PREFIXES, PIP_SUFFIXES
    else:
        prefixes, suffixes = NPM_PREFIXES, NPM_SUFFIXES
    for written, normalized, pbare, pfold in _table(manager):
        if len(normalized) >= 4 and _edit_close(n, normalized):
            return written
        if normalized != n and (pbare == nbare or pfold == nfold):
            return written
        if (
            len(normalized) >= 4
            and -6 <= len(nbare) - len(pbare) <= 6
            and _affixed(nbare, pbare, prefixes, suffixes)
        ):
            return written
    return None
