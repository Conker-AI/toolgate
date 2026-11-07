"""Tests for the lookalike check: typo-squatting names are refused with a suggestion.

The expected names were checked against the data files first. One swap from the brief: the
npm list has no plain `electron` entry (only `electron-*` and `@electron/*` names), so the
transposition case uses `dbeug` -> `debug`, which is in the list at rank 3.
"""

from __future__ import annotations

import time

from toolgate.sandbox import lookalike

# A name that is popular after normalizing is never a lookalike, however it is spelled.
POPULAR_CASES = [
    ("pip", "Requests", None),
    ("pip", "requests", None),
    ("pip", "python_dateutil", None),
    ("npm", "lodash", None),
    ("npm", "Express", None),
]


def test_normalize_follows_each_manager_rules():
    assert lookalike.normalize("pip", "Foo__Bar.baz") == "foo-bar-baz"
    assert lookalike.normalize("npm", "Foo__Bar.baz") == "foo__bar.baz"


def test_popular_rank_reads_the_file():
    assert lookalike.popular_rank("pip", "boto3") == 1
    assert lookalike.popular_rank("pip", "some-unknown-package-name") is None


def test_popular_list_loads_in_rank_order():
    names = lookalike.popular("pip")
    assert names[0] == "boto3"
    assert names.index("requests") == 7
    assert len(names) == 8000


def test_popular_names_are_not_lookalikes():
    for manager, name, expected in POPULAR_CASES:
        assert lookalike.resemble(manager, name) == expected


def test_distance_one_typos_are_caught():
    assert lookalike.resemble("pip", "reqests") == "requests"
    assert lookalike.resemble("pip", "requets") == "requests"
    assert lookalike.resemble("pip", "reqeusts") == "requests"
    assert lookalike.resemble("pip", "numpi") == "numpy"
    assert lookalike.resemble("pip", "djang0") == "django"
    assert lookalike.resemble("npm", "lodahs") == "lodash"
    assert lookalike.resemble("npm", "expresss") == "express"


def test_adjacent_transpositions_are_caught():
    assert lookalike.resemble("npm", "dbeug") == "debug"
    assert lookalike.resemble("pip", "bot3o") == "boto3"


def test_confusable_and_separator_folds_are_caught():
    assert lookalike.resemble("pip", "pythondateutil") == "python-dateutil"
    assert lookalike.resemble("npm", "crossenv") == "cross-env"


def test_affixes_are_caught():
    assert lookalike.resemble("pip", "python-requests") == "requests"
    assert lookalike.resemble("pip", "requests-py") == "requests"
    assert lookalike.resemble("pip", "requests-dev") == "requests"
    assert lookalike.resemble("npm", "node-lodash") == "lodash"
    assert lookalike.resemble("npm", "lodash-js") == "lodash"
    assert lookalike.resemble("npm", "lodash.js") == "lodash"


def test_affixes_do_not_cross_managers():
    assert lookalike.resemble("pip", "lodash-js") is None
    assert lookalike.resemble("npm", "lodash-python") is None


def test_too_short_names_are_ignored():
    assert lookalike.resemble("pip", "mx") is None
    assert lookalike.resemble("pip", "qq") is None


def test_unrelated_names_are_ignored():
    assert lookalike.resemble("pip", "zzqv-totally-unrelated") is None
    assert lookalike.resemble("npm", "zzqv-totally-unrelated") is None


def test_fifty_calls_stay_fast():
    start = time.perf_counter()
    for _ in range(50):
        assert lookalike.resemble("pip", "some-unknown-package-name") is None
    elapsed = time.perf_counter() - start
    assert elapsed < 2.5, f"50 resemble calls took {elapsed:.2f}s"
