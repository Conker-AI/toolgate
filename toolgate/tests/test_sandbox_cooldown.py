"""The package proxy's cooldown: releases younger than the cooldown are hidden from pip and npm."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest

from toolgate.sandbox import cooldown

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def ago(days: float) -> str:
    return (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")


def pypi_page(files: list[dict]) -> bytes:
    return json.dumps({"meta": {"api-version": "1.1"}, "name": "demo", "files": files}).encode()


def test_pypi_hides_files_younger_than_the_cooldown_and_undated_ones():
    files = [
        {"filename": "demo-1.whl", "upload-time": ago(1)},
        {"filename": "demo-6.whl", "upload-time": ago(6)},
        {"filename": "demo-8.whl", "upload-time": ago(8)},
        {"filename": "demo-400.whl", "upload-time": ago(400)},
        {"filename": "demo-undated.whl"},
        {"filename": "demo-garbage.whl", "upload-time": "garbage"},
    ]
    body, removed = cooldown.filter_pypi(pypi_page(files), NOW.timestamp(), 7)
    assert body is not None
    doc = json.loads(body)
    assert [f["filename"] for f in doc["files"]] == ["demo-8.whl", "demo-400.whl"]
    assert removed == 4
    assert doc["meta"] == {"api-version": "1.1"} and doc["name"] == "demo"


def test_pypi_cooldown_zero_passes_the_page_unchanged():
    page = pypi_page([{"filename": "new.whl", "upload-time": ago(0)}])
    assert cooldown.filter_pypi(page, NOW.timestamp(), 0) == (page, 0)


def test_pypi_with_every_file_too_new_is_none():
    page = pypi_page([{"filename": "a.whl", "upload-time": ago(1)}, {"filename": "b.whl"}])
    assert cooldown.filter_pypi(page, NOW.timestamp(), 7) == (None, 2)


def npm_doc(versions: Mapping[str, float | None], tags: dict[str, str]) -> bytes:
    times = {"created": ago(500), "modified": ago(1)}
    times.update({v: ago(d) for v, d in versions.items() if d is not None})
    return json.dumps(
        {
            "name": "demo",
            "dist-tags": tags,
            "versions": {v: {"version": v} for v in versions},
            "time": times,
        }
    ).encode()


def test_npm_hides_new_versions_and_moves_latest_back():
    versions = {"1.0.0": 300, "1.1.0": 10, "2.0.0-beta.1": 9, "2.0.0": 2, "0.9.0": None}
    tags = {"latest": "2.0.0", "next": "2.0.0-beta.1", "old": "1.0.0", "canary": "2.0.0"}
    body, removed = cooldown.filter_npm(npm_doc(versions, tags), NOW.timestamp(), 7)
    assert body is not None
    doc = json.loads(body)
    assert sorted(doc["versions"]) == ["1.0.0", "1.1.0", "2.0.0-beta.1"]
    assert removed == 2  # 2.0.0 is too new, 0.9.0 has no date
    assert doc["dist-tags"] == {"next": "2.0.0-beta.1", "old": "1.0.0", "latest": "1.1.0"}


def test_npm_tag_on_a_removed_prerelease_is_deleted():
    versions = {"1.0.0": 300, "2.0.0-rc.1": 1}
    tags = {"latest": "1.0.0", "next": "2.0.0-rc.1"}
    body, removed = cooldown.filter_npm(npm_doc(versions, tags), NOW.timestamp(), 7)
    assert body is not None and removed == 1
    assert json.loads(body)["dist-tags"] == {"latest": "1.0.0"}


def test_npm_with_only_prereleases_left_points_latest_at_the_newest():
    versions = {"1.0.0-a": 40, "1.0.0-b": 20, "1.0.0": 1}
    body, _ = cooldown.filter_npm(npm_doc(versions, {"latest": "1.0.0"}), NOW.timestamp(), 7)
    assert body is not None
    assert json.loads(body)["dist-tags"]["latest"] == "1.0.0-b"


def test_npm_with_nothing_old_enough_is_none():
    versions = {"1.0.0": 1, "1.0.1": None}
    assert cooldown.filter_npm(npm_doc(versions, {"latest": "1.0.1"}), NOW.timestamp(), 7) == (
        None,
        2,
    )


@pytest.mark.parametrize("keep", [cooldown.filter_pypi, cooldown.filter_npm])
@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b"{}"])
def test_metadata_that_is_not_a_document_raises(keep, body):
    with pytest.raises(ValueError):
        keep(body, NOW.timestamp(), 7)


@pytest.mark.parametrize(("raw", "days"), [(None, 7), ("", 7), ("0", 0), ("30", 30), ("90", 90)])
def test_days_reads_the_environment(monkeypatch, raw, days):
    if raw is None:
        monkeypatch.delenv("PROXY_COOLDOWN_DAYS", raising=False)
    else:
        monkeypatch.setenv("PROXY_COOLDOWN_DAYS", raw)
    assert cooldown.days() == days


@pytest.mark.parametrize("raw", ["91", "x", "-1", "7.5"])
def test_days_refuses_values_out_of_range(monkeypatch, raw):
    monkeypatch.setenv("PROXY_COOLDOWN_DAYS", raw)
    with pytest.raises(ValueError):
        cooldown.days()
