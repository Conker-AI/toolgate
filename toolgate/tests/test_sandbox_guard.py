"""The install guard (sandbox/guard.py): lookalikes, malware, unknown, young and rarely used
packages, the owner's trusted packages, and failing closed. Registry answers are faked."""

import time

import httpx
import pytest

from toolgate.core import tool_settings
from toolgate.sandbox import guard
from toolgate.sandbox.validation import Refused

DAY = 86400


def iso(days_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days_ago * DAY))


@pytest.fixture
def registry(monkeypatch):
    """Fake answers keyed by URL; OSV answers keyed by package name. Records every request."""
    pages, osv, seen = {}, {}, []

    def get(url, body=None):
        seen.append(url)
        if body is not None:
            answer = osv.get(body["package"]["name"], {})
            if isinstance(answer, Exception):
                raise answer
            return answer
        answer = pages.get(url)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(guard, "_get", get)
    guard._kept.clear()
    yield pages, osv, seen
    guard._kept.clear()


def pypi(pages, name, days_ago):
    pages[f"https://pypi.org/pypi/{name}/json"] = {
        "releases": {"1.0": [{"upload_time_iso_8601": iso(days_ago)}], "0.1": []}
    }


def npm(pages, name, days_ago, weekly):
    pages[f"https://registry.npmjs.org/{name}"] = {
        "versions": {"1.0.0": {}},
        "time": {"created": iso(days_ago), "1.0.0": iso(days_ago)},
    }
    pages[f"https://api.npmjs.org/downloads/point/last-week/{name}"] = {"downloads": weekly}


def refused(manager, packages, trusted=()):
    with pytest.raises(Refused) as caught:
        guard.check(manager, packages, list(trusted))
    return caught.value


def test_split_names_and_exact_pins():
    assert guard.split("pip", "requests") == ("requests", None)
    assert guard.split("pip", "requests==2.31.0") == ("requests", "2.31.0")
    assert guard.split("pip", "requests[socks]===2.31.0") == ("requests", "2.31.0")
    assert guard.split("pip", "requests>=2.0") == ("requests", None)
    assert guard.split("pip", "requests==2.0,!=2.1") == ("requests", None)
    assert guard.split("npm", "lodash") == ("lodash", None)
    assert guard.split("npm", "lodash@4.17.21") == ("lodash", "4.17.21")
    assert guard.split("npm", "lodash@^4.0.0") == ("lodash", None)
    assert guard.split("npm", "@types/node@20.1.0") == ("@types/node", "20.1.0")
    assert guard.split("npm", "@types/node") == ("@types/node", None)


def test_an_old_known_package_passes(registry):
    pages, _, _ = registry
    pypi(pages, "requests", 4000)
    npm(pages, "lodash", 4000, 50_000_000)
    guard.check("pip", ["requests==2.31.0"], [])
    guard.check("npm", ["lodash"], [])


def test_a_lookalike_is_refused_with_the_name_meant_and_no_lookup(registry):
    _, _, seen = registry
    error = refused("pip", ["reqeusts"])
    assert error.code == "package_lookalike" and "Did you mean 'requests'?" in str(error)
    assert seen == []


def test_malware_is_refused_even_when_trusted(registry):
    pages, osv, _ = registry
    pypi(pages, "evilpkg", 4000)
    osv["evilpkg"] = {
        "vulns": [
            {
                "id": "MAL-2025-1",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
            }
        ]
    }
    for trusted in ((), ("pip:evilpkg",)):
        error = refused("pip", ["evilpkg"], trusted)
        assert error.code == "package_malware" and "MAL-2025-1" in str(error)


def test_malware_found_only_in_some_versions_refuses_that_exact_version(registry):
    pages, osv, _ = registry
    pypi(pages, "goodlib", 4000)
    osv["goodlib"] = {
        "vulns": [
            {"id": "GHSA-x", "aliases": ["MAL-2025-9"], "affected": [{"versions": ["4.4.2"]}]}
        ]
    }
    assert refused("pip", ["goodlib==4.4.2"]).code == "package_malware"
    guard.check("pip", ["goodlib==4.4.1"], [])
    guard.check("pip", ["goodlib"], [])  # the proxy's cooldown keeps a fresh bad version away


def test_advisories_that_are_not_malware_do_not_refuse(registry):
    pages, osv, _ = registry
    pypi(pages, "oldlib", 4000)
    osv["oldlib"] = {"vulns": [{"id": "PYSEC-2020-1", "affected": [{}]}]}
    guard.check("pip", ["oldlib"], [])


def test_unknown_new_and_rarely_used_packages(registry):
    pages, _, _ = registry
    assert refused("pip", ["no-such-package-zz"]).code == "package_unknown"
    pypi(pages, "freshlib", 3)
    error = refused("pip", ["freshlib"])
    assert error.code == "package_too_new" and "3 days" in str(error)
    npm(pages, "quietlib", 4000, 12)
    error = refused("npm", ["quietlib"])
    assert error.code == "package_rarely_used" and "12 downloads" in str(error)


def test_the_owner_can_trust_a_new_package_but_only_that_one(registry):
    pages, _, seen = registry
    pypi(pages, "freshlib", 3)
    guard.check("pip", ["Fresh_Lib".replace("_", "")], ["pip:freshlib"])
    assert not any("pypi.org" in url for url in seen)  # trusted: no age lookup
    pypi(pages, "otherlib", 3)
    assert refused("pip", ["freshlib", "otherlib"], ["pip:freshlib"]).code == "package_too_new"


@pytest.mark.parametrize("failure", [OSError("down"), httpx.ConnectError("no"), ValueError("json")])
def test_a_failed_lookup_refuses_the_install(registry, failure):
    pages, osv, _ = registry
    pypi(pages, "requests", 4000)
    osv["requests"] = failure
    assert refused("pip", ["requests"]).code == "package_check_failed"
    pages["https://pypi.org/pypi/requests/json"] = failure
    osv["requests"] = {}
    guard._kept.clear()
    assert refused("pip", ["requests"]).code == "package_check_failed"


def test_answers_are_kept_for_an_hour(registry, monkeypatch):
    pages, _, seen = registry
    pypi(pages, "requests", 4000)
    guard.check("pip", ["requests"], [])
    guard.check("pip", ["requests"], [])
    assert len(seen) == 2  # OSV and PyPI once each
    later = time.monotonic() + guard.KEEP_SECONDS + 1
    monkeypatch.setattr(guard.time, "monotonic", lambda: later)
    guard.check("pip", ["requests"], [])
    assert len(seen) == 4


def test_trusted_package_settings_are_normalised_and_checked():
    chosen = tool_settings.Settings(
        install_trusted_packages=[
            " PIP:Typing_Extensions ",
            "npm:@Types/Node",
            "pip:typing.extensions",
        ]
    )
    assert chosen.install_trusted_packages == ["pip:typing-extensions", "npm:@types/node"]
    for bad in ("requests", "cargo:serde", "pip:", "npm:a b"):
        with pytest.raises(ValueError):
            tool_settings.Settings(install_trusted_packages=[bad])
