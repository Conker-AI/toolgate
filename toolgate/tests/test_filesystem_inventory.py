import json
import stat
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from toolgate.executors import filesystem_inventory as files


class Backend:
    def __init__(self, names=None, fail=None):
        self.names = names or ["folder", "file", "link", "socket"]
        self.fail = fail
        self.opened = []
        self.closed = []

    def open_root(self):
        self.opened.append((0, "/"))
        return 0

    def open_child(self, fd, name):
        if name == self.fail:
            raise OSError("sensitive absolute path")
        self.opened.append((fd, name))
        return len(self.opened) - 1

    def close(self, fd):
        self.closed.append(fd)

    @contextmanager
    def scan(self, fd):
        yield iter(SimpleNamespace(name=name) for name in self.names)

    def mode(self, fd, name):
        return {"folder": stat.S_IFDIR, "link": stat.S_IFLNK,
                "socket": stat.S_IFSOCK}.get(name, stat.S_IFREG)


@pytest.fixture(autouse=True)
def config(monkeypatch):
    monkeypatch.setenv("TOOLGATE_FILE_ROOTS", json.dumps({"work": "/srv/work"}))


def test_configuration_is_not_observation():
    assert files.roots() == {
        "mode": "configured", "roots": [{"id": "work", "path": "/srv/work"}],
        "capabilities": {"list": True, "read": False, "write": False},
    }


def test_relative_fd_traversal_and_metadata_only():
    backend = Backend()
    result = files.list_directory("work", "child", backend=backend)
    assert backend.opened == [(0, "/"), (0, "srv"), (1, "work"), (2, "child")]
    assert backend.closed == [0, 1, 2, 3]
    assert result["entries"] == [
        {"name": "folder", "path": "child/folder", "kind": "directory"},
        {"name": "file", "path": "child/file", "kind": "file"},
        {"name": "link", "path": "child/link", "kind": "symlink"},
        {"name": "socket", "path": "child/socket", "kind": "other"},
    ]
    assert result["truncated"] is False


@pytest.mark.parametrize("path", ["/etc", "..", "x/../y", "x\\y", "x//y", "x/", "a\x00", "a\n"])
def test_reject_path_before_backend(path):
    backend = Backend()
    with pytest.raises(files.FileError, match="arguments"):
        files.list_directory("work", path, backend=backend)
    assert not backend.opened


@pytest.mark.parametrize("limit", [True, 0, 201, 1.2, "2"])
def test_reject_limit(limit):
    with pytest.raises(files.FileError):
        files.list_directory("work", limit=limit, backend=Backend())


def test_caps_and_invalid_names():
    result = files.list_directory("work", limit=2, backend=Backend(["a", "b", "c"]))
    assert len(result["entries"]) == 2 and result["truncated"]
    result = files.list_directory("work", backend=Backend([".."] * 2001))
    assert result["entries"] == [] and result["truncated"]
    result = files.list_directory("work", backend=Backend(["bad\nname"]))
    assert result["entries"] == [] and result["truncated"]


def test_open_failure_closes_parent_and_hides_error():
    backend = Backend(fail="work")
    with pytest.raises(files.FileError) as error:
        files.list_directory("work", backend=backend)
    assert backend.closed == [0, 1]
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize("raw", ["{}", "[]", '{"x":"/a","x":"/b"}', '{"x":"relative"}',
                                  '{"x":"/a/../b"}', '{"x":"/a/"}', "x" * 32769],
                         ids=["empty", "array", "duplicate", "relative", "parent", "trailing", "large"])
def test_invalid_config(monkeypatch, raw):
    monkeypatch.setattr(files.os, "environ", {"TOOLGATE_FILE_ROOTS": raw})
    with pytest.raises(files.FileError) as error:
        files.roots()
    assert error.value.code == "invalid_configuration"


def test_missing_and_unknown(monkeypatch):
    with pytest.raises(files.FileError) as error:
        files.list_directory("missing", backend=Backend())
    assert error.value.code == "unknown_root"
    monkeypatch.delenv("TOOLGATE_FILE_ROOTS")
    with pytest.raises(files.FileError) as error:
        files.roots()
    assert error.value.code == "not_configured"


def test_unsupported_platform(monkeypatch):
    monkeypatch.setattr(files.sys, "platform", "win32")
    with pytest.raises(files.FileError) as error:
        files.list_directory("work")
    assert error.value.code == "unsupported_platform"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Actual Linux fd syscalls required")
def test_linux_metadata_symlinks_and_replaced_component(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden").write_text("not readable")
    (root / "file").write_text("never returned")
    (root / "link").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("TOOLGATE_FILE_ROOTS", json.dumps({"work": str(root)}))
    result = files.list_directory("work")
    assert {e["kind"] for e in result["entries"]} == {"file", "symlink"}
    assert "never returned" not in json.dumps(result)
    with pytest.raises(files.FileError):
        files.list_directory("work", "link")

    class Replace(files.LinuxBackend):
        def open_child(self, fd, name):
            if name == "root":
                root.rename(tmp_path / "old")
                root.symlink_to(outside, target_is_directory=True)
            return super().open_child(fd, name)

    with pytest.raises(files.FileError):
        files.list_directory("work", backend=Replace())
