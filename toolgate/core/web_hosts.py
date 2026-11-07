# ruff: noqa: RUF001, RUF002  -- lookalike letters here are the point
"""Web hosts that research never shows or opens: lookalike names and hosts on public threat lists.

Both checks run inside ToolGate before any DNS answer is needed, and no per-host question leaves it:

- Lookalike names. A label that mixes scripts (a Cyrillic "а" inside "apple", "xn--pple-43d") or
  that is written only in Cyrillic or Greek letters that look Latin ("аррӏе") under a TLD that is
  not Cyrillic or Greek, and any `xn--` label that does not decode. The mixes real names use stay
  allowed: Latin with Han and kana (Japanese), with Han and Bopomofo, or with Han and Hangul.
  This follows the browsers' IDN display rules, which show such names as `xn--` instead.
- Threat lists. Whole lists of malware and phishing hosts are downloaded every 12 hours into
  `TOOLGATE_DATA_DIR/threat-lists/` (one file per feed) and checked locally; a host is refused when
  it or any parent domain is listed. `TOOLGATE_THREAT_FEEDS` holds the feed URLs, comma-separated;
  empty or `off` turns the lists off. A feed that fails keeps its last good file, so a list can be
  older than 12 hours but is never emptied by an outage; with no file yet, nothing is refused.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from toolgate.core.paths import DATA_DIR
from toolgate.core.public_https import public_client

DEFAULT_FEEDS = (
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
)
REFRESH_SECONDS = 12 * 3600
RETRY_SECONDS = 3600
FEED_BYTES = 16 * 1024 * 1024
LIST_DIR = DATA_DIR / "threat-lists"

_ALLOWED_MIXES = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)
# Letters that read as Latin ones (Chromium's whole-script confusable sets).
_LATIN_LOOKING = {
    "CYRILLIC": set("аысԁеԍһіюјӏорԗԛѕԝхуъьҽпгѵѡ"),
    "GREEK": set("αικνορτυχ"),
}
_OWN_TLDS = {
    "CYRILLIC": {"ru", "su", "ua", "by", "kz", "bg", "rs", "mk", "mn", "kg", "tj", "uz",
                 "рф", "бг", "срб", "укр", "қаз", "мкд", "мон", "бел"},
    "GREEK": {"gr", "cy", "ελ", "ευ"},
}
_HOST = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")

_lock = threading.Lock()
_loaded: dict[Path, tuple[float, frozenset[str]]] = {}
_attempted: dict[str, float] = {}
_running: set[str] = set()


def _script(char: str) -> str | None:
    """The script of one character; None for digits, hyphens and combining marks."""
    if char in "-0123456789" or unicodedata.category(char).startswith("M"):
        return None
    name = unicodedata.name(char, "")
    if not name:
        return "UNKNOWN"
    word = name.split()[0]
    if word in {"CJK", "IDEOGRAPHIC"} and "IDEOGRAPH" in name:
        return "HAN"
    if word == "KATAKANA-HIRAGANA":
        return "KATAKANA"
    return word


def _unicode_labels(host: str) -> list[str] | None:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                return None
            if label.isascii():  # an xn-- label must hold something non-ASCII
                return None
        labels.append(label.lower())
    return labels


def lookalike(host: str) -> bool:
    labels = _unicode_labels(host.rstrip(".").lower())
    if labels is None:
        return True
    tld = labels[-1]
    for label in labels:
        if label.isascii():
            continue
        if any(char != "-" and unicodedata.category(char)[0] not in "LMN" for char in label):
            return True  # controls, symbols and punctuation have no place in a host name
        scripts = {script for char in label if (script := _script(char))}
        if len(scripts) > 1 and not any(scripts <= mix for mix in _ALLOWED_MIXES):
            return True
        if len(scripts) == 1:
            (script,) = scripts
            letters = [char for char in label if _script(char)]
            if script in _LATIN_LOOKING and tld not in _OWN_TLDS[script] and all(
                char in _LATIN_LOOKING[script] for char in letters
            ):
                return True
    return False


def feeds() -> list[str]:
    raw = os.environ.get("TOOLGATE_THREAT_FEEDS")
    if raw is None:
        return list(DEFAULT_FEEDS)
    if raw.strip().lower() in {"", "off"}:
        return []
    return [url.strip() for url in raw.split(",") if url.strip()]


def _feed_file(url: str) -> Path:
    return LIST_DIR / f"{hashlib.sha256(url.encode()).hexdigest()[:16]}.txt"


def parse(text: str) -> set[str]:
    """Hosts from a hosts-file style list: `0.0.0.0 host` or `host`, `#` comments."""
    hosts = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        host = line.split()[-1].rstrip(".").lower()
        if _HOST.match(host) and host not in {"0.0.0.0", "127.0.0.1"}:
            hosts.add(host)
    return hosts


def _download(url: str) -> set[str]:
    body = bytearray()
    with public_client(timeout=30.0) as client, client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > FEED_BYTES:
                raise ValueError("threat feed is larger than 16 MiB")
    return parse(bytes(body).decode("utf-8", errors="replace"))


def refresh(url: str) -> bool:
    """Download one feed and replace its file; False keeps the old file."""
    try:
        hosts = _download(url)
    except Exception:  # any failure keeps the last good list
        return False
    if not hosts:
        return False
    target = _feed_file(url)
    temporary = target.with_suffix(".tmp")
    try:
        LIST_DIR.mkdir(parents=True, exist_ok=True)
        temporary.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    except OSError:  # a full or read-only data folder keeps the last list too
        return False
    return True


def _refresh_in_background(url: str) -> None:
    try:
        refresh(url)
    finally:
        with _lock:
            _running.discard(url)


def _due(url: str, now: float) -> bool:
    if url in _running or now - _attempted.get(url, 0.0) < RETRY_SECONDS:
        return False
    try:
        return now - _feed_file(url).stat().st_mtime >= REFRESH_SECONDS
    except OSError:
        return True


def _hosts(path: Path) -> frozenset[str]:
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return frozenset()
    cached = _loaded.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        hosts = frozenset(path.read_text(encoding="utf-8").split())
    except OSError:
        return frozenset()
    _loaded[path] = (mtime, hosts)
    return hosts


def listed(host: str) -> bool:
    host = host.rstrip(".").lower()
    labels = host.split(".")
    names = {".".join(labels[index:]) for index in range(len(labels) - 1)} or {host}
    now = time.time()
    found = False
    for url in feeds():
        with _lock:
            if _due(url, now):
                _attempted[url] = now
                _running.add(url)
                threading.Thread(target=_refresh_in_background, args=(url,), daemon=True).start()
            hosts = _hosts(_feed_file(url))
        if names & hosts:
            found = True
    return found


def refusal(url: str) -> str | None:
    """Why research must not show or open `url`, or None."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return None  # the public HTTPS check refuses it
    if not host:
        return None
    if lookalike(host):
        return "lookalike"
    if listed(host):
        return "threat_list"
    return None
