"""Research text: HTML text extraction, publication dates and prompt-injection inspection."""

from __future__ import annotations

import html
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser

INJECTION_RULES = (
    ("instruction_override", re.compile(r"\b(ignore|disregard|override|forget)\b.{0,80}\b(previous|prior|system|developer|instructions?|prompt)\b", re.I | re.S)),
    ("role_impersonation", re.compile(r"\b(system|developer|assistant)\s*(message|prompt|instruction)?\s*:", re.I)),
    ("secret_request", re.compile(r"\b(reveal|print|send|upload|exfiltrate)\b.{0,80}\b(secret|credential|token|api[- _]?key|password|environment)\b", re.I | re.S)),
    ("tool_command", re.compile(r"\b(run|execute|call)\b.{0,60}\b(toolgate|terminal|shell|powershell|bash|curl)\b", re.I | re.S)),
    ("encoded_payload", re.compile(r"\b(base64|decode this|hidden instruction|jailbreak)\b", re.I)),
    ("encoded_blob", re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{96,}={0,2}(?![A-Za-z0-9+/])")),
    ("model_directive", re.compile(r"\b(assistant|agent|model|you)\b.{0,30}\b(must|should|need to|required to)\b.{0,100}\b(ignore|follow|obey|execute|call|reveal|send|open|visit)\b", re.I | re.S)),
    ("prompt_probe", re.compile(r"\b(repeat|show|print|reveal)\b.{0,60}\b(system prompt|hidden instructions?|developer message)\b", re.I | re.S)),
)


SUPPRESSED_TAGS = {
    "aside", "dialog", "footer", "form", "head", "header", "menu", "nav",
    "noscript", "script", "style", "svg", "template",
}


BLOCK_TAGS = {
    "article", "blockquote", "br", "dd", "div", "dl", "dt", "figcaption",
    "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "li", "main",
    "p", "pre", "section", "table", "td", "th", "tr",
}


BOILERPLATE_MARKERS = {
    "advertisement", "cookie", "cookie-banner", "cookie-consent", "modal",
    "newsletter", "paywall", "popup", "privacy-banner", "subscribe",
}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.suppressed: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        attributes = {str(key).lower(): str(value or "").lower() for key, value in attrs}
        identity = f"{attributes.get('id', '')} {attributes.get('class', '')}"
        identity_tokens = set(re.findall(r"[a-z0-9-]+", identity))
        hidden = (
            "hidden" in attributes
            or attributes.get("aria-hidden") == "true"
            or "display:none" in attributes.get("style", "").replace(" ", "")
            or "visibility:hidden" in attributes.get("style", "").replace(" ", "")
            or bool(identity_tokens & BOILERPLATE_MARKERS)
        )
        if self.suppressed or tag in SUPPRESSED_TAGS or hidden:
            self.suppressed.append(tag)
            return
        if tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self.suppressed:
            if tag in self.suppressed:
                while self.suppressed:
                    if self.suppressed.pop() == tag:
                        break
            return
        if tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.suppressed:
            self.parts.append(data)


class _PublishedAtExtractor(HTMLParser):
    ACCEPTED_META_KEYS = frozenset({
        "article:published_time", "datepublished", "date-published", "publishdate", "pubdate",
    })

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.candidates: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {str(key).lower(): str(value or "").strip() for key, value in attrs}
        if tag.lower() == "meta":
            key = (attributes.get("property") or attributes.get("name") or attributes.get("itemprop") or "").lower()
            if key in self.ACCEPTED_META_KEYS and attributes.get("content"):
                self.candidates.append((f"meta:{key}", attributes["content"]))
        elif tag.lower() == "time" and attributes.get("itemprop", "").lower() == "datepublished" and attributes.get("datetime"):
            self.candidates.append(("time:datePublished", attributes["datetime"]))


def clean_text(value: object, limit: int = 4000) -> str:
    text = unicodedata.normalize("NFKC", html.unescape(str(value or "")))
    text = "".join(
        char for char in text
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:limit]


def extract_html_text(value: object, limit: int = 20000) -> str:
    parser = _TextExtractor()
    parser.feed(str(value or ""))
    parser.close()
    normalized = clean_text("".join(parser.parts), max(limit * 2, limit))
    lines: list[str] = []
    previous = None
    for line in normalized.splitlines():
        line = line.strip()
        if not line or line == previous:
            continue
        lines.append(line)
        previous = line
    return clean_text("\n".join(lines), limit)


def extract_published_metadata(value: object) -> tuple[str | None, dict | None]:
    """Extract only explicit machine-readable publication metadata from bounded HTML."""
    raw = str(value or "")
    parser = _PublishedAtExtractor()
    try:
        parser.feed(raw)
        parser.close()
    except (UnicodeError, ValueError):
        return None, None
    json_ld = re.search(r'"datePublished"\s*:\s*"([^"\\]{4,80})"', raw, flags=re.I)
    candidates = list(parser.candidates)
    if json_ld:
        candidates.append(("jsonld:datePublished", json_ld.group(1)))
    now = datetime.now(UTC)
    for field, candidate in candidates:
        normalized = clean_text(candidate, 80)
        try:
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        parsed = parsed.astimezone(UTC)
        if datetime(1990, 1, 1, tzinfo=UTC) <= parsed <= now + timedelta(days=1):
            return parsed.isoformat(), {"provider": "page_metadata", "field": field}
    return None, None


def inspect_text(value: str) -> dict:
    normalized = clean_text(value, max(len(value), 1))
    flags = [name for name, pattern in INJECTION_RULES if pattern.search(normalized)]
    risk = "high" if flags else "low"
    return {"risk": risk, "flags": flags}
