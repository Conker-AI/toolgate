"""Outside text on its way to a model: invisible code points removed, then fenced.

The same `strip_invisible` rule lives in Pi (pi/core/untrusted_text.py); change both together.
Their tests pin the same fingerprint of the removed set.
"""

from __future__ import annotations

import re
import unicodedata

# Invisible code points that can carry a hidden message (emoji smuggling in variation
# selectors) and that NFKC and the "C" categories do not remove.
INVISIBLE = re.compile("[\u115f\u1160\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0\U000e0000-\U000e0fff]")


def strip_invisible(text: str) -> str:
    """Drop what a reader cannot see: format and bidi controls, tags, selectors, fillers, private
    use and unassigned code points, control characters except newline and tab."""
    text = INVISIBLE.sub("", text)
    return "".join(
        char for char in text if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )


def strip_invisible_values(value):
    """`strip_invisible` on every string in a JSON value, keys included."""
    if isinstance(value, str):
        return strip_invisible(value)
    if isinstance(value, list):
        return [strip_invisible_values(item) for item in value]
    if isinstance(value, dict):
        return {strip_invisible(str(key)): strip_invisible_values(item) for key, item in value.items()}
    return value


# Outside text that writes a fence's own tokens could close it early or open one of its own.
FENCE_TOKEN = re.compile(r"\[(\s*/?\s*)UNTRUSTED_", re.I)


def fenced(kind: str, label: str, text: str) -> str:
    """Wrap outside text in an UNTRUSTED_<kind>_CONTENT fence; `label` must be ToolGate's own."""
    text = FENCE_TOKEN.sub(r"(\1UNTRUSTED_", text)
    return f"[UNTRUSTED_{kind}_CONTENT {label}]\n{text}\n[/UNTRUSTED_{kind}_CONTENT]"
