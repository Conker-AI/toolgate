"""AI text for `ollama_generate` tools through Pi's model roles (Pi `POST /inference`).

Used when `TOOLGATE_PI_URL` and `TOOLGATE_PI_SERVICE_KEY` are both set; without them ToolGate
calls Ollama directly, as before. Pi's `tool-text` role picks the model and its settings
(temperature included); ToolGate sends only the prompt and the tool's token cap. The service key
travels only in the request header: it never appears in a log line, an error or a result.
"""

from __future__ import annotations

import os
import uuid

import httpx

ROLE = "tool-text"
PROMPT_LIMIT = 64000
TIMEOUT_SECONDS = 180


class PiUnavailable(Exception):
    """Pi produced no text. The message is safe to show: no key, no host."""


def configured() -> tuple[str, str] | None:
    """Pi's address and this service's key, or None to keep the direct Ollama path."""
    url = os.environ.get("TOOLGATE_PI_URL", "").strip().rstrip("/")
    key = os.environ.get("TOOLGATE_PI_SERVICE_KEY", "").strip()
    return (url, key) if url and key else None


def generate(
    url: str, key: str, prompt: str, max_tokens: int, timeout: float = TIMEOUT_SECONDS
) -> str:
    body = {
        "role": ROLE,
        "system": "",
        "prompt": prompt,
        "max_tokens": max_tokens,
        "json": False,
        "request_id": "toolgate:" + uuid.uuid4().hex,
    }
    try:
        response = httpx.post(
            f"{url}/inference",
            json=body,
            headers={"X-Pi-Service-Key": key},
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        raise PiUnavailable("Pi did not answer in time") from exc
    except httpx.HTTPError as exc:
        raise PiUnavailable(f"Pi is unreachable ({type(exc).__name__})") from exc
    if response.status_code == 503:
        try:
            code = response.json()["detail"]["code"]
        except (ValueError, KeyError, TypeError):
            code = None
        if code == "no_model":
            raise PiUnavailable("Pi has no usable model for tool text")
        raise PiUnavailable("Pi's model for tool text is unavailable")
    if response.status_code != 200:
        raise PiUnavailable(f"Pi refused the request (HTTP {response.status_code})")
    try:
        text = response.json()["text"]
    except (ValueError, KeyError, TypeError) as exc:
        raise PiUnavailable("Pi sent an unreadable answer") from exc
    if not isinstance(text, str):
        raise PiUnavailable("Pi sent an unreadable answer")
    return text
