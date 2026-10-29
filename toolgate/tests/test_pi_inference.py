"""AI tools go through Pi's tool-text role when Pi is configured, and straight to Ollama when not.

A real local HTTP server stands in for Pi and Ollama, so the request ToolGate sends is the one on
the wire, and httpx's own logging is part of what the key must never reach.
"""

import json
import logging
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import HTTPException

from toolgate.api import definitions, dispatch
from toolgate.core import control_plane as cp
from toolgate.core import vault
from toolgate.executors import pi_inference

KEY = "pi-service-key-" + "k" * 40


class Upstream(BaseHTTPRequestHandler):
    seen: list = []
    answer = (200, {"text": "  hello there \n", "model": "local", "provider": "ollama"})
    delay = 0.0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        headers = {name.lower(): value for name, value in self.headers.items()}
        Upstream.seen.append(
            {"path": self.path, "headers": headers, "body": json.loads(self.rfile.read(length))}
        )
        time.sleep(Upstream.delay)
        status, body = Upstream.answer
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    Upstream.seen, Upstream.delay = [], 0.0
    Upstream.answer = (200, {"text": "  hello there \n", "model": "local", "provider": "ollama"})
    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("TOOLGATE_PI_URL", url + "/")
    monkeypatch.setenv("TOOLGATE_PI_SERVICE_KEY", KEY)
    yield url
    server.shutdown()
    server.server_close()


def tool(**execution):
    return {
        "id": "ai.text",
        "outputs": [],
        "execution": {
            "type": "ollama_generate",
            "prompt_template": "Say {text}",
            "max_tokens": 64,
            "temperature": 0.7,
            **execution,
        },
    }


def failure(**execution):
    with pytest.raises(HTTPException) as error:
        dispatch._dispatch_tool(tool(**execution), {"text": "hi"})
    assert KEY not in json.dumps(error.value.detail)
    return error.value.status_code, error.value.detail


def test_configured_pi_gets_the_prompt_and_token_cap_on_the_tool_text_role(upstream, caplog):
    caplog.set_level(logging.DEBUG)
    result = dispatch._dispatch_tool(tool(model="ignored-model"), {"text": "hi"})
    assert result == {"ok": True, "result": "hello there"}
    [request] = Upstream.seen
    assert request["path"] == "/inference"
    assert request["headers"]["x-pi-service-key"] == KEY
    body = request["body"]
    assert set(body) == {"role", "system", "prompt", "max_tokens", "json", "request_id"}
    assert body["role"] == "tool-text" and body["system"] == "" and body["json"] is False
    assert body["prompt"] == "Say hi" and body["max_tokens"] == 64
    assert re.fullmatch(r"[A-Za-z0-9_.:-]{16,128}", body["request_id"])
    assert KEY not in caplog.text


@pytest.mark.parametrize(
    "status,body,words",
    [
        (503, {"detail": {"code": "no_model", "message": "Pick a model"}}, "no usable model"),
        (503, {"detail": {"code": "unavailable", "message": "Provider failed"}}, "unavailable"),
        (401, {"detail": "bad key"}, "HTTP 401"),
        (403, {"detail": "role"}, "HTTP 403"),
        (200, {"model": "local"}, "unreadable"),
        (200, {"text": 5}, "unreadable"),
    ],
)
def test_pi_failures_are_the_usual_ai_tool_failure(upstream, status, body, words):
    Upstream.answer = (status, body)
    status_code, detail = failure()
    assert status_code == 502 and detail["code"] == "AI_UNAVAILABLE"
    assert words in detail["message"]


def test_a_slow_or_absent_pi_is_the_usual_failure(upstream, monkeypatch):
    monkeypatch.setattr(pi_inference, "TIMEOUT_SECONDS", 0.2)
    Upstream.delay = 1.0
    status_code, detail = failure()
    assert (status_code, detail["code"]) == (502, "AI_UNAVAILABLE")
    assert "in time" in detail["message"]
    monkeypatch.setattr(pi_inference, "TIMEOUT_SECONDS", 30)
    monkeypatch.setenv("TOOLGATE_PI_URL", "http://127.0.0.1:1")
    status_code, detail = failure()
    assert (status_code, detail["code"]) == (502, "AI_UNAVAILABLE")
    assert "unreachable" in detail["message"]


def test_a_prompt_over_the_pi_limit_is_refused_before_sending(upstream):
    with pytest.raises(HTTPException) as error:
        dispatch._dispatch_tool(tool(), {"text": "x" * pi_inference.PROMPT_LIMIT})
    assert error.value.status_code == 422 and error.value.detail["code"] == "VALIDATION_ERROR"
    assert Upstream.seen == []


@pytest.mark.parametrize("unset", ["TOOLGATE_PI_URL", "TOOLGATE_PI_SERVICE_KEY"])
def test_without_pi_the_tool_calls_ollama_directly(upstream, monkeypatch, unset):
    monkeypatch.delenv(unset)
    cp.update_settings({"generation_url": upstream}, "test")
    Upstream.answer = (200, {"response": " direct \n"})
    assert dispatch._dispatch_tool(tool(), {"text": "hi"}) == {"ok": True, "result": "direct"}
    [request] = Upstream.seen
    assert request["path"] == "/api/generate"
    assert "x-pi-service-key" not in request["headers"]
    assert request["body"]["prompt"] == "Say hi"
    assert request["body"]["options"]["temperature"] == 0.7
    assert request["body"]["options"]["num_predict"] == 64


def test_tool_validation_still_bounds_temperature_and_tokens(upstream):
    definition = {
        "id": "ai.text",
        "name": "AI text",
        "description": "Writes text",
        "authorization": "auto",
        "status": "active",
        "inputs": [{"name": "text", "type": "string"}],
        "execution": {"type": "ollama_generate", "prompt_template": "Say {text}"},
    }
    assert definitions.tool_definition_errors(definition) == []
    for field, value in (("temperature", 3), ("max_tokens", 2000), ("max_tokens", 4)):
        bad = {**definition, "execution": {**definition["execution"], field: value}}
        assert any(field in error for error in definitions.tool_definition_errors(bad))


def test_the_service_key_is_configuration_never_a_vault_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("TOOLGATE_VAULT_SECRET", raising=False)
    (tmp_path / "vault.env").write_text(
        f"TOOLGATE_PI_SERVICE_KEY={KEY}\nTOOLGATE_PI_URL=http://pi\n"
    )
    assert vault.encrypt_values_at_rest() == 0
    assert KEY in (tmp_path / "vault.env").read_text()
    assert vault.list_placeholders() == []
    with pytest.raises(KeyError):
        vault.get_key("TOOLGATE_PI_SERVICE_KEY")
    with pytest.raises(ValueError):
        vault.set_secret("TOOLGATE_PI_SERVICE_KEY", "other")
