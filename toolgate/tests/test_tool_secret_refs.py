"""A tool or verification method can name a vault secret, never ToolGate's own credentials."""
import pytest
from fastapi import HTTPException

from toolgate.api import dispatch
from toolgate.api.models import VerificationMethodCreate
from toolgate.api.routes import settings
from toolgate.core import vault

CONTROL = ("TOOLGATE_ADMIN_KEY", "TOOLGATE_BOOTSTRAP_EXECUTION_KEY", "TOOLGATE_VAULT_SECRET")


@pytest.fixture
def configured(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / ".env")
    monkeypatch.setenv("TOOLGATE_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("TOOLGATE_VAULT_SECRET", raising=False)
    vault.set_secret("PARTNER_TOKEN", "partner-value")


def _no_network(**_kwargs):
    raise AssertionError("a refused secret must not reach the network")


@pytest.mark.parametrize("name", CONTROL)
def test_a_public_http_tool_cannot_send_a_control_credential(configured, monkeypatch, name):
    monkeypatch.setenv(name, f"private-{name.lower()}")
    monkeypatch.setattr(dispatch, "public_url", lambda _url: True)
    monkeypatch.setattr(dispatch, "public_client", _no_network)
    execution = {"url": "https://api.example.com/v1", "allowed_hosts": ["api.example.com"],
                 "secret_headers": {"X-Auth": name}}
    with pytest.raises(HTTPException) as refused:
        dispatch._execute_http_json(execution, {})
    assert refused.value.status_code == 503
    assert refused.value.detail["code"] == "SECRET_UNAVAILABLE"
    assert f"private-{name.lower()}" not in repr(refused.value.detail)


def test_a_public_http_tool_still_sends_an_ordinary_vault_secret(configured, monkeypatch):
    sent = {}

    class Client:
        def __init__(self, timeout, headers):
            sent.update(headers)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def request(self, method, url, json=None):
            raise dispatch.httpx.ConnectError("stop here")

    monkeypatch.setattr(dispatch, "public_url", lambda _url: True)
    monkeypatch.setattr(dispatch, "public_client", Client)
    execution = {"url": "https://api.example.com/v1", "allowed_hosts": ["api.example.com"],
                 "secret_headers": {"X-Auth": "PARTNER_TOKEN"}}
    with pytest.raises(HTTPException):
        dispatch._execute_http_json(execution, {})
    assert sent["X-Auth"] == "partner-value"


@pytest.mark.parametrize("name", CONTROL)
def test_a_verification_method_cannot_sign_with_a_control_credential(configured, monkeypatch, name):
    monkeypatch.setenv(name, f"private-{name.lower()}")
    with pytest.raises(HTTPException) as refused:
        settings.create_verification_method(VerificationMethodCreate(name="Phone", secret_ref=name), "admin")
    assert refused.value.status_code == 422
