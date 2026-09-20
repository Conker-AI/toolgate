"""Owner secret storage for ToolGate.

Vault values are encrypted at rest.  "Write-only" is a property of the HTTP
surface -- no route ever returns a value -- but that says nothing about the
file, so every provider credential is stored as a Fernet token behind the
``enc:v1:`` prefix and is readable only by a process that also holds the
install-time vault secret.

The encryption key is derived with scrypt from a secret that is deliberately
kept *outside* the values file:

1. ``TOOLGATE_VAULT_SECRET`` in the environment (preferred: a Docker secret or
   an orchestrator-supplied value that never lands in the data directory), or
2. the key file named by ``TOOLGATE_VAULT_KEY_FILE`` -- created 0600 with a
   fresh random secret on first start.  ToolGate's ``docker-compose.yml``
   points this at a dedicated volume so that a copy of the bind-mounted source
   directory does not carry the key that decrypts it.

The per-install scrypt salt lives in ``.env`` as ``TOOLGATE_VAULT_SALT``.  A
salt is not a secret; keeping it beside the values is what lets a passphrase
supplied through ``TOOLGATE_VAULT_SECRET`` stay usable across restarts.

Runtime configuration keys are listed in ``_CONFIG_KEYS`` and stay in
cleartext, because the process reads them out of its own environment before
this module can decrypt anything.  None of them is a provider credential, and
they are neither listed nor writable as vault secrets.
"""
import base64
import hashlib
import os
import re
import secrets
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import dotenv_values, set_key, unset_key

from toolgate.core.paths import DATA_DIR, ENV_PATH

ENCRYPTED_PREFIX = "enc:v1:"

_CONTROL_KEYS = {"TOOLGATE_ADMIN_KEY"}
_SALT_KEY = "TOOLGATE_VAULT_SALT"
# Read from the process environment during startup, so they can never be
# ciphertext.  Kept off the vault surface entirely rather than stored in
# cleartext behind a name that claims to be encrypted.
_CONFIG_KEYS = _CONTROL_KEYS | {
    _SALT_KEY,
    "MEMORYGATE_URL",
    "TOOLGATE_BOOTSTRAP_EXECUTION_KEY",
    "TOOLGATE_BOOTSTRAP_SCOPES",
    "TOOLGATE_OWNER_KEY_SHA256",
    "TOOLGATE_OWNER_KEY",
    "TOOLGATE_DASHBOARD_ORIGINS",
    "TOOLGATE_DATA_DIR",
    "TOOLGATE_ENV_PATH",
    # Retired configuration stays reserved so upgrades cannot expose it as provider secrets.
    "TOOLGATE_MCP_ACTOR",
    "TOOLGATE_MCP_PRESERVE_IDS",
    "TOOLGATE_MEMORYGATE_AGENT_ID",
    "TOOLGATE_SKILL_INJECTION",
    "TOOLGATE_VAULT_KEY_FILE",
    "TOOLGATE_VAULT_SECRET",
    "X_AGENT_ID",
}
_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_derived_keys: dict[tuple[str, str], "Fernet"] = {}


class VaultError(KeyError):
    """A vault value exists but cannot be produced.

    Subclasses ``KeyError`` on purpose: every ``vault.get_key`` caller already
    treats a missing secret as a closed door, so an undecryptable one takes the
    same path instead of surfacing as an unhandled 500.
    """


def key_file_path() -> Path:
    return Path(os.environ.get("TOOLGATE_VAULT_KEY_FILE", DATA_DIR / "vault.key"))


def _load() -> dict:
    if not ENV_PATH.exists():
        return {}
    return {k: v for k, v in dotenv_values(ENV_PATH).items() if v is not None}


def _install_secret() -> str:
    """Return the install-time secret, creating the key file on first start.

    Never falls back to an unencrypted vault: if no secret can be read and none
    can be written, this raises and the caller fails closed.
    """
    configured = os.environ.get("TOOLGATE_VAULT_SECRET", "").strip()
    if configured:
        return configured

    path = key_file_path()
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        path.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_urlsafe(48)
        path.write_text(generated + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        return generated
    except OSError as exc:
        raise VaultError(
            f"No vault key is available: {path} is unreadable ({type(exc).__name__}). "
            "Set TOOLGATE_VAULT_SECRET, or point TOOLGATE_VAULT_KEY_FILE at a writable path."
        ) from exc


def _salt() -> bytes:
    value = _load().get(_SALT_KEY) or os.environ.get(_SALT_KEY)
    if not value:
        value = secrets.token_hex(16)
        if not ENV_PATH.exists():
            ENV_PATH.touch()
        set_key(str(ENV_PATH), _SALT_KEY, value, quote_mode="never")
        os.environ[_SALT_KEY] = value
    return bytes.fromhex(value)


def _fernet() -> Fernet:
    """Derive the value key, memoised per (install secret, salt).

    scrypt is deliberately expensive, and get_key runs on every tool execution
    that carries a credential; deriving it per call would put ~60 ms of KDF on
    the action path. The cache is keyed by its inputs, so changing either the
    install secret or the salt produces a different key rather than a stale one.
    """
    secret, salt = _install_secret(), _salt()
    cache_key = (secret, salt.hex())
    cached = _derived_keys.get(cache_key)
    if cached is None:
        derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt,
                                 n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        cached = Fernet(base64.urlsafe_b64encode(derived))
        _derived_keys[cache_key] = cached
    return cached


def _encrypt(value: str) -> str:
    return ENCRYPTED_PREFIX + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt(name: str, raw: str) -> str:
    """Return the cleartext for a stored value.

    A value without the prefix is returned as-is, so an operator can still hand
    a secret straight to the process environment -- a Docker secret, say --
    without it having to round-trip through this file.
    """
    if not raw.startswith(ENCRYPTED_PREFIX):
        return raw
    try:
        return _fernet().decrypt(raw[len(ENCRYPTED_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise VaultError(f"{name} is encrypted with a different vault key and cannot be read") from exc


def get_key(placeholder: str) -> str:
    """Return the real value for a vault placeholder. Never exposed to callers via list_placeholders()."""
    if placeholder in {"TOOLGATE_OWNER_KEY_SHA256", "TOOLGATE_OWNER_KEY"}:
        raise KeyError("Owner channel configuration is not a tool secret")
    value = _load().get(placeholder) or os.environ.get(placeholder)
    if not value:
        raise KeyError(f"{placeholder} is not set in .env")
    return _decrypt(placeholder, value)


def list_placeholders() -> list[str]:
    """Return placeholder names only. Values are never returned by this function."""
    return sorted(k for k in _load() if k not in _CONFIG_KEYS)


def set_secret(name: str, value: str, *, allow_existing: bool = True) -> None:
    if name in _CONTROL_KEYS:
        raise ValueError(f"{name} is an internal control key, not a vault secret")
    if name in _CONFIG_KEYS:
        raise ValueError(f"{name} is runtime configuration, not a vault secret; set it in the environment")
    if not _NAME_PATTERN.match(name):
        raise ValueError("Key name must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)")
    if not allow_existing and name in _load():
        raise ValueError(f"{name} already exists")

    if not ENV_PATH.exists():
        ENV_PATH.touch()
    set_key(str(ENV_PATH), name, _encrypt(value), quote_mode="never")


def delete_secret(name: str) -> None:
    if name in _CONFIG_KEYS:
        raise ValueError(f"{name} is runtime configuration, not a vault secret; it cannot be deleted here")
    if name not in _load():
        raise KeyError(name)
    unset_key(str(ENV_PATH), name)


def encrypt_values_at_rest() -> int:
    """Re-write any cleartext vault value as ciphertext. Returns how many moved.

    Runs on startup so an install that predates encryption stops holding
    provider keys in the clear the first time it is restarted.
    """
    moved = 0
    for name, value in _load().items():
        if name in _CONFIG_KEYS or not value or value.startswith(ENCRYPTED_PREFIX):
            continue
        set_key(str(ENV_PATH), name, _encrypt(value), quote_mode="never")
        moved += 1
    return moved


def vault_status() -> dict:
    """Coarse readiness of the secret store, safe for an unauthenticated probe.

    Names no path, no value and no placeholder: only whether the store can be
    read and whether the configured key decrypts what it holds.
    """
    try:
        source = "environment" if os.environ.get("TOOLGATE_VAULT_SECRET", "").strip() else "key_file"
        fernet = _fernet()
        for name, value in _load().items():
            if name in _CONFIG_KEYS or not value.startswith(ENCRYPTED_PREFIX):
                continue
            fernet.decrypt(value[len(ENCRYPTED_PREFIX):].encode("ascii"))
            break
    except (VaultError, InvalidToken, ValueError, OSError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    return {"status": "ok", "key_source": source}


def get_control_key(name: str) -> str | None:
    """Read the owner-only admin key, which is never a vault placeholder."""
    if name != "TOOLGATE_ADMIN_KEY":
        return None
    return _load().get(name) or os.environ.get(name)


def ensure_control_keys() -> dict:
    """Generate TOOLGATE_ADMIN_KEY on first run if missing and persist it.

    Returns the key only when it was freshly generated.
    """
    if not ENV_PATH.exists():
        ENV_PATH.touch()

    values = _load()
    generated = {}
    for name in ("TOOLGATE_ADMIN_KEY",):
        if values.get(name):
            continue
        configured = os.environ.get(name, "").strip()
        if configured:
            set_key(str(ENV_PATH), name, configured, quote_mode="never")
            continue
        new_value = uuid.uuid4().hex
        set_key(str(ENV_PATH), name, new_value, quote_mode="never")
        os.environ[name] = new_value
        generated[name] = new_value

    return generated


def rotate_control_key(name: str) -> str:
    if name != "TOOLGATE_ADMIN_KEY":
        raise ValueError(f"Cannot rotate {name}")
    new_value = uuid.uuid4().hex
    if not ENV_PATH.exists():
        ENV_PATH.touch()
    set_key(str(ENV_PATH), name, new_value, quote_mode="never")
    os.environ[name] = new_value
    return new_value
