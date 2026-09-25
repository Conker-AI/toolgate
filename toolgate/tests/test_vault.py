"""Vault storage tests.

These run against real files and the real cipher. The property under test is
that a reader who holds the values file but not the install-time secret learns
nothing, so nothing here may be mocked.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from toolgate.core import vault


class VaultEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.env_path = self.root / "vault.env"
        self.key_file = self.root / "keys" / "vault.key"
        self.env_patch = patch.dict(
            os.environ,
            {"TOOLGATE_VAULT_KEY_FILE": str(self.key_file)},
            clear=False,
        )
        self.env_patch.start()
        os.environ.pop("TOOLGATE_VAULT_SECRET", None)
        self.path_patch = patch.object(vault, "ENV_PATH", self.env_path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.env_patch.stop()
        os.environ.pop(vault._SALT_KEY, None)
        self.temp_dir.cleanup()

    def _file_text(self) -> str:
        return self.env_path.read_text(encoding="utf-8")

    def test_a_written_secret_is_not_recoverable_from_the_values_file(self):
        vault.set_secret("GITHUB_TOKEN", "ghp_super_secret_value")

        self.assertNotIn("ghp_super_secret_value", self._file_text())
        self.assertIn(f"GITHUB_TOKEN={vault.ENCRYPTED_PREFIX}", self._file_text())
        self.assertEqual(vault.get_key("GITHUB_TOKEN"), "ghp_super_secret_value")

    def test_the_key_file_lives_outside_the_values_file(self):
        vault.set_secret("TAVILY_API_KEY", "tvly-value")

        self.assertTrue(self.key_file.exists())
        self.assertNotIn(self.key_file.read_text(encoding="utf-8").strip(), self._file_text())
        if os.name != "nt":  # Windows has no POSIX mode bits to assert on
            self.assertEqual(self.key_file.stat().st_mode & 0o777, 0o600)

    def test_cleartext_values_from_an_older_install_are_encrypted_on_startup(self):
        self.env_path.write_text(
            "TOOLGATE_ADMIN_KEY=owner-key\n"
            "MEMORYGATE_URL=http://memorygate-api:8020\n"
            "GITHUB_TOKEN=ghp_legacy_cleartext\n"
            "TAVILY_API_KEY=tvly-legacy-cleartext\n"
            "RESEND_API_KEY=\n",
            encoding="utf-8",
        )

        moved = vault.encrypt_values_at_rest()

        self.assertEqual(moved, 2)
        self.assertNotIn("ghp_legacy_cleartext", self._file_text())
        self.assertNotIn("tvly-legacy-cleartext", self._file_text())
        self.assertEqual(vault.get_key("GITHUB_TOKEN"), "ghp_legacy_cleartext")
        self.assertEqual(vault.get_key("TAVILY_API_KEY"), "tvly-legacy-cleartext")
        # Configuration the process reads from its own environment stays readable,
        # and an empty placeholder is left alone rather than encrypted to nothing.
        self.assertIn("MEMORYGATE_URL=http://memorygate-api:8020", self._file_text())
        self.assertIn("TOOLGATE_ADMIN_KEY=owner-key", self._file_text())
        self.assertIn("RESEND_API_KEY=", self._file_text())

    def test_migration_is_idempotent(self):
        vault.set_secret("GITHUB_TOKEN", "ghp_value")
        first = self._file_text()

        self.assertEqual(vault.encrypt_values_at_rest(), 0)
        self.assertEqual(self._file_text(), first)

    def test_a_different_install_secret_fails_closed_instead_of_leaking(self):
        vault.set_secret("GITHUB_TOKEN", "ghp_value")

        with patch.dict(os.environ, {"TOOLGATE_VAULT_SECRET": "some-other-install-secret"}):
            with self.assertRaises(vault.VaultError):
                vault.get_key("GITHUB_TOKEN")
            self.assertEqual(vault.vault_status()["status"], "unavailable")

    def test_an_undecryptable_secret_is_a_key_error_so_callers_deny(self):
        # Every vault.get_key call site already treats KeyError as a closed
        # door; VaultError must keep taking that path rather than becoming a 500.
        vault.set_secret("GITHUB_TOKEN", "ghp_value")

        with patch.dict(os.environ, {"TOOLGATE_VAULT_SECRET": "wrong"}), self.assertRaises(KeyError):
            vault.get_key("GITHUB_TOKEN")

    def test_a_secret_supplied_only_through_the_environment_still_resolves(self):
        with patch.dict(os.environ, {"STACKEXCHANGE_KEY": "supplied-by-docker-secret"}):
            self.assertEqual(vault.get_key("STACKEXCHANGE_KEY"), "supplied-by-docker-secret")

    def test_runtime_configuration_is_not_offered_as_a_vault_secret(self):
        self.env_path.write_text(
            "TOOLGATE_ADMIN_KEY=owner-key\n"
            "TOOLGATE_DASHBOARD_ORIGINS=http://localhost:8011\n"
            "MEMORYGATE_URL=http://memorygate-api:8020\n"
            "GITHUB_TOKEN=ghp_value\n",
            encoding="utf-8",
        )

        self.assertEqual(vault.list_placeholders(), ["GITHUB_TOKEN"])
        with self.assertRaises(ValueError):
            vault.set_secret("MEMORYGATE_URL", "http://elsewhere:8020")
        with self.assertRaises(ValueError):
            vault.set_secret("TOOLGATE_ADMIN_KEY", "hijack")
        with self.assertRaises(ValueError):
            vault.delete_secret("TOOLGATE_DASHBOARD_ORIGINS")

    def test_vault_status_is_coarse_enough_for_an_unauthenticated_probe(self):
        vault.set_secret("GITHUB_TOKEN", "ghp_value")

        status = vault.vault_status()

        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["key_source"], "key_file")
        rendered = repr(status)
        self.assertNotIn("ghp_value", rendered)
        self.assertNotIn("GITHUB_TOKEN", rendered)
        self.assertNotIn(str(self.key_file), rendered)

    def test_an_unwritable_key_location_refuses_rather_than_storing_cleartext(self):
        blocked = self.root / "blocked"
        blocked.write_text("not a directory", encoding="utf-8")

        with (
            patch.dict(os.environ, {"TOOLGATE_VAULT_KEY_FILE": str(blocked / "vault.key")}),
            self.assertRaises(vault.VaultError),
        ):
            vault.set_secret("GITHUB_TOKEN", "ghp_value")

        self.assertNotIn("ghp_value", self._file_text() if self.env_path.exists() else "")


if __name__ == "__main__":
    unittest.main()
