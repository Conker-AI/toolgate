"""The base test case the research search tests share: each test gets its own control-plane database."""

import unittest

import pytest

from toolgate.core import control_plane


class ResearchDbTestCase(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _use_tmp_path(self, tmp_path):  # pytest's temporary directory, set before setUp
        self.tmp_path = tmp_path

    def setUp(self):
        self.original_db = control_plane.DB_PATH
        control_plane.DB_PATH = self.tmp_path / "toolgate-test.db"

    def tearDown(self):
        control_plane.DB_PATH = self.original_db
