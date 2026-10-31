"""Holds the guard scripts to their own rules, in throwaway trees.

toolgate/scripts/check_file_sizes.py and toolgate/scripts/check_package_boundaries.py guard the
repository, but nothing guarded them: an edit could quietly loosen what CI enforces. Each test
here builds a disposable tree in `tmp_path`, runs the real script there with
`[sys.executable, <script>]`, and checks its exit code and message text, so a wording change
cannot slip past unnoticed either.
"""

import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FILE_SIZES = SCRIPTS / "check_file_sizes.py"
BOUNDARIES = SCRIPTS / "check_package_boundaries.py"

FILE_SIZE_ALLOWLIST = "file-size-allowlist.txt"
PACKAGE_BOUNDARIES = "package-boundaries.txt"


def run_script(script: Path, root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def track_everything(root: Path) -> None:
    """Make the tree a git repo so `git ls-files` sees its files; no commit is needed."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)


def source_file(lines: int) -> str:
    """A tracked .py file with exactly `lines` newlines, which is how the script counts."""
    return "".join(f"# filler line {number}\n" for number in range(1, lines + 1))


class TestCheckFileSizes:
    def test_file_at_the_limit_passes(self, tmp_path):
        write(tmp_path, "mod.py", source_file(600))
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "file sizes ok (limit 600, 0 allowlisted files)" in result.stdout

    def test_file_one_line_over_the_limit_fails(self, tmp_path):
        write(tmp_path, "mod.py", source_file(601))
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 1
        assert "mod.py: 601 lines, limit 600. Split it by concern." in result.stdout

    def test_allowlisted_file_at_its_ceiling_passes(self, tmp_path):
        write(tmp_path, "big.py", source_file(700))
        write(tmp_path, FILE_SIZE_ALLOWLIST, "# already large when the check arrived\nbig.py 700\n")
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "file sizes ok (limit 600, 1 allowlisted files)" in result.stdout

    def test_allowlisted_file_that_grows_fails(self, tmp_path):
        write(tmp_path, "big.py", source_file(701))
        write(tmp_path, FILE_SIZE_ALLOWLIST, "big.py 700\n")
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 1
        assert (
            "big.py: grew to 701 lines; it is allowlisted at 700 and may only shrink."
            in result.stdout
        )

    def test_allowlisted_file_back_under_the_limit_fails_asking_to_delete_the_entry(self, tmp_path):
        write(tmp_path, "big.py", source_file(500))
        write(tmp_path, FILE_SIZE_ALLOWLIST, "big.py 700\n")
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 1
        assert (
            "big.py: now 500 lines, under the limit; delete its line from file-size-allowlist.txt."
            in result.stdout
        )

    def test_allowlisted_file_that_shrank_but_stays_over_the_limit_fails_asking_to_lower_the_entry(
        self, tmp_path
    ):
        write(tmp_path, "big.py", source_file(650))
        write(tmp_path, FILE_SIZE_ALLOWLIST, "big.py 700\n")
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 1
        assert (
            "big.py: shrank to 650 lines; lower its entry in file-size-allowlist.txt from 700."
            in result.stdout
        )

    def test_allowlisted_path_that_is_not_tracked_fails(self, tmp_path):
        write(tmp_path, "mod.py", source_file(10))
        write(tmp_path, FILE_SIZE_ALLOWLIST, "gone.py 700\n")
        track_everything(tmp_path)
        result = run_script(FILE_SIZES, tmp_path)
        assert result.returncode == 1
        assert (
            "gone.py: listed in file-size-allowlist.txt but no longer tracked; delete the line."
            in result.stdout
        )


class TestCheckPackageBoundaries:
    def module(self, tmp_path: Path, package: str, body: str) -> None:
        write(tmp_path, f"toolgate/{package}/mod.py", body)

    def boundaries(self, tmp_path: Path, edges: list[str]) -> None:
        write(tmp_path, PACKAGE_BOUNDARIES, "".join(f"{edge}\n" for edge in edges))

    def test_module_loose_in_toolgate_fails(self, tmp_path):
        write(tmp_path, "toolgate/__init__.py", "")
        write(tmp_path, "toolgate/loose.py", "VALUE = 1\n")
        self.boundaries(tmp_path, [])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 1
        assert (
            "toolgate/loose.py: modules live in a package named for their type, not loose in toolgate/."
            in result.stdout
        )

    def test_unlisted_cross_package_import_fails_and_names_the_edge(self, tmp_path):
        self.module(tmp_path, "agent", "from toolgate.core import helpers\n")
        self.boundaries(tmp_path, [])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 1
        assert "agent -> core (toolgate/agent/mod.py): a new cross-package import." in result.stdout

    def test_listed_cross_package_import_passes(self, tmp_path):
        self.module(tmp_path, "agent", "from toolgate.core import helpers\n")
        self.boundaries(tmp_path, ["agent -> core"])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "package boundaries ok (1 cross-package edges, all listed)" in result.stdout

    def test_listed_edge_that_the_code_no_longer_has_fails(self, tmp_path):
        self.module(tmp_path, "core", "VALUE = 1\n")
        self.boundaries(tmp_path, ["core -> sandbox"])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 1
        assert (
            "core -> sandbox: listed in package-boundaries.txt but no longer imported; delete the line."
            in result.stdout
        )

    def test_package_other_than_scripts_cannot_import_api_even_when_listed(self, tmp_path):
        self.module(tmp_path, "plugins", "import toolgate.api.routes\n")
        self.boundaries(tmp_path, ["plugins -> api"])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 1
        assert (
            "plugins -> api (toolgate/plugins/mod.py): only toolgate/scripts may import toolgate.api."
            in result.stdout
        )

    def test_scripts_may_import_api_when_listed(self, tmp_path):
        self.module(tmp_path, "scripts", "import toolgate.api\n")
        self.boundaries(tmp_path, ["scripts -> api"])
        result = run_script(BOUNDARIES, tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "package boundaries ok (1 cross-package edges, all listed)" in result.stdout
