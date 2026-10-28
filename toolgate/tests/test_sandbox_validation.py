"""Tests for sandbox validation functions."""

import pytest

from toolgate.sandbox import validation


class TestGuard:
    """Test the guard function that refuses dangerous commands."""

    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf /",
            "rm -rf /*",
            "rm -r -f /",
            "rm -fr / ",
            "rm --recursive --force /",
            "rm -rf --no-preserve-root /x",
            "ls; rm -rf /",
            "echo hi && /bin/rm -Rf /",
            "$(rm -rf /)",
            "x=1 rm -rf /",
            "env rm -rf /",
            "rm -rf ~",
            "kill -9 -1",
            "kill -- -1",
            "kill -s KILL -1",
            "pkill -9 -u sandbox",
            "killall .",
            "killall5 -9",
            "shutdown -h now",
            "reboot",
            "/sbin/halt",
            "poweroff",
            "init 0",
            "systemctl poweroff",
            ":(){ :|:& };:",
            "bomb(){ bomb|bomb& }; bomb",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            "echo x > /dev/sda",
            "find / -delete",
            "chmod -R 000 /",
        ],
    )
    def test_guard_refuses_dangerous_commands(self, command):
        reason = validation.guard(command)
        assert reason is not None, f"Command should be refused: {command}"
        assert isinstance(reason, str)

    @pytest.mark.parametrize(
        "command",
        [
            "ls -la",
            "rm -rf build/",
            "rm -rf ./node_modules",
            "kill 1234",
            "kill -1 1234",
            "python3 -c 'print(1)'",
            "echo hi > /dev/null",
            "find . -name '*.pyc' -delete",
            "git status",
            "rm -rf /tmp/x",
            "chmod -R u+w src",
            "echo 'rm -rf /' > notes.txt",
            "a | b && c || d",
        ],
    )
    def test_guard_accepts_safe_commands(self, command):
        reason = validation.guard(command)
        assert reason is None, f"Command should be accepted: {command}"


class TestCommand:
    """Test command validation."""

    def test_command_refuses_empty(self):
        with pytest.raises(validation.Refused) as exc:
            validation.command("")
        assert exc.value.code == "invalid_command"

    def test_command_refuses_whitespace_only(self):
        with pytest.raises(validation.Refused) as exc:
            validation.command("   \t  ")
        assert exc.value.code == "invalid_command"

    def test_command_refuses_too_long(self):
        cmd = "echo a; " * 1001  # This will be over 8000 chars
        assert len(cmd) > validation.MAX_COMMAND
        with pytest.raises(validation.Refused) as exc:
            validation.command(cmd)
        assert exc.value.code == "invalid_command"

    def test_command_accepts_max_length(self):
        cmd = "echo a; " * 399  # This should be under 8000 chars
        assert len(cmd) <= validation.MAX_COMMAND
        result = validation.command(cmd)
        assert result == cmd

    def test_command_refuses_nul_byte(self):
        with pytest.raises(validation.Refused) as exc:
            validation.command("echo\x00hi")
        assert exc.value.code == "invalid_command"

    def test_command_refuses_guarded_command(self):
        with pytest.raises(validation.Refused) as exc:
            validation.command("rm -rf /")
        assert exc.value.code == "guard_refused"
        assert "Refused:" in str(exc.value)


class TestCwd:
    """Test current working directory validation."""

    def test_cwd_empty_and_none(self):
        assert validation.cwd("") == ""
        assert validation.cwd(None) == ""

    def test_cwd_normal_paths(self):
        assert validation.cwd("a/b") == "a/b"
        assert validation.cwd("./a") == "a"
        assert validation.cwd("a//b/") == "a/b"

    def test_cwd_refuses_parent_traversal(self):
        with pytest.raises(validation.Refused) as exc:
            validation.cwd("../x")
        assert exc.value.code == "invalid_cwd"

    def test_cwd_refuses_absolute_paths(self):
        with pytest.raises(validation.Refused) as exc:
            validation.cwd("/abs")
        assert exc.value.code == "invalid_cwd"

    def test_cwd_root_is_the_workspace(self):
        """Small models send "/" for "where the command starts": that is the workspace."""
        assert validation.cwd("/") == ""

    def test_cwd_accepts_the_mounted_workspace_path(self):
        """Models name the folder as the container sees it; that is the same workspace."""
        assert validation.cwd("/workspace") == ""
        assert validation.cwd("/workspace/") == ""
        assert validation.cwd("/workspace/src/app") == "src/app"
        for escape in ("/workspace/../etc", "/workspaces", "/workspace2/x", "/etc", "//etc"):
            with pytest.raises(validation.Refused) as exc:
                validation.cwd(escape)
            assert exc.value.code == "invalid_cwd", escape

    def test_cwd_refuses_traversal_components(self):
        with pytest.raises(validation.Refused) as exc:
            validation.cwd("a/../b")
        assert exc.value.code == "invalid_cwd"

    def test_cwd_refuses_nul_byte(self):
        with pytest.raises(validation.Refused) as exc:
            validation.cwd("a\x00b")
        assert exc.value.code == "invalid_cwd"

    def test_cwd_refuses_too_long(self):
        path = "a" * 256
        with pytest.raises(validation.Refused) as exc:
            validation.cwd(path)
        assert exc.value.code == "invalid_cwd"


class TestAgent:
    """Test agent validation."""

    def test_agent_accepts_valid(self):
        assert validation.agent("companion") == "companion"
        assert validation.agent("research_2") == "research_2"

    def test_agent_refuses_empty(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent("")
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_uppercase(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent("Companion")
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_starting_with_digit(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent("1abc")
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_hyphen(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent("a-b")
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_slash(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent("a/b")
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_too_long(self):
        agent = "a" * 65
        with pytest.raises(validation.Refused) as exc:
            validation.agent(agent)
        assert exc.value.code == "invalid_agent"

    def test_agent_refuses_non_string(self):
        with pytest.raises(validation.Refused) as exc:
            validation.agent(123)
        assert exc.value.code == "invalid_agent"


class TestPackages:
    """Test package validation for different managers."""

    def test_pip_accepts_valid(self):
        result = validation.packages("pip", ["requests"])
        assert result == ["requests"]

    def test_pip_accepts_versions(self):
        result = validation.packages("pip", ["requests==2.32.3", "pandas>=2,<3", "uvicorn[standard]"])
        assert result == ["requests==2.32.3", "pandas>=2,<3", "uvicorn[standard]"]

    def test_npm_accepts_valid(self):
        result = validation.packages("npm", ["lodash"])
        assert result == ["lodash"]

    def test_npm_accepts_scoped_and_versioned(self):
        result = validation.packages("npm", ["@types/node@^22", "is-number@7.0.0"])
        assert result == ["@types/node@^22", "is-number@7.0.0"]

    def test_refuses_unknown_manager(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("yarn", ["something"])
        assert exc.value.code == "invalid_manager"

    def test_pip_refuses_vcs(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["git+https://x"])
        assert exc.value.code == "invalid_packages"

    def test_pip_refuses_options(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["-r"])
        assert exc.value.code == "invalid_packages"

    def test_pip_refuses_local_paths(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["./local"])
        assert exc.value.code == "invalid_packages"

    def test_pip_refuses_direct_urls(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["https://e/x.whl"])
        assert exc.value.code == "invalid_packages"

    def test_pip_refuses_direct_references(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["a @ https://x"])
        assert exc.value.code == "invalid_packages"

    def test_refuses_injection_attempts(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["pkg; rm"])
        assert exc.value.code == "invalid_packages"

    def test_refuses_duplicates(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", ["requests", "requests"])
        assert exc.value.code == "invalid_packages"

    def test_refuses_empty_list(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", [])
        assert exc.value.code == "invalid_packages"

    def test_refuses_too_many_items(self):
        packages = [f"pkg{i}" for i in range(21)]
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", packages)
        assert exc.value.code == "invalid_packages"

    def test_refuses_non_list(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("pip", "requests")
        assert exc.value.code == "invalid_packages"

    def test_npm_refuses_git(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("npm", ["git+ssh://x"])
        assert exc.value.code == "invalid_packages"

    def test_npm_refuses_file_protocol(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("npm", ["file:../x"])
        assert exc.value.code == "invalid_packages"

    def test_npm_refuses_evil_urls(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("npm", ["evil@http://x"])
        assert exc.value.code == "invalid_packages"

    def test_npm_refuses_options(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("npm", ["--registry=x"])
        assert exc.value.code == "invalid_packages"

    def test_npm_refuses_github_shortcut(self):
        with pytest.raises(validation.Refused) as exc:
            validation.packages("npm", ["github:user/repo"])
        assert exc.value.code == "invalid_packages"
