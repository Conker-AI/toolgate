"""Tests for sandbox container specification."""

import pytest

from toolgate.sandbox import spec


class TestConfigFromEnv:
    """Test Config.from_env validation."""

    def test_accepts_pinned_image(self):
        env = {
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
        }
        config = spec.Config.from_env(env)
        assert config.image == "sha256:" + "a" * 64
        assert config.workspaces_volume == "ws"
        assert config.proxy_volume == "px"

    def test_accepts_ghcr_image(self):
        env = {
            "SANDBOX_IMAGE": "ghcr.io/x/y@sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
        }
        config = spec.Config.from_env(env)
        assert config.image == "ghcr.io/x/y@sha256:" + "a" * 64

    def test_refuses_unpinned_image(self):
        env = {
            "SANDBOX_IMAGE": "toolgate-sandbox:latest",
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
        }
        with pytest.raises(spec.ConfigError) as exc:
            spec.Config.from_env(env)
        assert "must be pinned" in str(exc.value)

    def test_refuses_bad_volume_name(self):
        env = {
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "bad volume!",
            "SANDBOX_PROXY_VOLUME": "px",
        }
        with pytest.raises(spec.ConfigError) as exc:
            spec.Config.from_env(env)
        assert "must be a Docker volume name" in str(exc.value)

    def test_refuses_uid_zero(self):
        env = {
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
            "SANDBOX_UID": "0",
        }
        with pytest.raises(spec.ConfigError) as exc:
            spec.Config.from_env(env)
        assert "must be between" in str(exc.value)

    def test_refuses_low_memory(self):
        env = {
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
            "SANDBOX_MEMORY_MB": "10",
        }
        with pytest.raises(spec.ConfigError) as exc:
            spec.Config.from_env(env)
        assert "must be between" in str(exc.value)

    def test_refuses_non_integer_pids(self):
        env = {
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
            "SANDBOX_PIDS": "abc",
        }
        with pytest.raises(spec.ConfigError) as exc:
            spec.Config.from_env(env)
        assert "must be an integer" in str(exc.value)


class TestContainerSpec:
    """Test the container specification generated for requests."""

    def setup_method(self):
        self.config = spec.Config.from_env({
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
            "SANDBOX_UID": "65533",
            "SANDBOX_GID": "65533",
        })

    def test_run_container_basic_properties(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        # Network and security
        assert container_spec["HostConfig"]["NetworkMode"] == "none"
        assert container_spec["NetworkDisabled"] is True

        # No privileges
        assert container_spec["HostConfig"]["Privileged"] is False
        assert container_spec["HostConfig"]["ReadonlyRootfs"] is True
        assert container_spec["HostConfig"]["CapDrop"] == ["ALL"]
        assert container_spec["HostConfig"]["CapAdd"] == []
        assert container_spec["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"]
        assert container_spec["HostConfig"]["Init"] is True
        assert container_spec["HostConfig"]["Devices"] == []
        assert container_spec["HostConfig"]["DeviceRequests"] == []

        # No network access
        assert container_spec["HostConfig"]["PortBindings"] == {}
        assert container_spec["HostConfig"]["PublishAllPorts"] is False
        assert container_spec["HostConfig"]["GroupAdd"] == []
        assert container_spec["HostConfig"]["IpcMode"] == "private"
        assert container_spec["HostConfig"]["PidMode"] == ""
        assert container_spec["HostConfig"]["UsernsMode"] == ""

    def test_run_container_workspace_mount(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        mounts = container_spec["HostConfig"]["Mounts"]
        assert len(mounts) == 1

        workspace_mount = mounts[0]
        assert workspace_mount["Type"] == "volume"
        assert workspace_mount["Source"] == "ws"
        assert workspace_mount["Target"] == "/workspace"
        assert workspace_mount["ReadOnly"] is False
        assert workspace_mount["VolumeOptions"] == {"NoCopy": True, "Subpath": "companion"}

        # No other mounts
        assert container_spec["HostConfig"]["Binds"] == []
        assert container_spec["HostConfig"]["VolumesFrom"] == []

    def test_run_container_user_and_limits(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        # User
        assert container_spec["User"] == "65533:65533"

        # Memory limits
        assert container_spec["HostConfig"]["Memory"] == 512 * 1024 * 1024
        assert container_spec["HostConfig"]["MemorySwap"] == 512 * 1024 * 1024

        # CPU and process limits
        assert container_spec["HostConfig"]["NanoCpus"] == 1_000_000_000
        assert container_spec["HostConfig"]["PidsLimit"] == 128

        # Ulimits
        ulimits = container_spec["HostConfig"]["Ulimits"]
        fsize_limit = next(u for u in ulimits if u["Name"] == "fsize")
        assert fsize_limit["Soft"] == 512 * 1024 * 1024
        assert fsize_limit["Hard"] == 512 * 1024 * 1024

        nofile_limit = next(u for u in ulimits if u["Name"] == "nofile")
        assert nofile_limit["Soft"] == 1024
        assert nofile_limit["Hard"] == 1024

        core_limit = next(u for u in ulimits if u["Name"] == "core")
        assert core_limit["Soft"] == 0
        assert core_limit["Hard"] == 0

    def test_run_container_tmpfs(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        tmpfs = container_spec["HostConfig"]["Tmpfs"]["/tmp"]
        assert "size=128m" in tmpfs
        assert "nosuid" in tmpfs
        assert "nodev" in tmpfs

    def test_run_container_logging(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        log_config = container_spec["HostConfig"]["LogConfig"]
        assert log_config["Type"] == "json-file"
        assert log_config["Config"]["max-size"] == "4m"
        assert log_config["Config"]["max-file"] == "1"

    def test_run_container_environment(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        env = container_spec["Env"]
        assert any("PATH=" in e for e in env)
        assert "HOME=/tmp" in env
        assert "LANG=C.UTF-8" in env
        assert "TERM=dumb" in env
        assert "CONKER_SANDBOX=1" in env

        # No secrets in environment
        for entry in env:
            name = entry.split("=")[0]
            assert "KEY" not in name
            assert "TOKEN" not in name
            assert "SECRET" not in name
            assert "PASSWORD" not in name
            assert "CREDENTIAL" not in name

    def test_run_container_entrypoint_and_command(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        assert container_spec["Entrypoint"] == ["/bin/bash"]
        assert len(container_spec["Cmd"]) >= 2
        assert container_spec["Cmd"][-2:] == ["/workspace", "ls"]

    def test_run_container_with_cwd(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", "a b"))

        assert container_spec["Cmd"][-2:] == ["/workspace/a b", "ls"]

    def test_run_container_labels(self):
        container_spec = spec.container(self.config, "companion", spec.run_argv("ls", ""))

        labels = container_spec["Labels"]
        assert labels["conker.sandbox"] == "1"
        assert labels["conker.sandbox.agent"] == "companion"
        assert labels["conker.sandbox.kind"] == "run"

    def test_install_container_adds_proxy_mount(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        mounts = container_spec["HostConfig"]["Mounts"]
        assert len(mounts) == 2

        # Workspace mount (first)
        workspace_mount = mounts[0]
        assert workspace_mount["Source"] == "ws"
        assert workspace_mount["Target"] == "/workspace"

        # Proxy mount (second)
        proxy_mount = mounts[1]
        assert proxy_mount["Type"] == "volume"
        assert proxy_mount["Source"] == "px"
        assert proxy_mount["Target"] == "/run/conker-proxy"
        assert proxy_mount["ReadOnly"] is True
        assert proxy_mount["VolumeOptions"] == {"NoCopy": True}

    def test_install_container_still_no_network(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        # Still no network access even for install
        assert container_spec["HostConfig"]["NetworkMode"] == "none"

    def test_install_container_increased_memory(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        # Install gets more memory
        assert container_spec["HostConfig"]["Memory"] == 1024 * 1024 * 1024
        assert container_spec["HostConfig"]["MemorySwap"] == 1024 * 1024 * 1024

    def test_install_container_environment(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        env = container_spec["Env"]
        assert "CONKER_PROXY_SOCKET=/run/conker-proxy/proxy.sock" in env
        assert "CONKER_PROXY_PORT=3128" in env

    def test_install_container_entrypoint_and_command(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        assert container_spec["Entrypoint"] == ["/usr/local/bin/conker-install"]
        assert container_spec["Cmd"] == ["pip", "--", "six"]

    def test_install_container_labels(self):
        container_spec = spec.container(
            self.config, "companion", spec.install_argv("pip", ["six"]), install=True
        )

        labels = container_spec["Labels"]
        assert labels["conker.sandbox"] == "1"
        assert labels["conker.sandbox.agent"] == "companion"
        assert labels["conker.sandbox.kind"] == "install"


class TestArgvBuilders:
    """Test argument list builders for different operations."""

    def test_run_argv(self):
        argv = spec.run_argv("ls -la", "src")
        expected = ["/bin/bash", "-c", spec.RUN, "conker-sandbox", "/workspace/src", "ls -la"]
        assert argv == expected

    def test_run_argv_no_cwd(self):
        argv = spec.run_argv("pwd", "")
        expected = ["/bin/bash", "-c", spec.RUN, "conker-sandbox", "/workspace", "pwd"]
        assert argv == expected

    def test_install_argv(self):
        argv = spec.install_argv("pip", ["requests", "pandas"])
        expected = ["/usr/local/bin/conker-install", "pip", "--", "requests", "pandas"]
        assert argv == expected

    def test_install_argv_npm(self):
        argv = spec.install_argv("npm", ["lodash"])
        expected = ["/usr/local/bin/conker-install", "npm", "--", "lodash"]
        assert argv == expected


class TestEnvironment:
    """Test environment variable generation."""

    def test_run_environment(self):
        env = spec.environment(install=False)

        # Check key variables are present
        env_dict = dict(e.split("=", 1) for e in env)
        assert env_dict["PATH"].startswith("/workspace/.venv/bin")
        assert env_dict["HOME"] == "/tmp"
        assert env_dict["LANG"] == "C.UTF-8"
        assert env_dict["TERM"] == "dumb"
        assert env_dict["CONKER_SANDBOX"] == "1"
        assert env_dict["NODE_PATH"] == "/workspace/node_modules"
        assert env_dict["npm_config_cache"] == "/tmp/.npm"
        assert env_dict["npm_config_update_notifier"] == "false"
        assert env_dict["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
        assert env_dict["PIP_NO_INPUT"] == "1"

        # No proxy variables for run
        assert "CONKER_PROXY_SOCKET" not in env_dict
        assert "CONKER_PROXY_PORT" not in env_dict

    def test_install_environment(self):
        env = spec.environment(install=True)

        env_dict = dict(e.split("=", 1) for e in env)

        # Has proxy variables for install
        assert env_dict["CONKER_PROXY_SOCKET"] == "/run/conker-proxy/proxy.sock"
        assert env_dict["CONKER_PROXY_PORT"] == "3128"


class TestLoweredLimits:
    """The owner's settings may lower memory, CPU and workspace for one command, never raise them."""

    def setup_method(self):
        self.config = spec.Config.from_env({
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
            "SANDBOX_MEMORY_MB": "256",
        })

    def test_no_limits_keep_the_configured_ones(self):
        assert spec.lowered(self.config, None) is self.config
        assert spec.lowered(self.config, {}) == self.config

    def test_lower_values_shape_the_container(self):
        lowered = spec.lowered(self.config, {"memory_mb": 128, "cpus_milli": 500, "workspace_mb": 64})
        assert (lowered.limits.memory_mb, lowered.limits.cpus_milli) == (128, 500)
        assert lowered.limits.workspace_mb == 64
        assert lowered.limits.pids == self.config.limits.pids
        host = spec.container(lowered, "companion", spec.run_argv("ls", ""))["HostConfig"]
        assert host["Memory"] == host["MemorySwap"] == 128 * 1024 * 1024
        assert host["NanoCpus"] == 500_000_000

    def test_a_higher_value_keeps_the_configured_limit(self):
        lowered = spec.lowered(
            self.config, {"memory_mb": 4096, "cpus_milli": 64000, "workspace_mb": 1048576}
        )
        assert lowered.limits == self.config.limits

    @pytest.mark.parametrize(
        "limits",
        [
            {"memory_mb": 63},
            {"cpus_milli": 99},
            {"workspace_mb": 15},
            {"memory_mb": "128"},
            {"memory_mb": True},
            {"memory_mb": 128.0},
            {"pids": 16},
            {"max_seconds": 5},
            ["memory_mb"],
            "128",
        ],
    )
    def test_anything_else_is_refused(self, limits):
        with pytest.raises(spec.ConfigError):
            spec.lowered(self.config, limits)

    def test_the_defaults_are_todays_limits(self):
        defaults = spec.Config.from_env({
            "SANDBOX_IMAGE": "sha256:" + "a" * 64,
            "SANDBOX_WORKSPACES_VOLUME": "ws",
            "SANDBOX_PROXY_VOLUME": "px",
        }).limits
        assert (defaults.memory_mb, defaults.cpus_milli, defaults.workspace_mb) == (
            spec.MEMORY_MB,
            spec.CPUS_MILLI,
            spec.WORKSPACE_MB,
        )
