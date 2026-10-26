"""The agent sandbox: terminal commands and package installs in locked-down containers.

ToolGate never holds the Docker socket for this. It sends typed requests over a Unix socket to
the sandbox runner (`runner.py`), a separate networkless service that alone talks to Docker and
builds every container from a fixed specification (`spec.py`). Installs reach the registries only
through the package proxy (`proxy.py`). See docs/sandbox.md.
"""
