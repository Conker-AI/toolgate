# The agent sandbox: what an agent's terminal commands and package installs run in.
#
# Started only by the sandbox runner (toolgate/sandbox/runner.py), one fresh container per
# command, with no network, a read-only root, user 65533, no capabilities and hard limits. The
# image itself carries no secret and no setuid program. Built from the repository root:
#   docker build -f sandbox/Dockerfile sandbox
FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python-is-python3 \
        git ca-certificates jq ripgrep sqlite3 tree file less procps make \
        unzip zip xz-utils bzip2 \
    && rm -rf /var/lib/apt/lists/*

# Common libraries, pinned. Anything else goes through the install tool and the package proxy.
RUN pip3 install --no-cache-dir --break-system-packages \
        numpy==2.4.6 pandas==3.1.0 requests==2.34.2 pyyaml==6.0.3 \
        beautifulsoup4==4.15.0 python-dateutil==3.0.0 openpyxl==3.1.5 \
    && rm -rf /root/.cache

# No setuid or setgid programs, and one unprivileged user the runner always selects.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && userdel --remove node \
    && groupadd --gid 65533 sandbox \
    && useradd --uid 65533 --gid 65533 --no-create-home --home-dir /tmp --shell /bin/bash sandbox \
    && mkdir /workspace && chown 65533:65533 /workspace

COPY --chmod=0755 conker-install /usr/local/bin/conker-install

USER 65533:65533
WORKDIR /workspace
CMD ["/bin/bash"]
