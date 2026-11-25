FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Debian security fixes newer than the base image. The base still ships libzstd1 without the
# CVE-2026-124851 fix (1.5.7+dfsg-1+deb13u1, trixie-security), so the build fails if the upgrade
# did not bring it in. Naming it also changes this layer, so a build cache from before the fix
# cannot be reused. Drop the check once python:3.11-slim ships the fixed version.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libzstd1)" ge 1.5.7+dfsg-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*
COPY toolgate/requirements.txt ./toolgate/requirements.txt
# The base image's setuptools and wheel are build tools the service never imports; removing
# them keeps their vendored copies (and their advisories) out of the running image.
RUN pip install --no-cache-dir -r toolgate/requirements.txt \
    && pip uninstall --yes setuptools wheel
COPY toolgate ./toolgate
# Mount points for the agent sandbox's services (toolgate/sandbox). An empty named volume takes
# its first owner and mode from here: the runner (65533) owns its socket folder and the agent
# workspaces, the package proxy (65532) its own socket folder.
RUN mkdir -p /run/conker-sandbox /run/conker-proxy /workspaces \
    && chown 65533:65533 /run/conker-sandbox /workspaces \
    && chown 65532:65532 /run/conker-proxy \
    && chmod 0755 /run/conker-sandbox /run/conker-proxy \
    && chmod 2770 /workspaces
EXPOSE 8010
CMD ["uvicorn", "toolgate.api.server:app", "--host", "0.0.0.0", "--port", "8010"]
