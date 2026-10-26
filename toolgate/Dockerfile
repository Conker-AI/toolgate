FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
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
