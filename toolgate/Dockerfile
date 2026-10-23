FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY toolgate/requirements.txt ./toolgate/requirements.txt
# The base image's setuptools and wheel are build tools the service never imports; removing
# them keeps their vendored copies (and their advisories) out of the running image.
RUN pip install --no-cache-dir -r toolgate/requirements.txt \
    && pip uninstall --yes setuptools wheel
COPY toolgate ./toolgate
EXPOSE 8010
CMD ["uvicorn", "toolgate.api.server:app", "--host", "0.0.0.0", "--port", "8010"]
