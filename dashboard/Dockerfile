FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
# Tailwind's optional native packages are platform-specific; disable lifecycle
# downloads in the production build while resolving the locked dependency tree.
RUN npm install --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
# The base image's setuptools and wheel are build tools the service never imports; removing
# them keeps their vendored copies (and their advisories) out of the running image.
RUN pip install --no-cache-dir fastapi==0.138.2 uvicorn==0.49.0 \
    && pip uninstall --yes setuptools wheel
COPY server.py ./server.py
COPY --from=build /app/dist ./dist
EXPOSE 8011
CMD ["python", "server.py"]
