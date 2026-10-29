# LogSentry image: one image, two processes (`logsentry tail` and `logsentry web`, see compose).
# Build context is the repo root: docker build -f docker/Dockerfile .

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv
# Bytecode is compiled here because the runtime filesystem is read-only.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Dependencies first, so editing src/ doesn't reinstall them.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY config ./config
# An empty named volume mounted at /data takes this owner, so the non-root user can write the DB.
RUN mkdir /data && chown 10001:10001 /data
USER 10001
ENTRYPOINT ["logsentry"]
CMD ["--help"]
