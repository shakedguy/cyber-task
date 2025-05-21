# syntax=docker/dockerfile:1


ARG PYTHON_VERSION=3.13.0
FROM python:${PYTHON_VERSION}-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

USER root

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN touch README.md


RUN uv sync --frozen
#RUN uv run pip install --no-binary :all: google-crc32c

FROM python:${PYTHON_VERSION}-slim AS runtime

WORKDIR /app

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src



COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
ADD . /app
