# syntax=docker/dockerfile:1


ARG PYTHON_VERSION=3.13.0
FROM python:${PYTHON_VERSION}-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ARG NPM_TOKEN

ENV NPM_TOKEN="${NPM_TOKEN}"

USER root

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    gcc \
    openssh-client \
    curl \
    bash \
    postgresql-client \
    redis-tools \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean


WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN touch README.md



RUN git config --global url."https://${NPM_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"

RUN uv sync --frozen --no-group dev
#RUN uv run pip install --no-binary :all: google-crc32c

FROM python:${PYTHON_VERSION}-slim AS runtime

WORKDIR /app

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src



COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
ADD . /app



EXPOSE 5555

