# syntax=docker/dockerfile:1
ARG KINSHIP_INSTALL=pypi
FROM rust:1.85.1-slim-bookworm AS rust

FROM python:3.13-slim AS builder
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir 'maturin>=1.9,<2'
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    maturin build --release --interpreter python3 --out /wheels

FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN pip install --no-cache-dir uvicorn httpx

FROM runtime AS source
COPY --from=builder /wheels /wheels
RUN for wheel in /wheels/*.whl; do pip install --no-cache-dir "${wheel}[fastapi]"; done \
    && rm -rf /wheels

# The default: the published package. --build-arg KINSHIP_INSTALL=source builds this checkout.
FROM runtime AS pypi
RUN pip install --no-cache-dir 'kinship[fastapi]>=0.3'

FROM ${KINSHIP_INSTALL} AS demo
COPY deploy/compose/*.py deploy/compose/dashboard.html ./
USER 10001:10001
EXPOSE 7946/tcp 7946/udp 8000/tcp 8080/tcp
CMD ["uvicorn", "node:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "5"]
