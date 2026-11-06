# dpdp-scan with Semgrep included.
#
#   docker build -t dpdp-scan .
#   docker run --rm -v "$PWD:/repo" dpdp-scan /repo --format sarif > results.sarif
#
# The scanned repository is mounted read-only at /repo by convention. The image
# makes no network requests and runs as a non-root user.

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install . "semgrep>=1.100"

FROM python:3.12-slim
LABEL org.opencontainers.image.title="dpdp-scan" \
      org.opencontainers.image.description="Finds Indian personal data in code, schemas, fixtures and logs, and points each finding at the DPDP Act obligation it touches." \
      org.opencontainers.image.source="https://github.com/statecheck-security/dpdp-scan" \
      org.opencontainers.image.licenses="Apache-2.0"
# git lets the walker honour .gitignore in a mounted work tree.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner
COPY --from=build /install /usr/local
USER scanner
# A mounted repository is owned by the host user; without this git refuses it
# ("dubious ownership") and the walker falls back to scanning without .gitignore.
RUN git config --global --add safe.directory '*'
WORKDIR /repo
ENV SEMGREP_SEND_METRICS=off \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["dpdp-scan"]
CMD ["/repo"]
