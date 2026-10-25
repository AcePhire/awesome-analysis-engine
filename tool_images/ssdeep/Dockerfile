FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends ssdeep \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["ssdeep"]
