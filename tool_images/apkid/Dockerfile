FROM python:3.14.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && pip install --no-cache-dir apkid==3.1.0 \
    && apt-get purge -y gcc libc6-dev && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["apkid"]

# tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py)
COPY --from=zippatch sitecustomize.py /usr/local/lib/python3.14/site-packages/sitecustomize.py
