FROM python:3.14.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends git graphviz \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir quark-engine==26.10.1 \
    && freshquark

WORKDIR /work

ENTRYPOINT ["quark"]

# tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py)
COPY --from=zippatch sitecustomize.py /usr/local/lib/python3.14/site-packages/sitecustomize.py
