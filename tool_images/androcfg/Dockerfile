# python-ssdeep, an AndroCFG dependency, does not build on Python 3.14
FROM python:3.11.17-slim

RUN apt-get update && apt-get install -y --no-install-recommends git graphviz build-essential libffi-dev libxml2-dev libxslt1-dev zlib1g-dev libjpeg-dev libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

# ...and only with legacy setuptools
RUN pip install --no-cache-dir "setuptools<70" wheel cffi \
    && pip install --no-cache-dir --no-build-isolation git+https://github.com/U039b/AndroCFG.git@main

COPY androcfg_json.py /usr/local/bin/androcfg_json.py

WORKDIR /work

ENTRYPOINT ["python", "/usr/local/bin/androcfg_json.py"]
