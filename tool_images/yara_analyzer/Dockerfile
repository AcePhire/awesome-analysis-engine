FROM python:3.14.8-slim

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /yara_analyzer
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "yara_analyzer.py"]

# tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py)
COPY --from=zippatch sitecustomize.py /usr/local/lib/python3.14/site-packages/sitecustomize.py
