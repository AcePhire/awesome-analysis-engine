FROM python:3.11-slim

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
