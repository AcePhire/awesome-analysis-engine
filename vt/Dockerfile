from python:3.11-slim

RUN pip install vt-py

WORKDIR /vt
COPY . .

ENTRYPOINT ["python", "virustotal.py"]
