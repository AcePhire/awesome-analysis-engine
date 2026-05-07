FROM python:3.11-slim

WORKDIR /apkinfo
COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "apk_info.py"]
