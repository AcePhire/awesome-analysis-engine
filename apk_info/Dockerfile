FROM python:3.14.8-slim

WORKDIR /apkinfo
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "apk_info.py"]
