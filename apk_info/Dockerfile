FROM python:3.14.8-slim

WORKDIR /apkinfo
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "apk_info.py"]

# tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py)
COPY --from=zippatch sitecustomize.py /usr/local/lib/python3.14/site-packages/sitecustomize.py
