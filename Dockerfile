FROM python:3.14.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APK_DIR=/data/apk_files

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py)
COPY --from=zippatch sitecustomize.py /usr/local/lib/python3.14/site-packages/sitecustomize.py

EXPOSE 8000

# Runs as root: the API launches the analysis tool containers through the
# mounted Docker socket.
CMD ["uvicorn", "fukhara_api:app", "--host", "0.0.0.0", "--port", "8000"]
