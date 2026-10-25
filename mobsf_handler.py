import os

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

from utils import hash_file, resolve_path

MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
MOBSF_DOMAIN = os.getenv("MOBSF_URL", "http://127.0.0.1:8181")


# Upload the APK to MobSF and return its hash, falling back to the local SHA256
def upload_file_to_mobsf(path):
    file, directory = resolve_path(path)

    url = f"{MOBSF_DOMAIN}/api/v1/upload"
    multipart_data = MultipartEncoder(
        fields={"file": (file, open(path, "rb"), "application/octet-stream")}
    )
    headers = {
        "Authorization": MOBSF_API_KEY,
        "Content-Type": multipart_data.content_type,
    }

    try:
        response = requests.post(url, data=multipart_data, headers=headers)

        return response.json()["hash"]
    except Exception:
        return hash_file(path)


# Ask MobSF to scan an uploaded file and return the JSON report
def scan_file_in_mobsf(hash):
    url = f"{MOBSF_DOMAIN}/api/v1/scan"
    headers = {"Authorization": MOBSF_API_KEY}
    data = {"hash": hash}

    try:
        response = requests.post(url, data=data, headers=headers)

        return response.json()
    except Exception:
        print("Couldn't scan file!")
