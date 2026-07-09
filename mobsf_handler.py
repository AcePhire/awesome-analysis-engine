import docker
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

from utils import hash_file, resolve_path

MOBSF_API_KEY = "515d3578262a2539cd13b5b9946fe17e350c321b91faeb1ee56095430242a4a9"
MOBSF_PORT = "8181"
MOBSF_DOMAIN = f"http://127.0.0.1:{MOBSF_PORT}"

client = docker.from_env()


# Start MobSF container
def run_mobsf(port):
    container = client.containers.run(
        "opensecurity/mobile-security-framework-mobsf:latest",
        detach=True,
        environment=["MOBSF_API_ONLY=0", f"MOBSF_API_KEY={MOBSF_API_KEY}"],
        ports={"8000": MOBSF_PORT},
    )

    return container


# Upload file to MobSF
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


# Scan file in MobSF
def scan_file_in_mobsf(hash):
    url = f"{MOBSF_DOMAIN}/api/v1/scan"
    headers = {"Authorization": MOBSF_API_KEY}
    data = {"hash": hash}

    try:
        response = requests.post(url, data=data, headers=headers)

        return response.json()
    except Exception:
        print("Couldn't scan file!")
