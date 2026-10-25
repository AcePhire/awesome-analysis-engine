import json
import os
import shutil
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import docker
import requests
from dotenv import load_dotenv

from mobsf_handler import scan_file_in_mobsf, upload_file_to_mobsf
from utils import csv_to_json, hash_file

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

APK_DIR = Path(os.getenv("APK_DIR", "apk_files")).resolve()
APK_VOLUME = os.getenv("APK_VOLUME", str(APK_DIR))
TOOL_VOLUMES = {APK_VOLUME: {"bind": "/analysis", "mode": "ro"}}

client = docker.from_env()


# Map a local APK path to its path inside the tool containers
def tool_path(path):
    return f"/analysis/{Path(path).resolve().relative_to(APK_DIR)}"


# Upload and scan the APK with MobSF
def mobsf_analysis(path):
    port = "8181"

    try:
        hash = upload_file_to_mobsf(path)
        if hash:
            data = scan_file_in_mobsf(hash)
    except Exception:
        data = "{}"

    print("mobsf_analysis.........complete!")
    return data


# Run APKiD in a container to identify packers, obfuscators and compilers
def apkid_analysis(path):
    try:
        container = client.containers.run(
            "fukhara/apkid",
            volumes=TOOL_VOLUMES,
            remove=True,
            command=["-j", tool_path(path)],
        )
        data = json.loads(container.decode("utf-8"))
    except Exception:
        data = "{}"

    print("apkid_analysis.........complete!")
    return data


# Extract the DEX files, manifest and resources, then fuzzy hash them and the APK with ssdeep
def ssdeep_analysis(path):
    with TemporaryDirectory(dir=APK_DIR) as tmp_dir:
        with zipfile.ZipFile(path, "r") as apk:
            file_list = apk.namelist()

            for file in file_list:
                try:
                    if file.endswith(".dex"):
                        apk.extract(file, tmp_dir)
                except Exception:
                    pass

            try:
                apk.extract("AndroidManifest.xml", tmp_dir)
                apk.extract("resources.arsc", tmp_dir)
            except Exception:
                pass

            shutil.copy(path, tmp_dir)

        try:
            container = client.containers.run(
                "fukhara/ssdeep",
                volumes=TOOL_VOLUMES,
                remove=True,
                working_dir=tool_path(tmp_dir),
                command=[f.name for f in Path(tmp_dir).iterdir()],
            )

            csv_data = container.decode("utf-8").strip("ssdeep,1.1--")
            data = json.loads(csv_to_json(csv_data))
        except Exception:
            data = "{}"

    ssdeep_hashes = []
    for file in data:
        filename = file["filename"].removeprefix("/analysis/")
        ssdeep_hash = file["blocksize:hash:hash"]
        ssdeep_hashes.append((filename, ssdeep_hash))

    print("ssdeep_analysis.........complete!")
    return ssdeep_hashes


# Run Quark Engine in a container to detect malicious behaviors
def quark_engine_analysis(path):
    try:
        container = client.containers.run(
            "fukhara/quark-engine",
            volumes=TOOL_VOLUMES,
            remove=True,
            entrypoint="",
            command=[
                "/bin/sh",
                "-c",
                f"quark -a {tool_path(path)} -o output.json > /dev/null && cat output.json",
            ],
        )

        data = json.loads(container.decode("utf-8"))
    except Exception:
        data = "{}"

    print("quark_engine_analysis.........complete!")
    return data


# Run AndroCFG in a container to extract control-flow and call-graph rules
def androcfg_analysis(path):
    try:
        container = client.containers.run(
            "fukhara/androcfg",
            volumes=TOOL_VOLUMES,
            remove=True,
            command=[tool_path(path)],
        )

        data = json.loads(container.decode("utf-8"))
    except Exception:
        data = "{}"

    print("androcfg_analysis.........complete!")
    return data


# Look up the APK's hash on VirusTotal
def virustotal_analysis(path):
    file_hash = hash_file(path)

    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers)

        data = response.json()
    except Exception:
        data = "{}"

    print("virustotal_analysis.........complete!")
    return data


# Look up the APK's hash on MalwareBazaar
def malwarebazaar_analysis(path):
    file_hash = hash_file(path)

    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}
    data_query = {"query": "get_info", "hash": file_hash}
    url = "https://mb-api.abuse.ch/api/v1/"

    try:
        response = requests.post(url, data=data_query, headers=headers)

        data = response.json()
    except Exception:
        data = "{}"

    print("malwarebazaar_analysis.........complete!")
    return data


# Run the apk_info container to extract metadata, signature and classes
def apk_info_analysis(path):
    try:
        container = client.containers.run(
            "fukhara/apk_info",
            volumes=TOOL_VOLUMES,
            remove=True,
            command=[tool_path(path)],
        )

        data = json.loads(container.decode("utf-8"))
    except Exception:
        data = "{}"

    print("apk_info_analysis.........complete!")
    return data


# Run the YARA analyzer container with the bundled Android rules
def yara_analysis(path):
    try:
        container = client.containers.run(
            "fukhara/yara_analyzer",
            volumes=TOOL_VOLUMES,
            remove=True,
            command=[tool_path(path), "/yara_analyzer/rules/android.yara"],
        )

        data = json.loads(container.decode("utf-8"))
    except Exception:
        data = "{}"

    print("yara_analysis.........complete!")
    return data
