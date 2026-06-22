import json
import os
import timeit
from datetime import datetime

import docker
import requests
from dotenv import load_dotenv

from mobsf_handler import scan_file_in_mobsf, upload_file_to_mobsf
from utils import csv_to_json, hash_file, resolve_path

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

# Load docker daemon
client = docker.from_env()


# Analyze using MobSF
def mobsf_analysis(path):
    port = "8181"
    # container = run_mobsf(port)

    try:
        hash = upload_file_to_mobsf(path)
        if hash:
            data = scan_file_in_mobsf(hash)
    except:
        data = "{}"

    print("mobsf_analysis.........complete!")
    return data

    # container.stop()


# Analyze using APKiD
def apkid_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "rednaga:apkid", volumes=[f"{directory}:/input:ro"], command=f"-j {file}"
        )
        data = json.loads(container.decode("utf-8"))
    except:
        data = "{}"

    print("apkid_analysis.........complete!")
    return data


# Analyze using ssdeep
def ssdeep_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "cincan/ssdeep",
            volumes=[f"{directory}:/analysis:ro"],
            command=f"/analysis/{file}",
        )

        csv_data = container.decode("utf-8").strip("ssdeep,1.1--")
        data = json.loads(csv_to_json(csv_data))
    except:
        data = "{}"

    ssdeep_hashes = []
    for file in data:
        filename = file["filename"]
        ssdeep_hash = file["blocksize:hash:hash"]
        ssdeep_hashes.append((filename, ssdeep_hash))

    print("ssdeep_analysis.........complete!")
    return ssdeep_hashes


# Analyze using Quark Engine
def quark_engine_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "ev-flow/quark-engine",
            volumes=[f"{directory}:/analysis:ro"],
            entrypoint="",
            command=[
                "/bin/bash",
                "-c",
                f"pipenv run quark -a /analysis/{file} -o output.json > /dev/null && cat output.json",
            ],
        )

        data = json.loads(container.decode("utf-8"))
    except Exception as e:
        print(e)
        data = "{}"

    print("quark_engine_analysis.........complete!")
    return data


# Analyze using AndroCFG
def androcfg_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "u039b/androcfg",
            volumes=[f"{directory}:/analysis:ro"],
            command=[
                "/bin/bash",
                "-c",
                f"AndroCFG -a /analysis/{file} -o output && cat output/report.json",
            ],
        )

        data = json.loads(container.decode("utf-8"))
    except:
        data = "{}"

    print("androcfg_analysis.........complete!")
    return data


# Analyze using VirusTotal
def virustotal_analysis(path):
    file_hash = hash_file(path)

    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers)

        data = response.json()
    except:
        data = "{}"

    print("virustotal_analysis.........complete!")
    return data


# Analyze using Malware Bazaar
def malwarebazaar_analysis(path):
    file_hash = hash_file(path)

    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}
    data_query = {"query": "get_info", "hash": file_hash}
    url = "https://mb-api.abuse.ch/api/v1/"

    try:
        response = requests.post(url, data=data_query, headers=headers)

        data = response.json()
    except:
        data = "{}"

    print("malwarebazaar_analysis.........complete!")
    return data


# Get APK info
def apk_info_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "acephire/apk_info",
            volumes=[f"{directory}:/analysis:ro"],
            command=f"/analysis/{file}",
        )

        data = json.loads(container.decode("utf-8"))
    except:
        data = "{}"

    print("apk_info_analysis.........complete!")
    return data


# Analyze using Yara Analyzer
def yara_analysis(path):
    file, directory = resolve_path(path)
    rules_path = (
        "/home/acephire/Documents/projects/awesome-analysis-engine/yara_analyzer/rules/"
    )

    try:
        container = client.containers.run(
            "acephire/yara_analyzer",
            volumes=[f"{directory}:/analysis:ro", f"{rules_path}:/rules/:ro"],
            command=[f"/analysis/{file}", "/rules/android.yara"],
        )

        data = json.loads(container.decode("utf-8"))
    except:
        data = "{}"

    print("yara_analysis.........complete!")
    return data
