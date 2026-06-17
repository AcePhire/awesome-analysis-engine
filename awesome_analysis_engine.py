import json
import os
import sys

import docker
import requests
from dotenv import load_dotenv

from mobsf_handler import scan_file_in_mobsf, upload_file_to_mobsf
from postgres_handler import (
    add_apk_analysis,
    add_ssdeep_hash,
    add_tool_analysis,
    get_apk_id,
    initalizeDatabase,
)
from utils import csv_to_json, hash_file, resolve_path

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")


# Load docker daemon
client = docker.from_env()


# Analyze using MobSF
def mobsf_analysis(path):
    file_hash = hash_file(path)

    port = "8181"
    # container = run_mobsf(port)

    try:
        hash = upload_file_to_mobsf(path)
        if hash:
            data = scan_file_in_mobsf(hash)
    except:
        data = "{}"

    add_tool_analysis("MOBSF_ANALYSIS", data, file_hash)
    print("mobsf_analysis.........complete!")

    # container.stop()


# Analyze using APKiD
def apkid_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)

    try:
        container = client.containers.run(
            "rednaga:apkid", volumes=[f"{directory}:/input:ro"], command=f"-j {file}"
        )
        data = json.loads(container.decode("utf-8"))
    except:
        data = "{}"

    add_tool_analysis("APKID_ANALYSIS", data, file_hash)
    print("apkid_analysis.........complete!")


# Analyze using ssdeep
def ssdeep_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)

    try:
        container = client.containers.run(
            "cincan/ssdeep",
            volumes=[f"{directory}:/analysis:ro"],
            command=f"/analysis/{file}",
        )

        csv_data = container.decode("utf-8").strip("ssdeep,1.1--")
        data = json.loads(csv_to_json(csv_data))

        apk_id = get_apk_id(file_hash)
    except:
        data = "{}"

    for file in data:
        filename = file["filename"]
        ssdeep_hash = file["blocksize:hash:hash"]
        add_ssdeep_hash(apk_id, filename, ssdeep_hash)

    print("ssdeep_analysis.........complete!")


# Analyze using Quark Engine
def quark_engine_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)

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

    add_tool_analysis("QUARK_ENGINE_ANALYSIS", data, file_hash)
    print("quark_engine_analysis.........complete!")


# Analyze using AndroCFG
def androcfg_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)

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

    add_tool_analysis("ANDROCFG_ANALYSIS", data, file_hash)
    print("androcfg_analysis.........complete!")


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

    add_tool_analysis("VIRUSTOTAL_ANALYSIS", data, file_hash)
    print("virustotal_analysis.........complete!")


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

    add_tool_analysis("MALWAREBAZAAR_ANALYSIS", data, file_hash)
    print("malwarebazaar_analysis.........complete!")


# Get APK info
def apk_info_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)

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
    add_tool_analysis("APK_INFO_ANALYSIS", data, file_hash)


# Analyze using Yara Analyzer
def yara_analysis(path):
    file, directory = resolve_path(path)
    file_hash = hash_file(path)
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

    add_tool_analysis("YARA_ANALYSIS", data, file_hash)
    print("yara_analysis.........complete!")


# Analyze APK using multiple tools
def analyze(path):
    add_apk_analysis(path)

    mobsf_analysis(path)
    apkid_analysis(path)
    ssdeep_analysis(path)
    quark_engine_analysis(path)
    androcfg_analysis(path)
    virustotal_analysis(path)
    malwarebazaar_analysis(path)
    apk_info_analysis(path)
    yara_analysis(path)


if __name__ == "__main__":
    # test()
    #
    initalizeDatabase()

    if len(sys.argv) == 1:
        # print("No path given!")
        exit()

    path = sys.argv[1]
    analyze(path)
    # report_id = hash_file(path)
    # saveReport(report, f"{report_id}.json")
