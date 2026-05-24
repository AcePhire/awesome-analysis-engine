import sys
import io
from pathlib import Path
import hashlib
import docker
import json, ast
import csv
import os
from dotenv import load_dotenv
from datetime import datetime
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")


MOBSF_API_KEY = "515d3578262a2539cd13b5b9946fe17e350c321b91faeb1ee56095430242a4a9"
MOBSF_PORT = "8181"
MOBSF_DOMAIN = f"http://127.0.0.1:{MOBSF_PORT}"

# Load docker daemon
client = docker.from_env()

# Hash the app file
def hash_file(path):
    with open(Path(path).resolve(), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# Format JSON Output
def json_formatter(data):
    valid_dict = data

    if isinstance(data, str):
        valid_dict = ast.literal_eval(data.strip())

    return json.dumps(valid_dict, indent=2)

# Resolve App Path
def resolve_path(path):
    file = Path(path).resolve().name
    directory = Path(path).resolve().parent

    return file, directory

# CSV to JSON
def csv_to_json(data):
    reader = csv.DictReader(io.StringIO(data))

    return json.dumps(list(reader), indent=2)

# Add metadata to the results
def tag_results(tool, results):
    return {
        "tool": tool,
        "timestamp": str(datetime.now()),
        "tool_results": json.loads(results)
    }

# Save report to a JSON file
def saveReport(report, output_file):
    with open(f"reports/{output_file}", "w") as file:
        json.dump(report, file, indent=2)

def run_mobsf(port):
    container = client.containers.run(
        "opensecurity/mobile-security-framework-mobsf:latest", 
        detach=True, 
        environment=[
            "MOBSF_API_ONLY=0", 
            f"MOBSF_API_KEY={MOBSF_API_KEY}"
        ],
        ports={
            "8000": MOBSF_PORT
        }
    )

    return container

def upload_file_to_mobsf(path):
    file, directory = resolve_path(path)
    
    url = f"{MOBSF_DOMAIN}/api/v1/upload"
    multipart_data = MultipartEncoder(fields={'file': (file, open(path, 'rb'), 'application/octet-stream')})
    headers = { "Authorization": MOBSF_API_KEY, "Content-Type": multipart_data.content_type }

    try:
        response = requests.post(url, data=multipart_data, headers=headers)

        return response.json()["hash"]
    except:
        return hash_file(path)

def scan_file_in_mobsf(hash):
    url = f"{MOBSF_DOMAIN}/api/v1/scan"
    headers = { "Authorization": MOBSF_API_KEY }
    data = { "hash": hash }

    try:
        with open(path, "rb") as file:
            response = requests.post(url, data=data, headers=headers)

            return response.json()
    except:
        print("Couldn't scan file!")

# Analyze using MobSF
def mobsf_analysis(path):
    file, directory = resolve_path(path)

    port = "8181"
    #container = run_mobsf(port)
 
    try:
        hash = upload_file_to_mobsf(path)

        if hash:
            data = scan_file_in_mobsf(hash)
    except:
        data = "{}"

    print("mobsf_analysis.........complete!")
    return tag_results("mobsf", json_formatter(data))

    #container.stop()

# Analyze using APKiD
def apkid_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "rednaga:apkid",
            volumes=[f"{directory}:/input:ro"],
            command=f"-j {file}"
        )
        data = container.decode("utf-8")
    except:
        data = "{}"

    print("apkid_analysis.........complete!")
    return tag_results("apkid", data)

# Analyze using ssdeep
def ssdeep_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "cincan/ssdeep", 
            volumes=[f"{directory}:/analysis:ro"], 
            command=f"/analysis/{file}"
        )
        
        csv_data = container.decode("utf-8").strip("ssdeep,1.1--")
        data = csv_to_json(csv_data)
    except:
        data = "{}"

    print("ssdeep_analysis.........complete!")
    return tag_results("ssdeep", data)

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
                f"pipenv run quark -a /analysis/{file} -o output.json > /dev/null && cat output.json"
            ]
        )
        
        data = container.decode("utf-8")
    except:
        data = "{}"

    print("quark_engine_analysis.........complete!")
    return tag_results("quark_engine", data)


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
                f"AndroCFG -a /analysis/{file} -o output && cat output/report.json"
            ]
        )

        data = container.decode("utf-8")
    except:
        data = "{}"
    
    print("androcfg_analysis.........complete!")
    return tag_results("androcfg", data)

# Analyze using VirusTotal
def virustotal_analysis(path):
    file_hash = hash_file(path)
    
    try:
        container = client.containers.run(
            "acephire/virustotal", 
            command=[
                VIRUSTOTAL_API_KEY,
                file_hash
            ]
        )

        data = container.decode("utf-8")
    except:
        data = "{}"

    print("virustotal_analysis.........complete!")
    return tag_results("virustotal", json_formatter(data))


# Analyze using Malware Bazaar
def malwarebazaar_analysis(path):
    file_hash = hash_file(path)

    try:
        container = client.containers.run(
            "acephire/malwarebazaar", 
            command=[
                MALWAREBAZAAR_API_KEY,
                file_hash
            ]
        )

        data = container.decode("utf-8")
        if "File not found!" in data:
            data = "{}"

    except:
        data = "{}"
    
    print("malwarebazaar_analysis.........complete!")
    return tag_results("malware_bazaar", json_formatter(data))

# Get APK info
def apk_info_analysis(path):
    file, directory = resolve_path(path)

    try:
        container = client.containers.run(
            "acephire/apk_info",
            volumes=[f"{directory}:/analysis:ro"],
            command=f"/analysis/{file}"
        )
    
        data = container.decode("utf-8")
    except:
        data = "{}"

    print("apk_info_analysis.........complete!")
    return tag_results("apk_info", data)

# Analyze using Yara Analyzer
def yara_analysis(path):
    file, directory = resolve_path(path)
    rules_path = "/home/acephire/Documents/projects/awesome-analysis-engine/yara_analyzer/rules/"

    try:
        container = client.containers.run(
            "acephire/yara_analyzer", 
            volumes=[
                f"{directory}:/analysis:ro",
                f"{rules_path}:/rules/:ro"
            ], 
            command=[
                f"/analysis/{file}",
                "/rules/android.yara"
            ]
        )

        data = container.decode("utf-8")
    except:
        data = "{}"

    print("yara_analysis.........complete!")
    return tag_results("yara_analyzer", data)

# Analyze APK using multiple tools
def analyze(path):
    report = [
        mobsf_analysis(path),
        apkid_analysis(path), 
        ssdeep_analysis(path),
        quark_engine_analysis(path),
        androcfg_analysis(path),
        virustotal_analysis(path),
        malwarebazaar_analysis(path),
        apk_info_analysis(path),
        yara_analysis(path)
    ]

    return report

def test():
    if len(sys.argv) == 1:
        print("No module specified!")
        exit()

    if len(sys.argv) == 2:
        print("No path given!")
        exit()

    path = sys.argv[2]

    if sys.argv[1] == "apkid":
        output = apkid_analysis(path)

    elif sys.argv[1] == "ssdeep":
        output = run_ssdeep(path)

    elif sys.argv[1] == "quark":
        output = quark_engine_analysis(path)

    elif sys.argv[1] == "androcfg":
        output = androcfg_analysis(path)

    elif sys.argv[1] == "virustotal":
        output = virustotal_analysis(path) 

    elif sys.argv[1] == "malwarebazaar":
        output = malwarebazaar_analysis(path)

    elif sys.argv[1] == "apk_info":
        output = apk_info_analysis(path)

    elif sys.argv[1] == "loki":
        output = loki_analysis(path)
    elif sys.argv[1] == "all":
        output = run_all(path)
    else:
        print("Invalid module!")
        exit()

    print(json_formatter(output))

if __name__ == "__main__":
    #test()

    if len(sys.argv) == 1:
        print("No path given!")
        exit()

    path = sys.argv[1]
    report = analyze(path)
    report_id = hash_file(path)
    saveReport(report, f"{report_id}.json")
