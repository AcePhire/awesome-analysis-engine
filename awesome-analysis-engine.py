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

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

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
    with open(f"/reports/{output_file}", "w") as file:
        json.dump(report, file, indent=2)

def run_mobsf():
    container = client.containers.run("opensecurity/mobile-security-framework-mobsf:latest", detach=True, environment=["MOBSF_API_ONLY=0", "MOBSF_API_KEY=515d3578262a2539cd13b5b9946fe17e350c321b91faeb1ee56095430242a4a9"])

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

    return tag_results("apk_info", data)

# Analyze using LOKI-RS
def loki_analysis(path):
    file, directory = resolve_path(path)

    container = client.containers.run(
        "acephire/loki-rs", 
        volumes=[f"{directory}:/analysis:ro"], 
        command=[
            "/bin/bash", 
            "-c", 
            "./loki-util update > /dev/null && ./loki --no-tui --no-log --no-html --no-procs -f /analysis/ -j output.json > /dev/null && cat output.json"
        ]
    )

    data = container.decode("utf-8")
    return tag_results("loki", data)

# Analyze APK using multiple tools
def analyze(path):
    report = [
        apkid_analysis(path), 
        ssdeep_analysis(path),
        quark_engine_analysis(path),
        androcfg_analysis(path),
        virustotal_analysis(path),
        malwarebazaar_analysis(path),
        apk_info_analysis(path)
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
