import ast
import csv
import hashlib
import io
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from venv import create

import docker
import psycopg2
import requests
from dotenv import load_dotenv
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


# Connect to PostgreSQL
def initalizeDatabase():
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        create_apk_analysis_table_query = """
        CREATE TABLE IF NOT EXISTS apk_analysis (
                ID INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY NOT NULL,
                SHA256 VARCHAR(64) UNIQUE NOT NULL,
                UPLOADED_AT TIMESTAMP NOT NULL,
                APK_FILENAME VARCHAR(255) NULL,
                ANALYSIS_RESULTS JSONB[]);
        """
        cursor.execute(create_apk_analysis_table_query)
        connection.commit()
        print("apk_analysis table created!")

        create_fuzzy_hash_table_query = """
        CREATE TABLE IF NOT EXISTS fuzzy_hash (
                ID INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY NOT NULL,
                FILENAME VARCHAR(255) NOT NULL,
                HASH VARCHAR UNIQUE NOT NULL,
                APK_ID INT NOT NULL,
                FOREIGN KEY (APK_ID) REFERENCES apk_analysis(ID));
        """
        cursor.execute(create_fuzzy_hash_table_query)
        connection.commit()
        print("fuzzy_hash table created!")
    except Exception as e:
        print("Failed to initialize database!")
        print(e)


def add_apk_analysis(path):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())

        insert_query = f"""
        INSERT INTO apk_analysis (SHA256, UPLOADED_AT)
        VALUES ('{sha256}', '{uploaded_at}')
        ON CONFLICT (SHA256) DO NOTHING
        """
        cursor.execute(insert_query)
        connection.commit()

    except Exception as e:
        print("Failed to add apk analysis!")
        print(e)


def add_ssdeep_hash(apk_id, filename, ssdeep_hash):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        insert_query = f"""
        INSERT INTO fuzzy_hash (FILENAME, HASH, APK_ID)
        VALUES ('{filename}', '{ssdeep_hash}', '{apk_id}')
        ON CONFLICT (HASH) DO NOTHING
        """
        cursor.execute(insert_query)
        connection.commit()

    except Exception as e:
        print("Failed to add ssdeep hash!")
        print(e)


def add_tool_analysis(tool, results, file_hash):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        tagged_results = tag_results(tool, results)

        update_query = f"""
        UPDATE apk_analysis
        SET ANALYSIS_RESULTS = ANALYSIS_RESULTS || %s::jsonb
        WHERE sha256 = '{file_hash}'
        """
        cursor.execute(update_query, (json.dumps(tagged_results),))
        connection.commit()

    except Exception as e:
        print(f"Failed to add {tool}!")
        print(e)


def get_apk_id(file_hash):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        select_query = f"""
        SELECT (ID) FROM apk_analysis
        WHERE SHA256 = '{file_hash}'
        """
        cursor.execute(select_query)
        connection.commit()

        apk_id = cursor.fetchone()[0]
        return apk_id

    except Exception as e:
        print(f"Failed to get apk ID!")
        print(e)


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
        "tool_results": results,
    }


# Save report to a JSON file
def saveReport(report, output_file):
    with open(f"reports/{output_file}", "w") as file:
        json.dump(report, file, indent=2)


def run_mobsf(port):
    container = client.containers.run(
        "opensecurity/mobile-security-framework-mobsf:latest",
        detach=True,
        environment=["MOBSF_API_ONLY=0", f"MOBSF_API_KEY={MOBSF_API_KEY}"],
        ports={"8000": MOBSF_PORT},
    )

    return container


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
    except:
        return hash_file(path)


def scan_file_in_mobsf(hash):
    url = f"{MOBSF_DOMAIN}/api/v1/scan"
    headers = {"Authorization": MOBSF_API_KEY}
    data = {"hash": hash}

    try:
        response = requests.post(url, data=data, headers=headers)

        return response.json()
    except:
        print("Couldn't scan file!")


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
