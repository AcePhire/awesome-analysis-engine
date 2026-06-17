import ast
import csv
import hashlib
import io
import json
from pathlib import Path


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
