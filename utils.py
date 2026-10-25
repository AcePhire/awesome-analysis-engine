import ast
import csv
import hashlib
import io
import json
from pathlib import Path


# Return the SHA256 of a file
def hash_file(path):
    with open(Path(path).resolve(), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# Pretty-print a dict, or a string containing a Python dict literal, as JSON
def json_formatter(data):
    valid_dict = data

    if isinstance(data, str):
        valid_dict = ast.literal_eval(data.strip())

    return json.dumps(valid_dict, indent=2)


# Split a path into its file name and parent directory
def resolve_path(path):
    file = Path(path).resolve().name
    directory = Path(path).resolve().parent

    return file, directory


# Convert CSV text to a JSON list of rows
def csv_to_json(data):
    reader = csv.DictReader(io.StringIO(data))

    return json.dumps(list(reader), indent=2)


# Wrap a tool's results with the tool name
def tag_results(tool, results):
    return {
        "tool": tool,
        "tool_results": results,
    }
