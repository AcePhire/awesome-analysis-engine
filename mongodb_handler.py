import os
from datetime import datetime

from pymongo import MongoClient

from utils import hash_file

CONNECTION_STRING = os.getenv("MONGO_URI", "mongodb://fukhara:fukhara@localhost:27017/")

_mongo_client = MongoClient(CONNECTION_STRING)


def _get_mongo_client():
    return _mongo_client


def _get_db():
    return _get_mongo_client()["fukhara"]


def _get_apk_analysis_collection():
    return _get_db()["apk_analysis"]


def get_fuzzy_hashes_collection():
    return _get_db()["fuzzy_hashes"]


def create_apk_analysis(path):
    try:
        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())
        _get_apk_analysis_collection().create_index("sha256", unique=True)
        apk_analysis = {
            "sha256": sha256,
            "uploaded_at": uploaded_at,
            "status": "pending",
            "tools_done": [],
        }
        _get_apk_analysis_collection().insert_one(apk_analysis)
    except Exception:
        # Re-submitting a known APK: re-run the analysis on the same document
        _get_apk_analysis_collection().update_one(
            {"sha256": sha256}, {"$set": {"status": "pending", "tools_done": []}}
        )

    return sha256


def add_fuzzy_hash(sha256, tool, filename, fuzzy_hash):
    try:
        fh = {
            "sha256": sha256,
            "tool": tool,
            "filename": filename,
            "fuzzy_hash": fuzzy_hash,
        }
        get_fuzzy_hashes_collection().create_index(
            [("sha256", 1), ("tool", 1), ("filename", 1), ("fuzzy_hash", 1)],
            unique=True,
        )
        get_fuzzy_hashes_collection().insert_one(fh)
    except Exception:
        pass


def add_tool_analysis(sha256, tool_name, result):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$set": {tool_name: result}}
    )


def mark_tool_done(sha256, tool_name):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$addToSet": {"tools_done": tool_name}}
    )


def list_apk_analyses():
    return _get_apk_analysis_collection().distinct("sha256")


def get_tool_analysis(sha256, tool_name):
    return _get_apk_analysis_collection().find_one({"sha256": sha256}).get(tool_name)


def get_fuzzy_hash_analysis(sha256, tool_name):
    return get_fuzzy_hashes_collection().find({"sha256": sha256, "tool": tool_name})


def get_analysis_status(sha256):
    return _get_apk_analysis_collection().find_one({"sha256": sha256}).get("status")


def get_analysis_progress(sha256):
    return _get_apk_analysis_collection().find_one(
        {"sha256": sha256},
        {"_id": 0, "sha256": 1, "status": 1, "uploaded_at": 1, "tools_done": 1},
    )


def get_analysis_upload_timestamp(sha256):
    return (
        _get_apk_analysis_collection().find_one({"sha256": sha256}).get("uploaded_at")
    )


def set_analysis_status(sha256, status):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$set": {"status": status}}
    )
