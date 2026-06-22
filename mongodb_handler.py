from datetime import datetime

from pymongo import MongoClient

from utils import hash_file


def _get_mongo_client():
    CONNECTION_STRING = "mongodb://fukhara:fukhara@localhost:27017/"
    return MongoClient(CONNECTION_STRING)


def _get_db():
    return _get_mongo_client()["fukhara"]


def _get_apk_analysis_collection():
    return _get_db()["apk_analysis"]


def _get_fuzzy_hashes_collection():
    return _get_db()["fuzzy_hashes"]


def create_apk_analysis(path):
    try:
        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())
        _get_apk_analysis_collection().create_index("sha256", unique=True)
        apk_analysis = {"sha256": sha256, "uploaded_at": uploaded_at}
        _get_apk_analysis_collection().insert_one(apk_analysis)
    except:
        pass


def add_fuzzy_hash(sha256, tool, filename, fuzzy_hash):
    try:
        fh = {
            "sha256": sha256,
            "tool": tool,
            "filename": filename,
            "fuzzy_hash": fuzzy_hash,
        }
        _get_fuzzy_hashes_collection().insert_one(fh)
    except:
        pass


def add_tool_analysis(sha256, tool_name, result):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$set": {tool_name: result}}
    )


def list_apk_analyses():
    return _get_apk_analysis_collection().distinct("sha256")


def get_tool_analysis(sha256, tool_name):
    return _get_apk_analysis_collection().find_one({"sha256": sha256}).get(tool_name)


def get_fuzzy_hash_analysis(sha256, tool_name):
    fuzzy_hashes = _get_fuzzy_hashes_collection().find(
        {"sha256": sha256, "tool": tool_name}
    )

    return list(fuzzy_hashes)


def get_apk_analysis_upload_timestamp(sha256):
    return (
        _get_apk_analysis_collection().find_one({"sha256": sha256}).get("uploaded_at")
    )
