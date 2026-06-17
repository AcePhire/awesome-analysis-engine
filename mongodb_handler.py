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


def create_apk_analysis(path):
    try:
        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())
        _get_apk_analysis_collection().create_index("sha256", unique=True)
        apk_analysis = {"sha256": sha256, "uploaded_at": uploaded_at}
        _get_apk_analysis_collection().insert_one(apk_analysis)
    except:
        pass


def add_tool_analysis(sha256, tool_name, result):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$set": {tool_name: result}}
    )


def add_fuzzy_hash(sha256, fuzzy_hash):
    _get_apk_analysis_collection().update_one(
        {"sha256": sha256}, {"$addToSet": {"fuzzy_hashes": fuzzy_hash}}
    )
