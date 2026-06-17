from pymongo import MongoClient


def get_mongo_client():
    CONNECTION_STRING = "mongodb://fukhara:fukhara@mongo:27017/"
    return MongoClient(CONNECTION_STRING)
