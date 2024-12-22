import os
from pymongo import MongoClient,  ASCENDING


def setup_mongo():
    mongo_client = MongoClient(
        host=os.getenv("DATABASE_HOST"),
        port=int(os.getenv("DATABASE_PORT")),
        username=os.getenv("DATABASE_USERNAME"),
        password=os.getenv("DATABASE_PASSWORD")
    )
    db = mongo_client[os.getenv("DATABASE_NAME")]
    collection = db[os.getenv("COLLECTION_NAME")]
    collection.create_index([("user_id", ASCENDING)], unique=True)

    return collection


def mongo_insert_one(user_id, data: dict):
    collection = setup_mongo()
    collection.insert_one(data)
    final_result: dict = collection.find_one({"user_id": user_id}, {"_id": 0})
    return final_result


def mongo_find_all():
    collection = setup_mongo()
    result = collection.find()
    return result


def mongo_find_by_user_id(user_id):
    collection = setup_mongo()
    return collection.find_one({"user_id": user_id}, {"_id": 0})


def mongo_update_one(user_id, query):
    collection = setup_mongo()
    filter = {"user_id": user_id}
    new_values = {"$set": query}
    return collection.update_one(filter, new_values)


def mongo_delete_one(user_id):
    collection = setup_mongo()
    filter = {"user_id": user_id}
    return collection.delete_one(filter)

