from pymongo import MongoClient


class MongoManager:
    def __init__(self, host, port, database, collection, maxSevSelDelay=30):
        mongo_client = MongoClient(
            host=host,
            port=port,
            serverSelectionTimeoutMS=maxSevSelDelay,
        )
        self.handler = mongo_client[database][collection]

    def find(self, query, projection=None):
        cursor = self.handler.find(query, projection=projection, no_cursor_timeout=True)
        return list(cursor) if cursor else None

    def find_one(self, query, projection=None):
        cursor = self.handler.find_one(query, projection=projection)
        return cursor

    def count(self, query):
        result = self.handler.count_documents(query)
        return result

    def insert(self, document):
        self.handler.insert_one(document)

    def update_one(self, query, data):
        self.handler.update_one(query, {"$set": data})

    def update_many(self, query, data):
        self.handler.update_many(query, {"$set": data})
