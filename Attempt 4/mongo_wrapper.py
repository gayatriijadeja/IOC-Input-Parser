import pymongo


class MongoWrapper:
    def __init__(self, database_name, collection_name):
        try:

            self.client = pymongo.MongoClient(
                "mongodb+srv://gayatriba2002:Gayu2002!@cluster0.xdltget.mongodb.net/?retryWrites=true&w=majority"
            )
            self.client.admin.command("ping")
            print("Pinged your deployment. You successfully connected to MongoDB!")
            self.db = self.client[database_name]
            self.collection = self.db[collection_name]
        except Exception as e:
            print(f"Error connecting to MongoDB: {e}")
            self.client = None
            self.db = None
            self.collection = None

    def insert_one(self, data):
        if self.collection is None:
            return False

        try:
            self.collection.insert_one(data)
            return True
        except Exception as e:
            print(f"Error inserting data: {e}")
            return False
