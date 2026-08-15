import chromadb 
from chromadb import Collection


class LocalChromaClient:
    def connect(self, db_name: str):
        self.client = chromadb.PersistentClient()
        self.collection: Collection = self.client.get_collection(
            name=db_name,
        )
    

class ChromaVectorDB:
    def __init__(self, client, db_name: str = None, embedder=None):
        self.client = client
        self.set_database(db_name)
        # TODO: Implement an embedder...

    def set_database(self, db_name: str):
        self.db_name = db_name

    def query(self, query, filters: dict = None, n_results=12):
        self.client.connect(self.db_name)
        results = self.client.collection.query(
            query_texts=[query],
            n_results=n_results,
            # where={
            #    "$and": [
            #        #{"categories": {"$not_contains": "hardware"}},
            #        #{"categories": {"$not_contains": "operating-system"}},
            #        #{"categories": {"$not_contains": "code-implementation"}},
            #        #{"abstraction": "variant"},
            #        {"mapping": "Allowed"},
            #        {"abstraction": {"$ne": "class"}},
            #    ]
            # },
            # where={
            #    "abstraction": "base"
            # }
            where={"abstraction": {"$ne": "class"}},
        )
        return results

    def add_entry(self, text: str, metadata: dict = None, id: int = None):
        pass

    def delete(self):
        pass