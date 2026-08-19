# Part 3: Use user input or LLM steps (actual RAG)
# to query the vectordb and test the efficacy of all of this
# lol.

import chromadb
from chromadb import Collection
import os
from dotenv import load_dotenv
import json

load_dotenv()


client = chromadb.PersistentClient()

collection: Collection = client.get_collection(
    name="cwe_strict",
)

print("Enter a vulnerability description or keywords.\n")
question = input("query> ")

print(question)

n_results = 12

results = collection.query(
    query_texts=[question],
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

documents = results.get("documents")[0]
metadatas = results.get("metadatas")[0]

for meta in metadatas:
    id = meta["cwe_id"]
    name = meta["name"]
    abstraction = meta["abstraction"]
    mapping = meta["mapping"]
    desc = meta["description"]
    impacts = meta["impacts"]
    print(f"---\n\nCWE-{id}: {name}\n[{abstraction} | {mapping}]\n{desc}\n{impacts}\n")
