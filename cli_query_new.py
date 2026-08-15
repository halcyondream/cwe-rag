# Part 3: Use user input or LLM steps (actual RAG)
# to query the vectordb and test the efficacy of all of this
# lol.

from dotenv import load_dotenv
from vectordbs import ChromaVectorDB, LocalChromaClient

load_dotenv()

vectordb = ChromaVectorDB(LocalChromaClient())
vectordb.set_database("cwe_strict")

print("Enter a vulnerability description or keywords.\n")
question = input("query> ")

results = vectordb.query(question)

documents = results.get("documents")[0]
metadatas = results.get("metadatas")[0]

for meta in metadatas:
    id = meta["cwe_id"]
    name = meta["name"]
    abstraction = meta["abstraction"]
    mapping = meta["mapping"]
    desc = meta["description"]
    impacts = meta["impacts"]
    print(
        "---\n\n"
        f"CWE-{id}: {name}\n"
        f"[{abstraction} | {mapping}]\n"
        f"{desc}\n"
        f"{impacts}\n"
    )
