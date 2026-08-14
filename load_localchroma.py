"""
Load markdown + topmatter into a local Chroma vector database.
"""

import chromadb
from chromadb import Collection
from chromadb.utils.embedding_functions.ollama_embedding_function import (
    OllamaEmbeddingFunction,
)
from pathlib import Path
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language
import os
import yaml

md_files = Path(os.environ.get("OUTPUT_FOLDER_MD")).rglob("cwe**.md")
ollama_host = os.environ.get("OLLAMA_HOST")
embedding_model = os.environ.get("EMBEDDING_MODEL")

ollama_embedding_function = OllamaEmbeddingFunction(
    url=ollama_host, model_name=embedding_model
)

client = chromadb.PersistentClient()

collection: Collection = client.get_or_create_collection(
    name="cwe_strict",
    embedding_function=ollama_embedding_function,
    metadata={"hnsw:space": "cosine"},
)


splitter = RecursiveCharacterTextSplitter.from_language(language=Language.MARKDOWN)


def extract_topmatter(text):
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return {}, text
    for i, line in enumerate(lines[1:], start=1):
        if line.rstrip("\r\n") in {"---", "..."}:
            metadata = yaml.safe_load("".join(lines[1:i])) or {}
            return metadata, "".join(lines[i + 1 :]).strip()
    raise ValueError("Unclosed YAML topmatter")


def parse_consequences(cwe_consequences):
    prepare = lambda x: [x] if type(x) == str else x
    scopes = []
    impacts = []
    notes = []
    for consequence in cwe_consequences:
        scopes += prepare(consequence["scope"])
        impacts += prepare(consequence["impact"])
        notes += prepare(consequence["note"])
    return {"scopes": scopes, "impacts": impacts, "notes": notes}


def get_keywords(cwe_json: dict) -> list[str]:
    keywords = []
    keywords += iter_values(cwe_json["platform_info"])
    return keywords


def iter_values(obj) -> list[str]:
    """
    Return a list of all non-null values in a dict. Omits keys entirely.
    TODO: Rename this function lol.
    """

    def _deep_extract(obj):
        """
        Helper function to perform a deep extract of all values in a dict.
        """
        if isinstance(obj, dict):
            for value in obj.values():
                yield from iter_values(value)
        elif isinstance(obj, list):
            for item in obj:
                yield from iter_values(item)
        else:
            yield obj

    # Return non-null items.
    return [str(e) for e in list(_deep_extract(obj)) if e]


for doc_idx, cwe_file in enumerate(md_files):

    with open(cwe_file) as f:
        content = f.read()
        topmatter, cwe_md = extract_topmatter(content)
    cwe_id = topmatter["id"]
    cwe_name = topmatter["name"]
    cwe_abstraction = topmatter["abstraction"]
    cwe_description = topmatter["description"]
    cwe_mapping = topmatter["mapping"]

    # Restructure keyword lists as a cleartext string
    # Use chromadb's `$not_contains` to filer out irrelevant keywords
    # or `$contains` to target known relevant ones.
    cwe_consequences = parse_consequences(topmatter["consequences"])

    cwe_keywords = get_keywords(topmatter)

    print(cwe_id, cwe_name)

    chunks = splitter.split_text(cwe_md)

    for chunk_idx, chunk in enumerate(chunks):
        collection.add(
            documents=chunk,
            ids=f"cwe_{doc_idx+1}_{chunk_idx+1}",
            metadatas={
                "cwe_id": cwe_id,
                "name": cwe_name,
                "impact_scopes": cwe_consequences["scopes"] or [""],
                "impacts": cwe_consequences["impacts"] or [""],
                "impact_notes": cwe_consequences["notes"] or [""],
                "keywords": cwe_keywords or "",
                "abstraction": cwe_abstraction,
                "mapping": cwe_mapping,
                "description": cwe_description,
            },
        )
