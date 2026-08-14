import os
import json
from jinja2 import Template
import re
from dotenv import load_dotenv
from pathlib import Path
import yaml

load_dotenv()


target_folder = Path(os.environ.get("OUTPUT_FOLDER"))
md_folder = Path(os.environ.get("OUTPUT_FOLDER_MD"))

files = list(target_folder.rglob("**.json"))

if not md_folder.exists():
    md_folder.mkdir()


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


def get_keywords(cwe_json: dict) -> list[str]:
    keywords = []
    keywords += iter_values(cwe_json["platform_info"])
    return keywords


cwe_md = """---
{{top_matter}}
---

# CWE-{{cwe_id}}: {{cwe_name}}

## Description

{{cwe_description}}

{% if cwe_extended_description %}
## Extended description

{{cwe_extended_description}}
{% endif %}
"""

for file in files:
    with open(file.absolute()) as f:
        data = json.load(f)
    md_template = Template(cwe_md)

    md_topmatter = yaml.safe_dump(data)

    md = md_template.render(
        top_matter=md_topmatter,
        cwe_id=data["id"],
        cwe_name=data["name"],
        cwe_description=data["description"],
        cwe_extended_description=data["extended_description"],
        keywords=get_keywords(data),
    )

    md = re.sub(r"\n\s*\n+", "\n\n", md)

    md_outfile = (md_folder / f"cwe-{data['id']}.md").absolute()

    with open(md_outfile, "w") as f:
        f.write(md)

import sys; sys.exit()

import chromadb
from chromadb import Collection
from chromadb.utils.embedding_functions.ollama_embedding_function import (
    OllamaEmbeddingFunction,
)
from pathlib import Path
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language

ollama_embedding_function = OllamaEmbeddingFunction(
    url=os.environ.get("OLLAMA_HOST"), model_name="mxbai-embed-large"
)

client = chromadb.PersistentClient()

collection: Collection = client.get_or_create_collection(
    name="cwe_strict", embedding_function=ollama_embedding_function,
    metadata={"hnsw:space": "cosine"}
)


splitter = RecursiveCharacterTextSplitter.from_language(
    language=Language.MARKDOWN
)


def parse_consequences(cwe_consequences):
    prepare = lambda x: [x] if type(x) == str else x
    scopes = []
    impacts = []
    notes = []
    for consequence in cwe_consequences:
        scopes += prepare(consequence["scope"])
        impacts += prepare(consequence["impact"])
        notes += prepare(consequence["note"])
    return {
        "scopes": scopes,
        "impacts": impacts,
        "notes": notes
    }


# Load data into the Vector DB.
# TODO: Have this load from YAML topmatter.

for doc_idx, cwe_file in enumerate(files):
    with open(cwe_file) as f:
        data = json.load(f)
    cwe_id = data["id"]
    cwe_name = data["name"]
    cwe_abstraction = data["abstraction"]
    cwe_description = data["description"]
    cwe_mapping = data["mapping"]
    cwe_md = (md_folder / f"cwe-{cwe_id}.md").read_text()
    
    # Restructure keyword lists as a cleartext string
    # Use chromadb's `$not_contains` to filer out irrelevant keywords
    # or `$contains` to target known relevant ones.
    cwe_consequences = parse_consequences(data["consequences"])

    cwe_keywords = get_keywords(data)

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
                "description": cwe_description
            }
        )
