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
from common import iter_values


class CweMarkdownToChromaLoader:
    """
    Load a CWE markdown representation into a Chroma Vector Database.
    """

    def __init__(self):
        self.ollama_host = os.environ.get("OLLAMA_HOST")
        self.embedding_model = os.environ.get("EMBEDDING_MODEL")
        self.markdown_folder = Path(os.environ.get("OUTPUT_FOLDER_MD"))

    def _initialize_db(self):
        ollama_embedding_function = OllamaEmbeddingFunction(
            url=self.ollama_host, model_name=self.embedding_model
        )

        client = chromadb.PersistentClient()

        self.collection: Collection = client.get_or_create_collection(
            name="cwe_strict",
            embedding_function=ollama_embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

        self.splitter = RecursiveCharacterTextSplitter.from_language(
            language=Language.MARKDOWN
        )

    def load(self):
        """
        Load markdown contents as searchable from the vector database.
        Retain markdown topmatter for metadata filtering.
        """
        self._initialize_db()
        md_files = list(self.markdown_folder.rglob("cwe**.md"))

        if not len(md_files):
            raise ValueError("No markdown files were found")

        for doc_idx, cwe_file in enumerate(md_files):

            with open(cwe_file) as f:
                content = f.read()
                topmatter, cwe_md = self._extract_markdown(content)

            cwe_id = topmatter["id"]
            cwe_name = topmatter["name"]
            cwe_abstraction = topmatter["abstraction"]
            cwe_description = topmatter["description"]
            cwe_mapping = topmatter["mapping"]

            cwe_consequences = self._parse_consequences(topmatter["consequences"])

            cwe_keywords = self._get_keywords(topmatter)

            print(cwe_id, cwe_name)

            chunks = self.splitter.split_text(cwe_md)

            for chunk_idx, chunk in enumerate(chunks):
                self.collection.add(
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

    def delete_database(self):
        """
        Delete the entire Chroma database.
        """
        db_path = Path("chroma")
        for file in db_path.rglob("**"):
            if file.is_dir():
                continue
            file.unlink()
        for path in db_path.rglob("**"):
            if path == db_path:
                continue
            path.rmdir()
        if db_path.exists():
            db_path.rmdir()

    def _parse_consequences(self, cwe_consequences):
        """
        Flatten the consequences for use as a Chroma metadatas line.
        """
        prepare = lambda x: [x] if type(x) == str else x
        scopes = []
        impacts = []
        notes = []
        for consequence in cwe_consequences:
            scopes += prepare(consequence["scope"])
            impacts += prepare(consequence["impact"])
            notes += prepare(consequence["note"])
        return {"scopes": scopes, "impacts": impacts, "notes": notes}

    def _extract_markdown(self, text: str) -> tuple[dict, str]:
        """
        Extracts a two-tuple of (topmatter, markdown,)

        Args:
            text(str): The markdown file

        Returns:
            (topmatter: dict, markdown: str,): A two-tuple of the file's contents
        """
        lines = text.splitlines(keepends=True)

        if not lines or lines[0].rstrip("\r\n") != "---":
            return {}, text

        for i, line in enumerate(lines[1:], start=1):
            if line.rstrip("\r\n") in {"---", "..."}:
                metadata = yaml.safe_load("".join(lines[1:i])) or {}
                return metadata, "".join(lines[i + 1 :]).strip()

        raise ValueError("Unclosed YAML topmatter")

    def _get_keywords(self, cwe_json: dict) -> list[str]:
        """
        Flatten keywords as a list.
        """
        keywords = []
        keywords += iter_values(cwe_json["platform_info"])
        return keywords


if __name__ == "__main__":
    loader = CweMarkdownToChromaLoader()
    loader.delete_database()
    loader.load()
