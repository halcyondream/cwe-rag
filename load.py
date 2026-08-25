"""
Load markdown + topmatter into a local Chroma vector database.
"""

import os
from abc import ABC, abstractmethod
from pathlib import Path

import chromadb
from chromadb import Collection
from chromadb.utils.embedding_functions.ollama_embedding_function import (
    OllamaEmbeddingFunction,
)
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter

from common import get_markdown, iter_values
from config import Config
from runner import IHook


class IEmbeddingClient(ABC):

    @abstractmethod
    def initialize(self):
        """
        Initialize the data store.
        """

    def get_chunks(self, document):
        """
        Represent a text document as a list of vector chunks.
        """

    def add_document_chunked(self, document, doc_idx, metadata: dict | None = None):
        """
        Add a document to the data store in its chunked form.
        """

    def query_texts(self, query: str, filter: dict, n_results=6):
        """
        Perform a similarity search of documents based on your query.
        """


class OllamaChromaEmbeddingClient(IEmbeddingClient):
    def __init__(
        self,
        config: Config,
        db_name=None,
        ollama_host=None,
        embedding_model=None,
        splitter=None,
    ):
        self.config = config
        self.db_name = db_name or self.config.db_name
        self.ollama_host = ollama_host or os.environ.get("OLLAMA_HOST")
        self.embedding_model = embedding_model or os.environ.get("EMBEDDING_MODEL")
        self.splitter = splitter or RecursiveCharacterTextSplitter.from_language(
            language=Language.MARKDOWN
        )

    def initialize(self):
        """
        Connect to the collection using the desired LLM embedding client
        and embedding function.
        """
        self.ollama_embedding_function = OllamaEmbeddingFunction(
            url=self.ollama_host, model_name=self.embedding_model
        )

        self.client = chromadb.PersistentClient()

        self.collection: Collection = self.client.get_or_create_collection(
            name="cwe_strict",
            embedding_function=self.ollama_embedding_function,
            metadata={"hnsw:space": "cosine"},
        )

    def get_chunks(self, document):
        return self.splitter.split_text(document)

    def add_document_chunked(self, document, doc_idx, metadata: dict | None = None):
        """
        Chunk and embed a text document to the vector database.
        """
        chunks = self.get_chunks(document)
        for chunk_idx, chunk in enumerate(chunks):
            if metadata:
                self._add_chunk_with_metadata(chunk, doc_idx, chunk_idx, metadata)
            else:
                self._add_chunk(chunk, doc_idx, chunk_idx)

    def query_texts(self, query: str, filter: dict, n_results=6):
        return self.collection.query(
            query_texts=[query], n_results=n_results, where=filter
        )

    def _add_chunk(self, chunk, doc_idx, chunk_idx):
        """
        Add a chunk without metadata.
        """
        self.collection.add(
            documents=chunk,
            ids=f"cwe_{doc_idx + 1}_{chunk_idx + 1}",
        )

    def _add_chunk_with_metadata(self, chunk, doc_idx, chunk_idx, metadata: dict):
        """
        Add a chunk with chunks.
        """
        self.collection.add(
            documents=chunk,
            ids=f"cwe_{doc_idx + 1}_{chunk_idx + 1}",
            metadatas=metadata,
        )


class CweMarkdownLoader(IHook):
    """
    Load a CWE markdown representation into a Chroma Vector Database.
    """

    def __init__(self, config: Config, client: IEmbeddingClient, cwe_md_folder=None):
        self.client = client
        self.config = config
        self.markdown_folder = Path(cwe_md_folder or self.config.md_output_folder)

    def run(self):
        self.load()

    def assert_success(self):
        """
        TODO: Return something sane like the length of the database.
        """

    def clean(self):
        self.delete_database()

    def load(self, validate=True):
        """
        Load markdown contents as searchable from the vector database.
        Retain markdown topmatter for metadata filtering.
        """
        self.client.initialize()
        md_files = list(self.markdown_folder.rglob("cwe**.md"))

        if not len(md_files):
            raise ValueError("No markdown files were found")

        for doc_idx, cwe_file in enumerate(md_files):
            with open(cwe_file) as f:
                content = f.read()
                topmatter, cwe_md = self._extract_markdown(content)

            if validate:
                self.config.validation_model.model_validate(
                    topmatter, extra="forbid", strict=True
                )

            cwe_id = topmatter["id"]
            cwe_name = topmatter["name"]
            cwe_abstraction = topmatter["abstraction"]
            cwe_description = topmatter["description"]
            cwe_mapping = topmatter["mapping"]

            cwe_consequences = self._parse_consequences(topmatter["consequences"])

            cwe_keywords = self._get_keywords(topmatter)

            print(cwe_id, cwe_name)

            metadatas = {
                "cwe_id": cwe_id,
                "name": cwe_name,
                "impact_scopes": cwe_consequences["scopes"] or [""],
                "impacts": cwe_consequences["impacts"] or [""],
                "impact_notes": cwe_consequences["notes"] or [""],
                "keywords": cwe_keywords or "",
                "abstraction": cwe_abstraction,
                "mapping": cwe_mapping,
                "description": cwe_description,
            }

            self.client.add_document_chunked(cwe_md, doc_idx, metadata=metadatas)

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
        return get_markdown(text)

    def _get_keywords(self, cwe_json: dict) -> list[str]:
        """
        Flatten keywords as a list.
        """
        keywords = []
        keywords += iter_values(cwe_json["platform_info"])
        return keywords


if __name__ == "__main__":
    from model import CweJsonModel

    config = Config(CweJsonModel)
    client = OllamaChromaEmbeddingClient(config)
    loader = CweMarkdownLoader(config, client)
    loader.delete_database()
    loader.load()
