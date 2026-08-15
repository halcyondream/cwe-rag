from model import CweJsonModel
from pathlib import Path
from pydantic import BaseModel
import defaults 


class Config:
    def __init__(
        self,
        cache_folder=None,
        json_output_folder=None,
        md_output_folder=None,
        web_cache_folder=None,
        chroma_db_folder=None,
        validation_model: BaseModel = None,
    ):
        self.cache_folder = Path(cache_folder or defaults.cache_folder)
        self.json_output_folder = self._cached(json_output_folder or defaults.json_output_folder)
        self.md_ouput = self._cached(md_output_folder or defaults.md_output_folder)
        self.web_cache_folder = self._cached(web_cache_folder or defaults.web_cache_folder)
        self.chroma_db_folder = chroma_db_folder or defaults.chroma_db_folder
        self.validation_model = validation_model or defaults.validation_model

    def _cached(self, folder):
        return Path(self.cache_folder / folder)