import configparser
from pathlib import Path

from pydantic import BaseModel


class Config:
    def __init__(
        self,
        validation_model: BaseModel,
        cache_folder=None,
        json_output_folder=None,
        md_output_folder=None,
        web_cache_folder=None,
        chroma_db_folder=None,
        db_name=None,
    ):
        defaults = self._load_config()
        self.cache_folder = Path(cache_folder or defaults["cache_folder"])
        self.json_output_folder = self._cached(
            json_output_folder or defaults["json_output_folder"]
        ).absolute()
        self.md_output_folder = self._cached(
            md_output_folder or defaults["md_output_folder"]
        ).absolute()
        self.web_cache_folder = self._cached(
            web_cache_folder or defaults["web_cache_folder"]
        ).absolute()
        self.chroma_db_folder = Path(
            chroma_db_folder or defaults["chroma_db_folder"]
        ).absolute()
        self.validation_model = validation_model
        self.db_name = db_name or defaults["db_name"]

    def _cached(self, folder):
        return Path(self.cache_folder / folder)

    def _load_config(self):
        config = configparser.ConfigParser()
        config.read("defaults.ini")
        return config["config"]
