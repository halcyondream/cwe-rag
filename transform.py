import json
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv
from jinja2 import Template

from config import Config
from model import CweJsonModel
from runner import IHook

load_dotenv()


class CweJsonToMarkdownTransformer(IHook):
    """
    Convert CWE JSON from files to markdown-with-topmatter files.
    """

    def __init__(self, config: Config, json_folder=None, md_folder=None):
        self.config = config
        self.json_folder = Path(json_folder or self.config.json_output_folder)
        self.md_folder = Path(md_folder or self.config.md_output_folder)

        if not self.md_folder.exists():
            self.md_folder.mkdir()

    def run(self):
        self.transform()

    def assert_success(self):
        assert len(list(self.md_folder.rglob("cwe**.md"))) > 0

    def clean(self):
        self.clear_files()

    def transform(self, validate=True):
        """
        Transform the intermediary representation JSON to markdown.
        Preserve metadata as YAML topmatter.
        """
        files = list(self.json_folder.rglob("**.json"))

        if not len(files):
            raise ValueError(
                f"JSON folder {self.json_folder.absolute()} has no valid JSON files"
            )

        with open("templates/cwe_template.jinja") as f:
            cwe_template = f.read()

        for file in files:
            with open(file.absolute()) as f:
                data = json.load(f)

            if validate:
                CweJsonModel.model_validate(data, extra="forbid", strict=True)

            md_template = Template(cwe_template)

            md_topmatter = yaml.safe_dump(data)

            md = md_template.render(
                top_matter=md_topmatter,
                cwe_id=data["id"],
                cwe_name=data["name"],
                cwe_description=data["description"],
                cwe_extended_description=data["extended_description"],
            )

            # Clean up unnecessary whietspaces.
            md = re.sub(r"\n\s*\n+", "\n\n", md)

            (self.md_folder / f"cwe-{data['id']}.md").write_text(md)

    def clear_files(self):
        for file in self.md_folder.iterdir():
            file.unlink()


if __name__ == "__main__":
    from model import CweJsonModel

    config = Config(CweJsonModel)
    transformer = CweJsonToMarkdownTransformer(config)
    transformer.transform()
