import os
import json
from jinja2 import Template
import re
from dotenv import load_dotenv
from pathlib import Path
import yaml
from pydantic import BaseModel

load_dotenv()


class CweJsonToMarkdownTransformer:
    """
    Convert CWE JSON from files to markdown-with-topmatter files.
    """

    def __init__(self, model: BaseModel):
        self.json_folder = Path(os.environ.get("OUTPUT_FOLDER"))
        self.md_folder = Path(os.environ.get("OUTPUT_FOLDER_MD"))
        self.model = model

        if not self.md_folder.exists():
            self.md_folder.mkdir()

    def transform(self):
        """
        Transform the intermediary representation JSON to markdown.
        Preserve metadata as YAML topmatter.
        """
        files = list(self.json_folder.rglob("**.json"))

        if not len(files):
            raise ValueError(
                f"JSON folder {self.json_folder.absolute()} has no valid JSON files"
            )

        with open("cwe_template.jinja") as f:
            cwe_template = f.read()

        for file in files:
            with open(file.absolute()) as f:
                data = json.load(f)

            self.model.model_validate(data)

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

    transformer = CweJsonToMarkdownTransformer(CweJsonModel)
    transformer.transform()
