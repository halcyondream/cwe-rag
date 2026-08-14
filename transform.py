"""
Once JSON is extracted, transform it into a searchable markdown file.
Persist needed metadata as YAML topmatter.
"""

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


with open("cwe_template.jinja") as f:
    cwe_template = f.read()


for file in files:
    with open(file.absolute()) as f:
        data = json.load(f)

    md_template = Template(cwe_template)

    md_topmatter = yaml.safe_dump(data)

    md = md_template.render(
        top_matter=md_topmatter,
        cwe_id=data["id"],
        cwe_name=data["name"],
        cwe_description=data["description"],
        cwe_extended_description=data["extended_description"],
    )

    md = re.sub(r"\n\s*\n+", "\n\n", md)

    md_outfile = (md_folder / f"cwe-{data['id']}.md").absolute()

    with open(md_outfile, "w") as f:
        f.write(md)
