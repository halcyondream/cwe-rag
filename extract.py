import os
import json
import xmltodict
from time import sleep
import csv
from dotenv import load_dotenv
import os
from pathlib import Path
import requests

load_dotenv()

IGNORE_PROHIBITED = os.environ.get("IGNORE_PROHIBITED") or False
IGNORE_DISCOURAGED = os.environ.get("IGNORE_DISCOURAGED") or False
output_folder = Path(os.environ.get("OUTPUT_FOLDER"))
cache_folder = Path("./cache")


def get_cwe_xml():
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    resp = requests.get(url)
    resp.raise_for_status()
    with open(cache_folder / "cwe.zip", "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)


def iter_values(obj) -> list[str]:
    """Return a list of all non-null values in a dict. Omits keys entirely.
    TODO: Rename this function lol."""

    def _deep_extract(obj):
        """Helper method to perform a deep extract of all values in a dict."""
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


def load_capec_map(filename) -> dict:
    """Return a `{capec-id: title}` lookup table."""
    mappings = {}

    with open(filename) as f:
        for line in csv.reader(f):
            id = line[0]
            description = line[1]
            mappings[id] = description

    return mappings


flatten = lambda x: "".join([line.strip() for line in x.split("\n")])

capec_map = load_capec_map("capec.csv")

with open("cwec_v4.20.xml") as f:
    cwe_xml = f.read()

cwe_json_all = xmltodict.parse(cwe_xml).get("Weakness_Catalog").get("Weaknesses")

preexisting_extractions = os.listdir(output_folder)

all_weaknesses = [
    weakness
    for weakness in cwe_json_all.get("Weakness")
]

for idx, cwe_json in enumerate(all_weaknesses):
    clean_str = lambda string: " ".join([s.strip() for s in string.split("\n")])

    cwe_id = int(cwe_json["@ID"])
    cwe_name = cwe_json["@Name"]
    cwe_mapping = cwe_json["Mapping_Notes"]["Usage"]
    cwe_abstraction = cwe_json["@Abstraction"].lower()

    print(
      f"\n[{round((idx/len(all_weaknesses))*100)}% | {idx+1}/{len(all_weaknesses)}] CWE-{cwe_id}: {cwe_name}\n"
    )
    
    if f"cwe-{cwe_id}.json" in preexisting_extractions:
      print("  [CWE already processed. Ignoring...]")
      continue

    if IGNORE_PROHIBITED and cwe_mapping.lower() == "prohibited":
        print("  [CWE mapping is PROHIBITED. Ignoring...]")
        continue

    if IGNORE_DISCOURAGED and cwe_mapping.lower() == "discouraged":
        print("  [CWE mapping is DISCOURAGED. Ignoring...]")
        continue

    capecs = cwe_json.get("Related_Attack_Patterns", [])
    related_capecs = []

    if len(capecs) > 0:
        for id in iter_values(capecs.get("Related_Attack_Pattern")):
            capec_id = int(id)
            capec_description = capec_map[id]
            related_capecs.append(
                {"capec_id": capec_id, "capec_description": capec_description}
            )

    cves = cwe_json.get("Observed_Examples", [])
    related_cves = []

    if len(cves) > 0:
        cve_instance = []
        cve_data = cves["Observed_Example"]

        # Handles an edge case in the XML-to-dict process where
        # the CVE is either an object or a list of objects.
        if type(cve_data) == dict:
            cve_instance.append(cve_data)
        elif type(cve_data) == list:
            cve_instance += cve_data
        for cve in cve_instance:
            cve_id = cve["Reference"]
            cve_description = clean_str(cve["Description"])
            related_cves.append({"cve_id": cve_id, "cve_description": cve_description})

    omissions = [
        "References",
        "Mapping_Notes",
        "Content_History",
        "Modes_Of_Introduction",
    ]

    for key in omissions:
        if cwe_json.get(key):
            del cwe_json[key]

    # Returns either the list or an empty set with the same key name.
    # Intended to preserve structure for unparsing later.
    xml_get = lambda xml_json, key: xml_json.get(key, {key: []})

    # Convert a dict back to XML. Omits the <?xml > header and flattens
    # newlines/indentation.
    xml_unparse = lambda xml_json: xmltodict.unparse(xml_json, full_document=False)

    cwe_platforms = xml_get(cwe_json, "Applicable_Platforms")
    cwe_description = xml_get(cwe_json, "Description")
    cwe_extended_description = "\n".join(
        iter_values(xml_get(cwe_json, "Extended_Description"))
    )
    cwe_background = xml_get(cwe_json, "Background_Details")
    cwe_alt_terms = xml_get(cwe_json, "Alternate_Terms")

    cwe_description = clean_str(cwe_description)
    cwe_extended_description = clean_str(cwe_extended_description)


    def handle_platform_collection(platform_info: dict, name: str, not_key: str):
        not_string = f"Not {not_key}-Specific"
        collection: list = iter_values(platform_info.get(name, []))
        ignore_terms = ["unknown", "undetermined", "often"]
        collection = [e for e in collection if e.lower() not in ignore_terms]
        is_specific = not_string not in collection and len(collection) > 0
        collection = [e for e in collection if e != not_string]
        return collection, is_specific


    cwe_languages, cwe_is_language_specific = handle_platform_collection(
        cwe_platforms, "Languages", "Language"
    )
    cwe_operating_systems, cwe_is_os_specific = handle_platform_collection(
        cwe_platforms, "Operating_System", "OS"
    )
    cwe_architectures, cwe_is_architecture_specific = handle_platform_collection(
        cwe_platforms, "Architecture", "Architecture"
    )
    cwe_technologies, cwe_is_technology_specific = handle_platform_collection(
        cwe_platforms, "Technology", "Technology"
    )

    cwe_platform_metadata = {
        "languages": cwe_languages,
        "is_language_specific": cwe_is_language_specific,
        "operating_systems": cwe_operating_systems,
        "is_os_specific": cwe_is_os_specific,
        "technologies": cwe_technologies,
        "is_technology_specific": cwe_is_technology_specific,
        "architectures": cwe_architectures,
        "is_architecture_specific": cwe_is_architecture_specific,
    }

    cwe_trimmed = {
        "Weakness_Trimmed": {
            "Applicable_Platforms": cwe_platforms,
            "Description": cwe_description,
            "Background_Details": cwe_background,
            "Alternate_Terms": cwe_alt_terms,
        }
    }

    cwe_metadata = {
        "id": cwe_id,
        "name": cwe_name,
        "mapping": cwe_mapping,
        "abstraction": cwe_abstraction,
        "description": "\n\n".join(iter_values(cwe_description)),
        "background": "\n\n".join(iter_values(cwe_background)),
        "cves": related_cves,
        "capecs": related_capecs,
        "platform_info": cwe_platform_metadata,
    }

    with open(output_folder / f"cwe-{cwe_id}.json", "w") as f:
        f.write(json.dumps(cwe_metadata, indent=2))
