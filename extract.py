import json
import xmltodict
from dotenv import load_dotenv
import os
from pathlib import Path
from zipfile import ZipFile
from common import iter_values, cache_file_from_url
from model import CweJsonModel
from config import Config
from runner import IHook

load_dotenv()


class CweXmlExtractor(IHook):
    """
    Download and extract CWE data as a JSON intermediate representation.

    This project distinguishes the JSON transformation from the vector db
    markdown form. The outputs here pipe directly into what you get with the
    markdown files, including content and topmatter.

    Alternatively, if you just want the JSON, this is the class you care about.
    """

    def __init__(
        self,
        config: Config,
        output_folder=None,
        cache_folder=None,
        ignore_prohibited=True,
        ignore_discouraged=True,
    ):
        self.config = config
        self.ignore_prohibited = ignore_prohibited
        self.ignore_discouraged = ignore_discouraged
        self.output_folder = Path(output_folder or self.config.json_output_folder)
        self.cache_folder = Path(cache_folder or self.config.web_cache_folder)
        self.cwe_xml = None

        if not self.cache_folder.exists():
            self.cache_folder.mkdir()

        if not self.output_folder.exists():
            self.output_folder.mkdir()

    def run(self):
        self.extract()

    def assert_success(self):
        assert len(list(self.output_folder.rglob("cwe**.json"))) > 0

    def clean(self):
        self.clear_all()

    def extract(self):
        """
        Extract all CWEs and rewrite them in a normalized JSON form.
        """
        cwe_file = self._pull()

        with open(cwe_file) as f:
            cwe_xml = f.read()

        cwe_json_all = (
            xmltodict.parse(cwe_xml).get("Weakness_Catalog").get("Weaknesses")
        )
        self.preexisting_extractions = self.output_folder.rglob("cwe**.json")
        self.all_weaknesses = [weakness for weakness in cwe_json_all.get("Weakness")]

        for idx, cwe_json in enumerate(self.all_weaknesses):
            self._process_cwe(cwe_json, idx)

    def print_stats(self):
        cached = list(self.cache_folder.rglob("cwec**.xml"))
        extracted = list(self.output_folder.rglob("cwe**.json"))
        print(f"Extracted: {len(extracted)} file(s)")
        print(f"Cached: {len(cached)} file(s)")

    def clear_cache(self):
        for file in self.cache_folder.iterdir():
            file.unlink()

    def clear_files(self):
        for file in self.output_folder.iterdir():
            file.unlink()

    def clear_all(self):
        self.clear_cache()
        self.clear_files()

    def _pull(self, force_update=False):
        """
        Fetch the current CWE catalog. This is assumed to be a zipfile containing
        one XML file in the format of `cwec_vX.YY.xml`. If this assumption changes
        (for example, multiple versions in one zipfile), update the code.
        """
        target_path = self.cache_folder / "cwe.zip"

        # Only fetch the zipfile if it doesn't exist or if fetching is forced.
        if force_update or not target_path.exists():
            cache_file_from_url(
                "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", target_path
            )

        with ZipFile(target_path) as z:
            z.extractall(self.cache_folder)

        xmls = [f.absolute() for f in self.cache_folder.rglob("cwec**.xml")]
        assert len(xmls) == 1
        return xmls[0]

    def _process_cwe(self, cwe_json, idx):
        """
        Extract a single CWE to JSON and cache it to a file.
        """
        clean_str = lambda string: " ".join([s.strip() for s in string.split("\n")])

        cwe_id = int(cwe_json["@ID"])
        cwe_name = cwe_json["@Name"]
        cwe_mapping = cwe_json["Mapping_Notes"]["Usage"]
        cwe_abstraction = cwe_json["@Abstraction"]

        print(
            f"\n[{round((idx/len(self.all_weaknesses))*100)}% | {idx+1}/{len(self.all_weaknesses)}] CWE-{cwe_id}: {cwe_name}\n"
        )

        if f"cwe-{cwe_id}.json" in self.preexisting_extractions:
            print("  [CWE already processed. Ignoring...]")
            return

        if self.ignore_prohibited and cwe_mapping.lower() == "prohibited":
            print("  [CWE mapping is PROHIBITED. Ignoring...]")
            return

        if self.ignore_discouraged and cwe_mapping.lower() == "discouraged":
            print("  [CWE mapping is DISCOURAGED. Ignoring...]")
            return

        capecs = cwe_json.get("Related_Attack_Patterns", [])
        related_capecs = []

        if len(capecs) > 0:
            for id in iter_values(capecs.get("Related_Attack_Pattern")):
                capec_id = int(id)
                related_capecs.append(capec_id)

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
                related_cves.append(
                    {"cve_id": cve_id, "cve_description": cve_description}
                )

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

        consequences = self._parse_consequences(cwe_json)

        cwe_platforms = xml_get(cwe_json, "Applicable_Platforms")
        cwe_description = xml_get(cwe_json, "Description")
        cwe_extended_description = "\n".join(
            iter_values(xml_get(cwe_json, "Extended_Description"))
        )
        cwe_background = xml_get(cwe_json, "Background_Details")
        cwe_alt_terms = xml_get(cwe_json, "Alternate_Terms")

        cwe_description = clean_str(cwe_description)
        cwe_extended_description = clean_str(cwe_extended_description)

        cwe_languages, cwe_is_language_specific = self._handle_platform_collection(
            cwe_platforms, "Languages", "Language"
        )
        cwe_operating_systems, cwe_is_os_specific = self._handle_platform_collection(
            cwe_platforms, "Operating_System", "OS"
        )
        cwe_architectures, cwe_is_architecture_specific = (
            self._handle_platform_collection(
                cwe_platforms, "Architecture", "Architecture"
            )
        )
        cwe_technologies, cwe_is_technology_specific = self._handle_platform_collection(
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

        cwe_metadata = {
            "id": cwe_id,
            "name": cwe_name,
            "mapping": cwe_mapping,
            "abstraction": cwe_abstraction,
            "description": "\n\n".join(iter_values(cwe_description)),
            "extended_description": "\n\n".join(iter_values(cwe_extended_description)),
            "background": "\n\n".join(iter_values(cwe_background)),
            "cves": related_cves,
            "capecs": related_capecs,
            "platform_info": cwe_platform_metadata,
            "consequences": consequences,
        }

        CweJsonModel.model_validate(cwe_metadata, strict=True)

        with open(self.output_folder / f"cwe-{cwe_id}.json", "w") as f:
            f.write(json.dumps(cwe_metadata, indent=2))

    def _handle_platform_collection(self, platform_info: dict, name: str, not_key: str):
        """
        Normalize some of the messy XML structure.
        """
        not_string = f"Not {not_key}-Specific"

        # Because the CWE XML is a bit messy, some keys are defined by their
        # pluaralized form and others are not (ex, "Languages" vs "Language").
        # Try both cases when determining whether a hit exists, preferring the
        # pluralized version first.
        try_1 = platform_info.get(name, [])
        try_2 = platform_info.get(not_key, [])

        if len(try_1):
            collection: list = iter_values(try_1)
        elif len(try_2):
            collection: list = iter_values(try_2)
        else:
            collection = []

        ignore_terms = ["unknown", "undetermined", "often"]
        collection = [e for e in collection if e.lower() not in ignore_terms]
        is_specific = not_string not in collection and len(collection) > 0
        collection = [e for e in collection if e != not_string]
        return collection, is_specific

    def _parse_consequences(self, cwe_json):
        """
        Normalize a CWE's consequences into intuitive scope, impact, and notes.
        """

        def get_json(data):
            scope = data.get("Scope") or []
            impact = data.get("Impact") or []
            note = data.get("Note") or "\n".join(iter_values(data.get("Note")))
            if type(scope) != list:
                scope = [scope]
            if type(impact) != list:
                impact = [impact]
            if type(note) == dict or type(note) == list:
                note = "\n".join(iter_values(note))
            return {"scope": scope, "impact": impact, "note": note}

        cwe_consequences = cwe_json.get("Common_Consequences")

        if not cwe_consequences:
            return []

        consequence = cwe_consequences["Consequence"]

        if type(consequence) == dict:
            return [get_json(consequence)]
        elif type(consequence) == list:
            ret = []
            for c in consequence:
                ret.append(get_json(c))
            return ret

        raise TypeError(f"Expected a dict or list, got {type(consequence)}")


if __name__ == "__main__":
    config = Config(CweJsonModel)
    extractor = CweXmlExtractor(config)
    extractor.clear_files()
    extractor.extract()
    extractor.print_stats()
