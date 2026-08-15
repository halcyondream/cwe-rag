from extract import CweXmlExtractor
from transform import CweJsonToMarkdownTransformer
from load import CweMarkdownToChromaLoader
from dotenv import load_dotenv
import os
from model import CweJsonModel

load_dotenv()


if __name__ == "__main__":
    """
    Run the full ETL steps to build the vector database.
    """
    ignore_prohibited = bool(os.environ.get("IGNORE_PROHIBITED"))
    ignore_discouraged = bool(os.environ.get("IGNORE_DISCOURAGED"))
    output_folder_json = os.environ.get("OUTPUT_FOLDER_JSON")
    output_folder_md = os.environ.get("OUTPUT_FOLDER_MD")

    extractor = CweXmlExtractor(
        CweJsonModel,
        ignore_prohibited=ignore_prohibited,
        ignore_discouraged=ignore_discouraged,
        output_folder=output_folder_json,
    )
    transformer = CweJsonToMarkdownTransformer(
        output_folder_json, output_folder_md, CweJsonModel
    )
    loader = CweMarkdownToChromaLoader(CweJsonModel)

    extractor.extract()
    transformer.transform()
    loader.load()
