from extract import CweXmlExtractor
from transform import CweJsonToMarkdownTransformer
from load import CweMarkdownToChromaLoader
from dotenv import load_dotenv
import os
from model import CweJsonModel
from config import Config

load_dotenv()


if __name__ == "__main__":
    """
    Run the full ETL steps to build the vector database.
    """
    ignore_prohibited = bool(os.environ.get("IGNORE_PROHIBITED"))
    ignore_discouraged = bool(os.environ.get("IGNORE_DISCOURAGED"))

    config = Config(CweJsonModel)

    extractor = CweXmlExtractor(
        config,
        ignore_prohibited=ignore_prohibited,
        ignore_discouraged=ignore_discouraged,
    )
    transformer = CweJsonToMarkdownTransformer(config)
    loader = CweMarkdownToChromaLoader(CweJsonModel)

    extractor.extract()
    transformer.transform()
    loader.load()
