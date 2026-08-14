from extract import CweXmlExtractor
from transform import CweJsonToMarkdownTransformer
from load import CweMarkdownToChromaLoader


if __name__ == "__main__":
    """
    Run the full ETL steps to build the vector database.
    """
    extractor = CweXmlExtractor()
    transformer = CweJsonToMarkdownTransformer()
    loader = CweMarkdownToChromaLoader()

    extractor.extract()
    transformer.transform()
    loader.load()
