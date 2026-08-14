from extract import CweXmlExtractor
from transform import CweJsonToMarkdownTransformer


if __name__ == "__main__":
    extractor = CweXmlExtractor()
    transformer = CweJsonToMarkdownTransformer()

    extractor.extract()
    transformer.transform()
