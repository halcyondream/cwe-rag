from extract import CweXmlExtractor
from transform import CweJsonToMarkdownTransformer
from load import OllamaEmbeddingClient, CweMarkdownToChromaLoader
from runner import SequentialRunner
from config import Config
from model import CweJsonModel
import argparse
from pathlib import Path
import json
from common import get_markdown


config = Config(CweJsonModel)
runner = SequentialRunner()


def copy_md_files(include_prohibited=False, include_discouraged=False):
    output_folder = Path("cwe_md_files")

    if not output_folder.exists():
        output_folder.mkdir()

    md_files = list(Path(config.md_output_folder).rglob("cwe**.md"))

    for md in md_files:
        assert md.suffix == ".md"
        md_content = md.read_text()
        frontmatter, _ = get_markdown(md_content)
        config.validation_model.model_validate(frontmatter, strict=True)
        mapping = frontmatter["mapping"]

        if mapping.lower() == "discouraged" and not include_discouraged:
            continue

        if mapping.lower() == "prohibited" and not include_prohibited:
            continue

        cwe_id = frontmatter["id"]
        target_path = output_folder / f"cwe-{cwe_id}.md"
        md.copy(target_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", help="Run the pipeline or copy artifacts", choices=["run", "copy-md"]
    )
    parser.add_argument(
        "--noextract",
        help="Any steps to omit from the pipeline",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--notransform",
        help="Any steps to omit from the pipeline",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--noload",
        help="Any steps to omit from the pipeline",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--include-prohibited",
        help="Includes CWEs with PROHIBITED mapping",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--include-discouraged",
        help="Includes CWEs with DISCOURAGED mapping",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    if not args.noextract:
        extractor = CweXmlExtractor(config)
        runner.register(extractor)

    if not args.notransform:
        transformer = CweJsonToMarkdownTransformer(config)
        runner.register(transformer)

    if not args.noload:
        client = OllamaEmbeddingClient(config)
        loader = CweMarkdownToChromaLoader(config, client)
        runner.register(loader)

    if args.mode == "run":
        runner.run()

    elif args.mode == "copy-md":
        copy_md_files(
            include_prohibited=args.include_prohibited,
            include_discouraged=args.include_discouraged,
        )
