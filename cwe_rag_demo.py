import json
import os

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_ai import Agent, ModelSettings, RunContext

from load import IEmbeddingClient

load_dotenv()

# Avoid refactoring the OLLAMA_HOST env var everywhere...
# TODO: Handle this in the Config object.
host = os.environ.get("OLLAMA_HOST")
path = os.environ.get("LLM_API_PATH")
os.environ["OLLAMA_BASE_URL"] = f"{host}{path}"

llm_model = os.environ.get("LLM_MODEL")
llm_provider = os.environ.get("LLM_PROVIDER")

model = f"{llm_provider}:{llm_model}"


class TopTwoPicks(BaseModel):
    """
    The top two CWEs that best relate to the vulnerability.
    """

    top_cwe_id: int = Field(
        description="The top CWE from the list that relates to the vulnerability"
    )
    secondary_cwe_id: int = Field(
        description="Another candidate CWE from the list that relates to the vulnerability"
    )


class SearchStrings(BaseModel):
    terms: list[str] = Field(
        description="A list of single-word search terms", min_length=3, max_length=6
    )


class RootCauseAnalysis(BaseModel):
    root_cause: str = Field(
        description="A one-sentence statement that describes the vulnerability's root cause"
    )
    top_cwes: TopTwoPicks


def rag_demo(client: IEmbeddingClient, n_results=6, structured_output=True):
    agent = Agent(
        model,
        instructions="You are a helpful vulnerability triage assistant.",
        retries=3,
        model_settings=ModelSettings(temperature=0.3),
    )
    filter = {
        "$and": [
            {"abstraction": {"$ne": "class"}},
            {"mapping": {"$ne": "Prohibited"}},
            {"mapping": {"$ne": "Discouraged"}},
        ]
    }
    client.initialize()
    query = input("Describe your vulnerability> ")

    user_prompt_searchstrings = (
        "Briefly summarize the following vulnerability without further explanation:\n"
        f"{query}"
    )

    # Transform the vulnerability scenario/description into a search-friendly
    # statement
    if structured_output:
        result = agent.run_sync(
            user_prompt_searchstrings, retries=3, output_type=SearchStrings
        )
    else:
        result = agent.run_sync(user_prompt_searchstrings, retries=3)

    # query = _process_search_strings(query, result.output)
    query = result.output
    print(query)

    results = client.query_texts(query, filter, n_results=6)
    documents = results.get("documents")[0]
    # metadata = results.get("metadatas")[0]

    user_prompt = (
        "Select the top two CWEs that describe the root cause of this <vulnerability>.\n"
        "Then, briefly describe the root cause in one sentence.\n"
    )
    user_prompt += f"<vulnerability>\n{query}\n</vulnerability>\n"
    user_prompt += f"\n<cwes>\n{json.dumps(documents)}\n</cwes>\n"
    user_prompt += "\nMost related CWEs:\n"

    if structured_output:
        answer = agent.run_sync(user_prompt, retries=3, output_type=RootCauseAnalysis)
    else:
        answer = agent.run_sync(user_prompt, retries=3)

    print(answer.output)


def agentic_demo(client: IEmbeddingClient):
    client.initialize()

    agent = Agent(model, instructions="You are a helpful vulnerability triage agent.")
    subagent = Agent(
        model, instructions="You are a helpful vulnerability triage agent."
    )

    @agent.tool
    def search_cwe_db(ctx: RunContext, query: str, n_results=3) -> list[str]:
        """
        Perform a vector database lookup of CWEs based on a search query

        Args:
            query (str): The search input, question, or vulnerability description
            n_results: The maximum number of results to return

        Returns:
            list[str]: A list of matching document bodies
        """
        user_prompt = (
            "Given the <question>, determine three to six search strings that are\n"
            "appropriate for vector database CWE searches. For example, you might expand\n"
            "XSS to 'cross-site' and 'scripting', sqli to 'SQL' and 'Injection', etc.\n\n"
            f"<question>\n{query}\n</question>\n\nSearch terms:"
        )
        # Leverage the sub-agent to emit a list of search strings.
        result = subagent.run_sync(
            user_prompt, deps=ctx.deps, retries=3, output_type=SearchStrings
        )

        # The agent may yield a list of space-separated terms.
        # Break this apart into a list of up to six single words.
        terms = set()

        for term in result.output.terms:
            for t in term.split(" "):
                terms.add(t.lower().strip())

        # Omit common words/articles from the search.
        omit = ["the", "a", "an", "it", "cwe"]
        terms = [t for t in terms if t.lower() not in omit and "cwe-" not in t.lower()]

        terms = list(terms)[:6]
        query += f"\nSearch terms: {', '.join(terms)}"

        print(query)
        return _search_cwe_db(client, query, n_results=n_results)

    @agent.tool_plain
    def get_cwe_details(cwe_id: int):
        """
        Get concrete details about a CWE.

        Args:
            cwe_id (int): The numeric CWE Identifier

        Returns:
            str|None: CWE data or nothing
        """
        _get_cwe_details(client, cwe_id)

    query = input("Describe a vulnerability> ")
    user_prompt = (
        "You are a helpful vulnerability triage expert.\n"
        "Given the user's <question>, provide a root-cause analysis\n"
        "report.\n"
        "To generate the report, identify the most relevant CWEs, then\n"
        "explain how and why they relate to the <question>.\n\n"
        "<question> into a string that is suitable for vector db queries.\n\n"
        f"<question>\n{query}\n</question>\n\nReport:"
    )

    response = agent.run_sync(user_prompt, output_type=RootCauseAnalysis, retries=3)
    print(response.output)


def _process_search_strings(query: str, search_strings: SearchStrings):
    # The agent may yield a list of space-separated terms.
    # Break this apart into a list of up to six single words.
    terms = set()

    SearchStrings.model_validate(search_strings, strict=True)

    for term in search_strings.terms:
        for t in term.split(" "):
            terms.add(t.lower().strip())

    # Omit common words/articles from the search.
    omit = ["the", "a", "an", "it", "cwe"]
    terms = [t for t in terms if t.lower() not in omit and "cwe-" not in t.lower()]

    terms = list(terms)[:6]
    query += f"\nSearch terms: {', '.join(terms)}"
    return query


def _get_cwe_details(client: IEmbeddingClient, cwe_id: int):
    filter = {
        "$and": [
            {"abstraction": {"$ne": "class"}},
            {"mapping": {"$ne": "Prohibited"}},
            {"mapping": {"$ne": "Discouraged"}},
            {"id": cwe_id},
        ]
    }
    result = client.query_texts("", filter, n_results=1)
    meta = result.get("metadatas")[0]
    if len(meta) == 1:
        return meta[0]
    else:
        return None


def _search_cwe_db(client: IEmbeddingClient, query: str, n_results=3):
    filter = {
        "$and": [
            {"abstraction": {"$ne": "class"}},
            {"mapping": {"$ne": "Prohibited"}},
            {"mapping": {"$ne": "Discouraged"}},
        ]
    }
    result = client.query_texts(query, filter, n_results=n_results)
    return result.get("documents")[0]
