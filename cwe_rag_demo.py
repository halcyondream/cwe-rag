import json
import os

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from load import IEmbeddingClient

load_dotenv()

# Avoid refactoring the OLLAMA_HOST env var everywhere...
# TODO: Handle this in the Config object.
host = os.environ.get("OLLAMA_HOST")
path = os.environ.get("LLM_API_PATH")
os.environ["OLLAMA_BASE_URL"] = f"{host}{path}"

llm_model = os.environ.get("LLM_MODEL")
model = f"ollama:{llm_model}"


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
    cwes: list[str] = Field(
        description="The `CWE-<id>: <title> of the most relevant root cause weakness(es)",
        min_length=2,
        max_length=3,
    )


def rag_demo(client: IEmbeddingClient):
    filter = {
        "$and": [
            {"abstraction": {"$ne": "class"}},
            {"mapping": {"$ne": "Prohibited"}},
            {"mapping": {"$ne": "Discouraged"}},
        ]
    }
    client.initialize()
    query = input("Describe your vulnerability> ")
    results = client.query_texts(query, filter)
    documents = results.get("documents")[0]
    # metadata = results.get("metadatas")[0]

    user_prompt = (
        "Select the top two CWEs that describe the root cause of this vulnerability."
    )
    user_prompt += f"\n<cwes>\n{json.dumps(documents)}\n</cwes>\nMost related CWEs:\n"

    agent = Agent(
        model,
        instructions="You are a helpful vulnerability triage agent.",
        output_type=TopTwoPicks,
    )

    answer = agent.run_sync(user_prompt)
    print(answer)


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
            "appropriate for vector database CWE searches. For example, you may expand\n"
            "XSS to 'cross-site scripting', sqli to 'SQL Injection', etc.\n\n"
            f"<question>\n{query}\n</question>\n\nSearch terms:"
        )
        result = subagent.run_sync(
            user_prompt, deps=ctx.deps, retries=3, output_type=SearchStrings
        )
        terms = set()
        for term in result.output.terms:
            for t in term.split(" "):
                terms.add(t)
        terms = list(terms)[:6]
        query += f"\nSearch terms: {', '.join(terms)}"
        print(f"[VECTORDB QUERY: {query}]")
        filter = {
            "$and": [
                {"abstraction": {"$ne": "class"}},
                {"mapping": {"$ne": "Prohibited"}},
                {"mapping": {"$ne": "Discouraged"}},
            ]
        }
        result = client.query_texts(query, filter, n_results=n_results)
        return result.get("documents")[0]

    @agent.tool_plain
    def get_cwe_details(cwe_id: int):
        """
        Get concrete details about a CWE.

        Args:
            cwe_id (int): The numeric CWE Identifier

        Returns:
            str|None: CWE data or nothing
        """
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
