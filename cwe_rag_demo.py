import json
import os

import jinja2
from dotenv import load_dotenv
from jinja2.sandbox import ImmutableSandboxedEnvironment
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
    top_reason: str = Field(
        description="A brief reason why this CWE was chosen."
    )
    secondary_cwe_id: int = Field(
        description="Another candidate CWE from the list that relates to the vulnerability"
    )
    secondary_reason: str = Field(
        description="A brief reason why this CWE was chosen."
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


def rag_demo(
    client: IEmbeddingClient,
    n_results=6,
    structured_output=True,
    llm_make_searchable=True,
):
    env = ImmutableSandboxedEnvironment(
        loader=jinja2.FileSystemLoader("prompts"), undefined=jinja2.StrictUndefined
    )
    agent = Agent(
        model,
        instructions="You are a helpful vulnerability triage assistant.",
        retries=3,
        model_settings=ModelSettings(temperature=0.0),
    )
    filter = {
        "$and": [
            {"abstraction": {"$ne": "class"}},
            {"abstraction": {"$ne": "Variant"}},
            {"mapping": {"$ne": "Prohibited"}},
            {"mapping": {"$ne": "Discouraged"}},
            {"parent_views": {"$contains": 1000}}
        ]
    }
    client.initialize()
    query = input("Describe your vulnerability> ")
    orig_query = query

    insructions_searchstrings = env.get_template(
        "demo-rag/search-terms/system.jinja"
    ).render()
    user_prompt_searchstrings = env.get_template(
        "demo-rag/search-terms/user.jinja"
    ).render(vulnerability=query)

    # Transform the vulnerability scenario/description into a search-friendly
    # statement
    if llm_make_searchable:
        if structured_output:
            # Transform and parse a SearchStrings object.
            result = agent.run_sync(
                user_prompt_searchstrings,
                retries=3,
                instructions=insructions_searchstrings,
                output_type=SearchStrings,
            )
            query = result.output.terms
        else:
            # Use output without generating/parsing search strings.
            result = agent.run_sync(
                user_prompt_searchstrings,
                retries=3,
                instructions=insructions_searchstrings,
            )
            query = list(json.loads(result.output))
        print(f"[search usage: {result.usage}]")
        print(f"[LLM optimized: {query}]")

    else:
        print("[No LLM optimization. Using query as-is...]")

    _prepend = "Represent this sentence for searching relevant passages:\n"

    results = client.query_texts([_prepend + q for q in query], filter, n_results=n_results)
    documents = results.get("documents")
    metadata = results.get("metadatas")

    # The ChromaDB query returns docs and metadatas for each string in
    # the query, but we test assumptions anyway.
    assert len(documents) == len(metadata) == len(query)

    for i in range(len(documents)):
        #docs = documents[i]
        metas = metadata[i]
        q = query[i]
        cwe_data = []

        for m in metas:
            id = m["cwe_id"]
            name = m["name"]
            desc = m["description"]
            label = f"- CWE-{id}: {name}. {desc}"
            cwe_data.append(label)

        print(f"[CWEs Found: {[meta["cwe_id"] for meta in metas]}]")

        instructions = env.get_template("demo-rag/judge/system.jinja").render()
        user_prompt = env.get_template("demo-rag/judge/user.jinja").render(
            weakness=q, cwes=cwe_data, report=orig_query
        )

        if structured_output:
            answer = agent.run_sync(
                user_prompt,
                retries=3,
                instructions=instructions,
                output_type=RootCauseAnalysis,
            )
            answer = answer.output.model_dump_json(indent=2)
        else:
            answer = agent.run_sync(user_prompt, retries=3, instructions=instructions)

        print(f"[judge usage: {answer.usage}]")
        print(f"[from {q}]")
        print(answer.output + "\n\n---\n\n")

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
