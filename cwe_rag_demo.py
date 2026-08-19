import json
import os

from pydantic import BaseModel, Field
from pydantic_ai import Agent

from load import IEmbeddingClient


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
    metadata = results.get("metadatas")[0]

    user_prompt = (
        "Select the top two CWEs that describe the root cause of this vulnerability."
    )
    user_prompt += f"\n<cwes>\n{json.dumps(documents)}\n</cwes>\nMost related CWEs:\n"

    llm_model = os.environ.get("LLM_MODEL")
    model = f"ollama:{llm_model}"

    # Avoid refactoring the OLLAMA_HOST env var everywhere...
    # TODO: Handle this in the Config object.
    host = os.environ.get("OLLAMA_HOST")
    path = os.environ.get("LLM_API_PATH")
    os.environ["OLLAMA_BASE_URL"] = f"{host}{path}"

    agent = Agent(
        model,
        instructions="You are a helpful vulnerability triage agent.",
        output_type=TopTwoPicks,
    )

    answer = agent.run_sync(user_prompt)
    print(answer)
