from pydantic import BaseModel, Field
from typing import Literal
import json


class PlatformInfoModel(BaseModel):
    """
    Platform information is derived from the weakness itself.
    The CWE documentation often leaves these fields empty or even ambiguous.
    An LLM classification step may be desirable to enrich or supplement these
    shortcomings.
    """

    langauges: list[str] = Field(
        description="A list of related programming languages", default=[]
    )
    is_language_specific: bool = Field(
        description="A heuristic from the platform info.", default=False
    )
    operating_systems: list[str] = Field(
        description="A list of related operating systems", default=[]
    )
    is_os_specific: bool = Field(
        description="A heuristic from the platform info.", default=False
    )
    technologies: list[str] = Field(
        description="A list of related technologies", default=[]
    )
    is_technology_specific: bool = Field(
        description="A heuristic from the platform info.", default=False
    )
    architecturees: list[str] = Field(
        description="A list of related architectures", default=[]
    )
    is_architecture_specific: bool = Field(
        description="A heuristic from the platform info", default=False
    )


class ConsequenceModel(BaseModel):
    """
    In CWE parlance, a consequence entails a scope (from the CIA triad),
    a technical explanation of the impact, and optional notes.
    """

    scope: Literal["Confidentiality", "Availability", "Integrity"] = Field(
        description="The weakness' general impact scope"
    )
    impact: str = Field(
        description="A technical description of the impact enabled by this weakness"
    )
    note: str = Field(description="An optional note about the impact")


class CveModel(BaseModel):
    cve_id: str = Field(description="The ID of the associated CVE")
    cve_description: str = Field(description="The CVE's description")


class CweJsonModel(BaseModel):
    """
    This schema captures key information about a CWE.
    It does not capture ALL information, including references and mapping notes.
    For complex analysis, refer to the official documentation.
    """

    id: int = Field(description="The numeric CWE ID")
    name: str = Field(description="The title of the weakness")
    mapping: Literal["Allowed", "Allowed-With-Review", "Discouraged", "Prohibited"] = (
        Field(description="Whether the CWE can be mapped to real-world vulnerabilities")
    )
    abstraction: Literal["variant", "base", "composite", "class", "category"] = Field(
        description="The CWE's abstraction level (base and variant preferred)"
    )
    description: str = Field(description="The weakness' brief description")
    extended_description: str = Field(
        description="An optional extended description of the weakness", default=""
    )
    background: str = Field(
        description="An optional background description", default=""
    )
    cves: list[CveModel] = Field(
        description="A list of known CVE vulnerabilities whose root cause is represented by this weakness",
        default=[],
    )
    capecs: list[int] = Field(
        description="A list of CAPEC attack patterns associated with this weakness",
        default=[],
    )
    platform_info: PlatformInfoModel = Field(
        description="Any platform information associated with the weakness"
    )
    consequences: list[ConsequenceModel] = Field(
        description="Any impacts associated with this weakness"
    )


if __name__ == "__main__":
    schema = CweJsonModel.model_json_schema()

    with open("cwe_schema.json", "w") as f:
        f.write(json.dumps(schema, indent=2))
