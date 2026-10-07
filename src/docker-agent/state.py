from typing import Annotated, Optional
from langchain_core.messages import AnyMessage # type: ignore
from langgraph.graph.message import add_messages # type: ignore
from pydantic import BaseModel, Field # type: ignore
from langchain_openai import ChatOpenAI # type: ignore
from pathlib import Path

# My modules
from configuration import Code, WebSearch, Stats, Milestones, CVEClassification, SanityCheckResult

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

class OverallState(BaseModel):
    model_name: str = Field(
        default="",
        description="Name of the model chosen for this agent run"
    )
    base_path: Path = Field(
        default=PROJECT_ROOT,
        description="The path of the root directory of the project"
    )
    forger_llm: ChatOpenAI = Field(
        default=None, 
        description="LLM instance being used"
    )
    cve_id: str = Field(
        default="",
        description="The input CVE-ID"
    )
    web_search_result: WebSearch = Field(
        default=WebSearch(desc="", cwe="", attack_type="", services=[]), 
        description="The result of the web search"
    )
    code: Code = Field(
        default=Code(files=[], directory_tree="", target_hostname=""),
        description="The generated file name, code and associated directory tree"
    )
    fail_explanation: str = Field(
        default="",
        description="Detailed explanation of why the Docker has failed testing"
    )
    revision_type: str = Field(
        default="",
        description="Type of revision to be applied to the Docker code"
    )
    revision_goal: str = Field(
        default="",
        description="Goal of the revision phase"
    )
    fixes: list[str] = Field(
        default=[],
        description="List of attempted fixes to the code"
    )
    platform_feasible: bool = Field(
        default=True,
        description="False if the service requires a platform that cannot be containerized in Linux"
    )
    platform_infeasibility_reason: str = Field(
        default="", 
        description="Explanation on why the input CVE was considered impossible to represent on Docker and Linux"
    )
    stats: Stats = Field(
        default=Stats(),
        description="Various stats about the current workflow"
    )
    milestones: Milestones = Field(
        default=Milestones(),
        description="Milestones of the workflow, used to to track its progress"
    )
    classification: CVEClassification = Field(
        default=None,
        description="Classification of the CVE: contains info like the CWE"
    )
    sanity_retry_count: int = Field(
        default=0,
        description="Number of times this step is repeated"
    )
    sanity_result: SanityCheckResult = Field(
        default=None,
        description="Result of the sanity check (e.g., is the flag exposed?)"
    )
    skip_to_red_team: bool = Field(
        default=False,
        description="Flag that forces to skip to the last step in the pipeline"
    )
    skip_to_scout: bool = Field(
        default=False,
        description="Flag that forces to skip to the docker scout check in the pipeline"
    )
    reuse_classification: bool = Field(
        default=False,
        description="Flag that forces to skip to the code generation phase"
    )    
    reuse_web_search_and_code: bool = Field(
        default=False,
        description="Flag that forces to skip to the phase in which the code is tested"
    )
    debug_retries: int = Field(
        default=0,
        description="Number of times the Debugger node was executed"
    )
    debugger_action: str = Field(
        default="" ,
        description="The action chosen by the debugger (either 'Hard Fix' or 'Soft Fix')"
    )
    dynamic_hint: str = Field(
        default="" ,
        description="The hint the debugger chooses to give to the evaluator"
    )