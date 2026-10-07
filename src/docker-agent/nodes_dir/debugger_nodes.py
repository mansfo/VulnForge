import builtins
from typing import Literal
from langchain_core.messages import HumanMessage, SystemMessage

from state import OverallState
from .utils.llm_utils import invoke_structured
from prompts import SYSTEM_PROMPT, DEBUGGER_PROMPT
from configuration import langfuse_handler, DebuggerDecision

from nodes_dir.utils.file_utils import docker_dir


def debugger(state: OverallState):
    print("\n[Debugger] Analyzing Red Team failure...")
    
    code_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool)
    log_file_path = code_dir_path / f"logs/red_team_log{state.debug_retries}.txt"
    
    red_team_log = ""
    if log_file_path.exists():
        with builtins.open(log_file_path, "r") as f:
            lines = f.readlines()
            red_team_log = "".join(lines[:])

    code_context = f"Directory tree:\n{state.code.directory_tree}\n\n"
    for f in state.code.files:
        code_context += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"

    prompt = DEBUGGER_PROMPT.format(
        cve_id=state.cve_id,
        code_context=code_context,
        red_team_log=red_team_log
    )
    prompt +="\n<|think|>"
    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)]
    decision = invoke_structured(state.builder_llm, state.model_name, messages, DebuggerDecision, config={"callbacks": [langfuse_handler]})

    print(f"\t[Debugger] Decision: {decision}")
    
    state.debug_retries += 1
    state.stats.debug_retries += 1
    updates = {
        "debugger_action": decision.action_type,
        "dynamic_hint": decision.expert_hint if decision.action_type == "Soft Fix" else state.dynamic_hint,
        "debug_retries": state.debug_retries,
    }

    if decision.action_type == "Hard Fix":
        updates["code"] = decision.fixed_code
        state.milestones.docker_builds = False
        state.milestones.docker_runs = False
        state.milestones.network_setup = False
        state.milestones.code_hard_version = False
        state.milestones.flag_protected = False
        state.milestones.exploit_surface_ok = False
        state.stats.test_iteration = 0
        updates["milestones"] = state.milestones
        updates["stats"] = state.stats

    return updates


def route_debugger(state: OverallState) -> Literal["Soft Fix", "Hard Fix"]:
    return state.debugger_action