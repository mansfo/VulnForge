import re
import json
import builtins
from typing import Literal
from langchain_core.messages import HumanMessage, SystemMessage # type: ignore

from state import OverallState
from .utils.file_utils import docker_dir
from .utils.llm_utils import invoke_structured
from prompts import PLATFORM_FEASIBILITY_PROMPT, SYSTEM_PROMPT
from configuration import PlatformFeasibility

NON_LINUX_PLATFORM_PATTERNS = [
    (re.compile(r"\bnetbsd\b", re.I), "NetBSD (kernel non-Linux)"),
    (re.compile(r"\bfreebsd\b", re.I), "FreeBSD (kernel non-Linux)"),
    (re.compile(r"\bopenbsd\b", re.I), "OpenBSD (kernel non-Linux)"),
    (re.compile(r"\bsolaris\b|\billumos\b|\bsmartos\b", re.I), "Solaris/illumos (kernel non-Linux)"),
    (re.compile(r"windowsservercore|nanoserver|mcr\.microsoft\.com/windows", re.I),
     "Windows Server Core/Nano Server (requires Windows containers, not available on host Docker Linux)"),
    (re.compile(r"\bmac\s?os\b|\bdarwin\b", re.I), "macOS/Darwin"),
    (re.compile(r"\bcisco\s?ios\b|\bjunos\b|\bvxworks\b|\brouteros\b|\bfirmware\b", re.I),
     "OS embedded/router/firmware (not containerizable)"),
    (re.compile(r"\bz/os\b|\bmainframe\b", re.I), "mainframe OS"),
    (re.compile(r"\besxi\b|\bhyper-?v\b", re.I), "hypervisor platform (not a containerizable guest OS)"),
    (re.compile(r"\badobe\s+(coldfusion|cfinish|cf)", re.I), "Adobe ColdFusion (requires license)"),
    (re.compile(r"\bkentico\b", re.I), "Kentico (requires license)"),
    (re.compile(r"\bdotnet\s+framework\b|\basp\.net\s+framework\b", re.I), ".NET Framework (requires Windows)"),
]

def check_platform_feasibility_static(services) -> tuple[bool, str]:
    for service in services:
        haystack = f"{service.name} {service.description}"
        for pattern, reason in NON_LINUX_PLATFORM_PATTERNS:
            if pattern.search(haystack):
                return False, f"Service '{service.name}' requires {reason}."
    return True, ""


def assess_platform_feasibility(state: OverallState):
    print("\nChecking platform feasibility (Linux-container guard)...")
    feasible, reason = check_platform_feasibility_static(state.web_search_result.services)

    logs_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs"
    final_report_file = logs_dir_path / "final_report.txt"

    if feasible:
        print("\tPlatform check (static) passed.")
        return {"platform_feasible": True}

    output_string = (
        f"\n\nPLATFORM FEASIBILITY CHECK FAILED (static):\n\t{reason}\n"
        f"\tCVE skipped before code generation — not reproducible as a Linux Docker container.\n"
    )
    print(f"\t[!] {output_string}")
    with builtins.open(final_report_file, "a") as f:
        f.write(output_string)

    with open("results.txt", "a") as f:
        f.write(f"{state.cve_id} | False | False | UnsupportedPlatform\n")

    return {"platform_feasible": False, "platform_infeasibility_reason": reason}


def route_platform_feasibility(state: OverallState) -> Literal["Feasible", "Not Feasible"]:
    print(f"\nRouting platform feasibility (feasible={state.platform_feasible})")
    if state.platform_feasible:
        return "Feasible"
    milestone_file = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs/milestones.json"
    with builtins.open(milestone_file, "w") as f:
        json.dump(state.milestones.model_dump(), f, indent=4)
    print("\nExecution Terminated (unsupported platform)!\n\n\n")
    return "Not Feasible"


def assess_platform_feasibility_llm(state: OverallState):
    if not state.platform_feasible:
        return {}

    hard_services = [s for s in state.web_search_result.services if s.dependency_type == "HARD"]
    for service in hard_services:
        query = PLATFORM_FEASIBILITY_PROMPT.format(
            service_name=service.name,
            service_description=service.description,
            service_versions=service.version,
        )
        result = invoke_structured(
            state.retrieve_info_llm, state.model_name,
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)],
            PlatformFeasibility,
        )
        if not result.linux_container_feasible:
            return {"platform_feasible": False, "platform_infeasibility_reason": result.reason}

    return {"platform_feasible": True}