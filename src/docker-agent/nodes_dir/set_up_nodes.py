
import os
import json
import requests
import builtins
from pathlib import Path
from typing import Literal
from langchain_openai import ChatOpenAI # type: ignore

# My modules
from state import OverallState
from .utils.file_utils import create_dir, docker_dir

def get_cve_id(state: OverallState):
    """Checks if the CVE ID is correctly retrieved from the initialized state"""
    print(f"The provided CVE ID is {state.cve_id.upper()}!")
    
    logs_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs"
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
        
    updated_final_report = "="*10 + f" {state.cve_id} Final Report "  + "="*10
    updated_final_report += "\n\n" + "-"*10 + f" Initial Parameters " + "-"*10 
    updated_final_report += f"\n'model_name': {state.model_name}\n'cve_id': {state.cve_id}\n'web_search_tool': {state.web_search_tool}\n'verbose_web_search': {state.verbose_web_search}\n'web_search_result': {state.web_search_result}"
    updated_final_report += f"\n'code': {state.code}\n'messages': {state.messages}\n'milestones': {state.milestones}\n'debug': {state.debug}\n"
    updated_final_report += "-"*40 + "\n\n"
    
    final_report_file = logs_dir_path / "final_report.txt"
    with builtins.open(final_report_file, "w") as f:
        f.write(updated_final_report)
        
    or_api_key = os.environ.get("MY_OPENROUTER_API_KEY", "")
    local_key = os.environ.get("LOCAL_KEY", "")

    # Initialize the LLM
    if state.use_local == True:
        if state.model_name == "gemma":
            state.retrieve_info_llm = ChatOpenAI(
                base_url="https://llm.polito.it",
                api_key=local_key,
                model="gemma-4-31b",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
            state.builder_llm = ChatOpenAI(
                base_url="https://llm.polito.it",
                api_key=local_key,
                model="gemma-4-31b",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
        else:
            state.retrieve_info_llm = ChatOpenAI(
                base_url="https://llm.polito.it",
                api_key=local_key,
                model="polito/deepseek-v4",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
            state.builder_llm = ChatOpenAI(
                base_url="https://llm.polito.it",
                api_key=local_key,
                model="polito/deepseek-v4",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )

    else:
        state.retrieve_info_llm = ChatOpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=or_api_key,
            model="deepseek/deepseek-v4-flash",
            temperature=0.0, 
            max_retries=2, 
            max_completion_tokens=10000
        )

        if state.model_name == "gpt-4o":
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                model="openai/gpt-4o", 
                temperature=0.5, 
                max_retries=2, 
                max_completion_tokens=10000
            )
        elif state.model_name == "gpt-5":
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=or_api_key,
                model="openai/gpt-5-mini", 
                max_retries=2,
                temperature=0.0,
            )
        elif state.model_name == "claude-sonnet":
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=or_api_key,
                model="anthropic/claude-sonnet-5",
                temperature=0.0,
                max_retries=2
            )
        elif state.model_name == "deepseek4":
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=or_api_key,
                model="deepseek/deepseek-v4-flash",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
        elif state.model_name == "deepseek4pro":
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=or_api_key,
                model="deepseek/deepseek-v4-flash",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
        else:
            state.builder_llm = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=or_api_key,
                model="deepseek/deepseek-v4-flash",
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
    return {
        "retrieve_info_llm": state.retrieve_info_llm,
        "builder_llm": state.builder_llm,
        "cve_id": state.cve_id.upper(),
    }


def assess_cve_id(state: OverallState):    
    """The agent checks if the CVE ID exists in the MITRE CVE database"""
    print("\nChecking if the CVE ID exists...")
    response = requests.get(f"https://cveawg.mitre.org/api/cve/{state.cve_id}")
    
    logs_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs"
    final_report_file = logs_dir_path / "final_report.txt"

    if response.status_code == 200:
        print(f"\t{state.cve_id} exists!")
        
        if not logs_dir_path.exists():
            create_dir(dir_path=logs_dir_path)
        
        state.milestones.cve_id_ok = True        
        return {"milestones": state.milestones}

    elif response.status_code == 404:
        output_string = f"The record for {state.cve_id} does not exist."
        print(output_string)
        
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
        return {}

    else:
        output_string = f"Failed to fetch CVE: {response.status_code}"
        print(output_string)
        
        with builtins.open(final_report_file, "a") as f:
            f.write(f"{output_string}\n")
            
        return {}

def route_cve(state: OverallState) -> Literal["Found", "Not Found"]:
    """Terminate the graph or go to the next step"""
    print(f"\nRouting CVE (cve_id_ok = {state.milestones.cve_id_ok})")
    if state.milestones.cve_id_ok:
        return "Found"
    else:
        milestone_file = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs/milestones.json"
        with builtins.open(milestone_file, "w") as f:
            json.dump(state.milestones.model_dump(), f, indent=4)

        print("\nExecution Terminated!\n\n\n")
        return "Not Found"


def route_start(state: OverallState) -> Literal["Skip to Red Team", "Scout", "GenCode", "TestCode", "Normal Workflow"]:
    """Route directly to red team if the flag is set"""
    if state.skip_to_red_team:
        print(f"\nRouting start(skip_to_red_team = {state.skip_to_red_team})")
        return "Skip to Red Team"
    elif state.skip_to_scout:
        print(f"\nRouting start(skip_to_scout = {state.skip_to_scout})")
        return "Scout"
    elif state.reuse_classification:
        return "GenCode"
    elif state.reuse_web_search_and_code:
        return "TestCode"
    else:
        return "Normal Workflow"