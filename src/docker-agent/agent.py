import json
import builtins
from pathlib import Path
from langchain_core.messages import SystemMessage # type: ignore

# My modules
from configuration import langfuse_handler
from prompts import SYSTEM_PROMPT
from graph import compiled_workflow
from nodes_dir.utils.docker_utils import remove_all_images, down_docker
from state import PROJECT_ROOT

import logging

logging.getLogger("opentelemetry.attributes").setLevel(logging.ERROR)
logging.getLogger("langfuse").setLevel(logging.ERROR)

#* RUN AGENT *#
def run_agent(cve_list: list[str], web_search_mode: str, model_name: str, use_local: bool, verbose_web_search: bool, reuse_web_search: bool, reuse_classification: bool, reuse_web_search_and_code: bool, relax_web_search_constraints: bool, skip_to_red_team: bool = False, skip_to_scout: bool = False):
    if web_search_mode == "all": web_search_mode = ["custom", "custom_no_tool", "openai", "duckduckgo"]
    elif web_search_mode == "all-openai": web_search_mode = ["custom", "custom_no_tool"]
    else: web_search_mode = [f"{web_search_mode}"]
    
    for wsm in web_search_mode:        
        for cve in cve_list:                
            if reuse_web_search or reuse_web_search_and_code or reuse_classification:
                with builtins.open(PROJECT_ROOT / "dockers" / cve / wsm / "logs/web_search_results.json", 'r') as f:
                    web_search_data = json.load(f)
                if reuse_web_search_and_code:
                    with builtins.open(PROJECT_ROOT / "dockers" / cve / wsm / "logs/code.json", 'r') as f:
                        code_data = json.load(f)    

            try:
                loaded_classification = None
                loaded_milestones = None
                loaded_stats = None

                if skip_to_red_team or reuse_classification or reuse_web_search_and_code or skip_to_scout:
                    class_path = PROJECT_ROOT / "dockers" / cve / wsm / "logs/classification.json"
                    if class_path.exists():
                        loaded_classification = json.loads(class_path.read_text())
                
                if skip_to_red_team or skip_to_scout:
                    miles_path = PROJECT_ROOT / "dockers" / cve / wsm / "logs/milestones.json"
                    if miles_path.exists():
                        loaded_milestones = json.loads(miles_path.read_text())
                    
                    stats_path = PROJECT_ROOT / "dockers" / cve / wsm / "logs/stats.json"
                    if stats_path.exists():
                        loaded_stats = json.loads(stats_path.read_text())

                input_data = {             
                    "model_name": model_name,
                    "cve_id": cve,
                    "web_search_tool": wsm,
                    "use_local": use_local,
                    "verbose_web_search": verbose_web_search,
                    "messages": [SystemMessage(content=SYSTEM_PROMPT)],
                    "debug": "relax-web-search-constraints" if relax_web_search_constraints else "",
                    "skip_to_red_team": skip_to_red_team,
                    "skip_to_scout": skip_to_scout,
                    "reuse_classification": reuse_classification,
                    "reuse_web_search_and_code": reuse_web_search_and_code,
                }

                if reuse_web_search or reuse_classification or reuse_web_search_and_code:
                    input_data["web_search_result"] = web_search_data
                if reuse_web_search_and_code:
                    input_data["code"] = code_data
                if loaded_classification:
                    input_data["classification"] = loaded_classification
                if loaded_milestones:
                    input_data["milestones"] = loaded_milestones
                if loaded_stats:
                    input_data["stats"] = loaded_stats

                result = compiled_workflow.invoke(
                    input=input_data,
                    config={"callbacks": [langfuse_handler], "recursion_limit": 100},
                )

                if len(cve_list) == 1 and len(web_search_mode) == 1:
                    return result
                
            except Exception as e:
                print(f"\n\n===== [AGENTIC WORKFLOW FAILED] =====\n{e}\n"+"="*37+"\n\n")
                code_dir_path = PROJECT_ROOT / "dockers" / cve / wsm 
                down_docker(code_dir_path=code_dir_path)
                remove_all_images()  
                with open("results.txt", "a") as f:
                    f.write(f"{cve} | False | False | WorkflowErr\n")           
                    f.close()   
                continue


def main():
    remove_all_images()
    
    cve_list = [
        "CVE-2017-8386"
    ]

    print(len(cve_list), cve_list)
    result = run_agent(
        cve_list=cve_list,
        web_search_mode="custom_no_tool",
        model_name="deepseek",
        use_local=False,
        verbose_web_search=True,
        reuse_web_search=False,
        reuse_classification=False,
        reuse_web_search_and_code=False,
        skip_to_scout=False,
        skip_to_red_team=False,
        relax_web_search_constraints=True
    )

if __name__ == "__main__":
    main()