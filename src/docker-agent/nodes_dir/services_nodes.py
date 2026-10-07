import os
import json
import builtins
import requests
from typing import Literal
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage # type: ignore
from langchain_community.tools.ddg_search import DuckDuckGoSearchRun # type: ignore
from langchain_core.output_parsers import PydanticOutputParser # type: ignore

# My modules
from state import OverallState
from tools.openai_tools import openai_web_search
from tools.custom_web_search import web_search_func
from tools.custom_tool_web_search import web_search, web_search_tool_func
from .utils.file_utils import create_dir, docker_dir
from .utils.llm_utils import invoke_structured

from prompts import (
    SYSTEM_PROMPT,
    WEB_SEARCH_FORMAT_PROMPT,
    CUSTOM_WEB_SEARCH_PROMPT,
    OPENAI_WEB_SEARCH_PROMPT,
    GET_VULHUB_SERVICES_PROMPT
)
from configuration import (
    langfuse_handler,
    WebSearch,
    VulhubGroundTruth
)

def web_search(state: OverallState):
    """The agent performs a web search to gather relevant information about the services needed to generate the vulnerable Docker code"""
    print("\nSearching the web...")
    code_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool)
    logs_dir_path = code_dir_path / "logs"
   
    if state.web_search_result.desc != "":
        print("\tWeb search results already provided!")
        response = f"CVE description: {state.web_search_result.desc}\nAttack Type: {state.web_search_result.attack_type}\nServices (format: [SERVICE-DEPENDENCY-TYPE][SERVICE-NAME][SERVICE-VERSIONS] SERVICE-DESCRIPTION):"
        for service in state.web_search_result.services:
            response += f"\n- [{service.dependency_type}][{service.name}][{service.version}] {service.description}"
        
        final_report_file = logs_dir_path / "final_report.txt"
        with builtins.open(final_report_file, "a") as f:
            f.write(response)
            
        return {"messages": state.messages + [AIMessage(content=response)]}
    
    # Create the directory to save logs (if it does not exist)
    if not logs_dir_path.exists():
        create_dir(dir_path=logs_dir_path)
    
    # Invoking the LLM with the chosen web search mode 
    if state.web_search_tool == "custom":
        web_query = CUSTOM_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        llm_custom_web_search_tool = state.retrieve_info_llm.bind_tools([web_search])        
        tool_call = llm_custom_web_search_tool.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=web_query)],
            config={"callbacks": [langfuse_handler]}
        )
        # Extract the tool arguments from the LLM call
        tool_call_args = json.loads(tool_call.additional_kwargs['tool_calls'][0]['function']['arguments'])
        query, cve_id = tool_call_args['query'], tool_call_args['cve_id']
        print(f"\tThe LLM invoked the 'web search' tool with parameters: query={query}, cve_id={cve_id}")
        #NOTE: 'web_search_tool_func' internally formats the response into a WebSearch Pydantic class
        formatted_response, in_token, out_token = web_search_tool_func(query=query, cve_id=cve_id, n_documents=5, verbose=state.verbose_web_search, model=state.model_name)
    
    elif state.web_search_tool == "custom_no_tool":
        #NOTE: 'web_search_func' internally formats the response into a WebSearch Pydantic class
        formatted_response, in_token, out_token = web_search_func(cve_id=state.cve_id, n_documents=5, verbose=state.verbose_web_search, model=state.model_name)
    
    elif state.web_search_tool == "openai":
        web_query = OPENAI_WEB_SEARCH_PROMPT.format(cve_id=state.cve_id)
        
        # Invoke the LLM to perform the web search and extract the token usage
        llm_openai_web_search_tool = state.retrieve_info_llm.bind_tools([openai_web_search])
        web_search_result = llm_openai_web_search_tool.invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=web_query)],
            config={"callbacks": [langfuse_handler]}
        )
        in_token, out_token = web_search_result.usage_metadata['input_tokens'], web_search_result.usage_metadata['output_tokens']
        response_sourceless = web_search_result.content[0]["text"]
        
        # Invoke the LLM to convert the web search results into a structured output
        messages = [
            SystemMessage(content=SYSTEM_PROMPT + f"  Never use Markdown in your answers.\n\n{parser.get_format_instructions()}"),
            HumanMessage(content=WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=response_sourceless)),
        ]
        formatted_response = invoke_structured(state.retrieve_info_llm, state.model_name, messages, WebSearch, config={"callbacks": [langfuse_handler]})
    
    elif state.web_search_tool == "duckduckgo":
        search_tool = DuckDuckGoSearchRun()
        raw_query = f"{state.cve_id} vulnerability details affected services"
        raw_search_result = search_tool.invoke(raw_query)
        parser = PydanticOutputParser(pydantic_object=WebSearch)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT + f"  Never use Markdown in your answers.\n\n{parser.get_format_instructions()}"),
            HumanMessage(content=WEB_SEARCH_FORMAT_PROMPT.format(web_search_result=raw_search_result)),
        ]
        formatted_response = invoke_structured(state.retrieve_info_llm, state.model_name, messages, WebSearch, config={"callbacks": [langfuse_handler]})
    else:
        raise ValueError("Invalid web search tool specified. Use 'custom', 'custom_no_tool', 'openai' or 'duckduckgo'.")    
    
    # Building response to be added to messages 
    response = f"\nCVE description: {formatted_response.desc}\nAttack Type: {formatted_response.attack_type}\nServices (format: [SERVICE-DEPENDENCY-TYPE][SERVICE-NAME][SERVICE-VERSIONS] SERVICE-DESCRIPTION):\n"
    for service in formatted_response.services:
        response += f"- [{service.dependency_type}][{service.name}][{service.version}] {service.description}\n"
        
    final_report_file = logs_dir_path / "final_report.txt"
    with builtins.open(final_report_file, "a") as f:
        f.write(response)
            
    print(f"\t[TOKEN USAGE INFO] This web search used {in_token} input tokens and {out_token} output tokens")
    
    # Saving web search log
    web_search_dict = formatted_response.model_dump()
    web_search_dict["input_tokens"] = in_token
    web_search_dict["output_tokens"] = out_token
    if state.web_search_tool == "custom":
        web_search_dict["query"] = query
    
    web_search_file = logs_dir_path / f"web_search_results.json"
    with builtins.open(web_search_file, 'w') as fp:
        json.dump(web_search_dict, fp, indent=4)
    print(f"\tWeb search result saved to: {web_search_file}")

    return {
        "web_search_result": formatted_response,
        "messages": state.messages + [AIMessage(content=response)],
    }
    
def get_dynamic_vulhub_services(cve_id: str, llm, model_name: str) -> list:
    print(f"\t[+] Fetching Vulhub repository tree for {cve_id}...")
    
    tree_url = "https://api.github.com/repos/vulhub/vulhub/git/trees/master?recursive=1"
    headers = {"Accept": "application/vnd.github.v3+json"}
        
    try:
        response = requests.get(tree_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            tree_data = response.json().get("tree", [])

            target_path = None
            for item in tree_data:
                path = item.get("path", "")
                if cve_id.upper() in path and path.endswith("docker-compose.yml"):
                    target_path = path
                    break
            
            if target_path:
                print(f"\t[+] Found match in Vulhub: {target_path}")
                raw_url = f"https://raw.githubusercontent.com/vulhub/vulhub/master/{target_path}"
                compose_resp = requests.get(raw_url, timeout=10)
                
                if compose_resp.status_code == 200:
                    compose_content = compose_resp.text
                    print(f"\t[+] docker-compose.yml downloaded! Extracting Ground Truth via LLM...")
                    
                    prompt = GET_VULHUB_SERVICES_PROMPT.format(
                        cve_id=cve_id,
                        compose_content=compose_content
                    )
                    
                    messages = [SystemMessage(content="You are a JSON data extractor."), HumanMessage(content=prompt)]
                    
                    gt_result = invoke_structured(llm, model_name, messages, VulhubGroundTruth)
                    return gt_result.services
            else:
                print(f"\t[-] {cve_id} not found in Vulhub tree.")
                
        elif response.status_code == 403 or response.status_code == 429:
            print("\t[-] GitHub API rate limit exceeded. Consider exporting a GITHUB_TOKEN.")
        else:
            print(f"\t[-] GitHub API returned status code: {response.status_code}")
            
    except Exception as e:
        print(f"\t[-] Error fetching from Vulhub: {e}")
        
    return []


def route_services(state: OverallState) -> Literal["Ok", "Not Ok"]:    
    """Route to the code generator or terminate the graph"""
    print(f"\nRouting services (hard_service={state.milestones.hard_service}, hard_version={state.milestones.hard_version}, soft_services={state.milestones.soft_services})")
    if state.debug == "relax-web-search-constraints" or (state.milestones.hard_service and state.milestones.hard_version and state.milestones.soft_services):
        return "Ok"
    else:
        milestone_file = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs/milestones.json"
        with builtins.open(milestone_file, "w") as f:
            json.dump(state.milestones.model_dump(), f, indent=4)

        print("\nExecution Terminated!\n\n\n")
        return "Not Ok"