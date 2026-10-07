
from langgraph.graph import StateGraph, START, END # type: ignore

# My modules
from state import OverallState
from nodes_dir.assessment_nodes import *
from nodes_dir.set_up_nodes import *
from nodes_dir.platform_check_nodes import *
from nodes_dir.code_nodes import *
from nodes_dir.services_nodes import *
from nodes_dir.red_team_nodes import *
from nodes_dir.test_code_nodes import *
from nodes_dir.classification_nodes import *
from nodes_dir.debugger_nodes import *

workflow = StateGraph(OverallState)

# Add nodes to the workflow
workflow.add_node("get_cve_id", get_cve_id)
workflow.add_node("assess_cve_id", assess_cve_id)
workflow.add_node("web_search", web_search)
workflow.add_node("assess_platform_feasibility", assess_platform_feasibility)
workflow.add_node("llm_platform_feasibility", assess_platform_feasibility_llm)
workflow.add_node("classify_cve", classify_cve)
workflow.add_node("generate_code", generate_code)
workflow.add_node("save_code", save_code)
workflow.add_node("test_code", test_code)
workflow.add_node("test_exploit_surface", test_exploit_surface)
workflow.add_node("revise_code", revise_code)
workflow.add_node("assess_vuln", assess_vuln)
workflow.add_node("sanity_check", sanity_check)
workflow.add_node("red_team", red_team)
workflow.add_node("debug_node", debugger)

# Add edges to the workflow
workflow.add_edge(START,"get_cve_id")
workflow.add_conditional_edges(
    "get_cve_id",
    route_start,
    {
        "Skip to Red Team": "red_team",
        "Scout": "assess_vuln",
        "GenCode": "generate_code",
        "TestCode": "test_code",
        "Normal Workflow": "assess_cve_id",
    },
)
workflow.add_conditional_edges(
    "assess_cve_id",
    route_cve,
    {
        "Found": "web_search",
        "Not Found": END,
    },
)
workflow.add_edge("web_search", "assess_platform_feasibility")
workflow.add_edge("assess_platform_feasibility", "llm_platform_feasibility")
workflow.add_conditional_edges(
    "llm_platform_feasibility",
    route_platform_feasibility,
    {
        "Feasible": "classify_cve",
        "Not Feasible": END,
    },
)
workflow.add_edge("classify_cve", "generate_code")
workflow.add_edge("generate_code", "save_code")
workflow.add_edge("save_code", "test_code")
workflow.add_edge("test_code", "test_exploit_surface")
workflow.add_conditional_edges(
    "test_exploit_surface",
    route_test,
    {
        "Ok": "sanity_check",
        "Stop Testing": END, 
        "Revise Code": "revise_code"
    },
)
workflow.add_edge("revise_code", "save_code")

workflow.add_conditional_edges(
    "sanity_check",
    route_sanity,    
    {
        "Ok": "assess_vuln",           
        "Exposed": "revise_code",   
        "End": END,
    },
)
workflow.add_edge("assess_vuln", "red_team")
workflow.add_conditional_edges(
    "red_team",
    route_after_red_team,
    {
        "End": END,
        "Debugger": "debug_node"    
    },
)

workflow.add_conditional_edges(
    "debug_node",
    route_debugger,
    {
        "Soft Fix": "red_team",    
        "Hard Fix": "save_code"     
    }
)

# Compile the graph
compiled_workflow = workflow.compile()
