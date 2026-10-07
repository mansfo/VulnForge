import json
import builtins
from pathlib import Path
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage # type: ignore

# My modules
from state import OverallState
from .utils.llm_utils import invoke_structured
from .utils.file_utils import docker_dir

from prompts import (
    SYSTEM_PROMPT,
    CVE_CLASSIFY_PROMPT,
)
from configuration import (
    langfuse_handler,
    CVEClassification,
)


def _perms_owner_only_read(perms: str) -> bool:
    p = (perms or "").strip()
    if not p.isdigit() or len(p) not in (3, 4):
        return False
    d = p[-3:]  # owner, group, other
    group_read = (int(d[1]) & 4) != 0
    other_read = (int(d[2]) & 4) != 0
    return not group_read and not other_read


def validate_classification(c) -> list:
    issues = []
    vt = c.vulnerability_type.value if hasattr(c.vulnerability_type, "value") else str(c.vulnerability_type)
    fp = (c.flag_path or "").strip()

    if vt == "sqli":
        if not fp.lower().startswith("database:"):
            issues.append(f"vulnerability_type=sqli requires flag_path 'Database: X, Table: Y, Column: Z', got '{fp}'.")
    elif vt == "ssrf":
        if not (fp.startswith("http://") or fp.startswith("https://")):
            issues.append(f"vulnerability_type=ssrf requires an internal URL flag_path (http://...), got '{fp}'.")
        if not c.requires_secondary_container:
            issues.append("vulnerability_type=ssrf requires requires_secondary_container=true.")
        if not (c.secondary_container_spec or "").strip():
            issues.append("vulnerability_type=ssrf requires a non-empty secondary_container_spec.")
    elif vt in ("xss", "csrf"):
        if not fp.startswith("/"):
            issues.append(f"vulnerability_type={vt} requires flag_path to be an application route/endpoint (starting with '/'), got '{fp}'.")
    else:
        if not fp.startswith("/"):
            issues.append(f"vulnerability_type={vt} requires an absolute filesystem flag_path (/...), got '{fp}'.")
        
    exec_user = (getattr(c, "execution_context_user", "") or "").strip()
    owner = (c.flag_owner or "").strip()
    if c.flag_permissions and c.flag_permissions.upper() != "N/A":
        if (_perms_owner_only_read(c.flag_permissions) and owner and exec_user
                and owner != exec_user and exec_user.lower() != "root"):
            if c.kill_chain_steps is not None and c.kill_chain_steps < 2:
                issues.append(
                    f"Flag is readable only by owner '{owner}', but the exploit's entry identity is "
                    f"'{exec_user}' and kill_chain_steps={c.kill_chain_steps} leaves no room for an "
                    f"escalation step. Either set flag_owner='{exec_user}' (or grant group/other read "
                    f"while keeping the flag out of any web-served path), or add the privilege-"
                    f"escalation step to '{owner}' and set kill_chain_steps >= 2."
                )

    if getattr(c, "requires_oob_interaction", False) and c.kill_chain_steps is not None and c.kill_chain_steps < 2:
        issues.append(
            "requires_oob_interaction=true (blind/callback exploit) but kill_chain_steps=1; a callback "
            "or exfiltration step is normally required — reconsider kill_chain_steps."
        )

    return issues


def classify_cve(state: OverallState):
    """Classifies the CVE type and determines the flag placement strategy"""
    if state.classification:
        print("\tSkipping CVE classification (reusing existing).")
        return {}
    print("\nClassifying CVE and determining flag placement strategy...")

    logs_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool) / "logs"
    logs_dir_path.mkdir(parents=True, exist_ok=True)
    final_report_file = logs_dir_path / "final_report.txt"

    # Build a summary of the web search result to pass to the classifier
    web_search_summary = f"Description: {state.web_search_result.desc}\nAttack Type: {state.web_search_result.attack_type}\nServices:\n"
    for service in state.web_search_result.services:
        web_search_summary += f"- [{service.dependency_type}][{service.name}][{service.version}] {service.description}\n"

    query = CVE_CLASSIFY_PROMPT.format(
        cve_id=state.cve_id,
        web_search_summary=web_search_summary,
    )

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=query)]
    result = invoke_structured(state.retrieve_info_llm, state.model_name, messages, CVEClassification, config={"callbacks": [langfuse_handler]})

    issues = validate_classification(result)
    retries = 0
    while issues and retries < 2:
        retries += 1
        print(f"\t[!] Classification inconsistent (attempt {retries}); asking the model to fix:")
        for msg in issues:
            print(f"\t    - {msg}")
        corrective = (
            "Your previous classification is internally inconsistent:\n- "
            + "\n- ".join(issues)
            + "\n\nRe-emit the FULL classification, fixing ONLY these inconsistencies and keeping "
              "every other field identical. In particular, make sure the identity that can read the "
              "flag matches the identity reached at the end of the kill chain, and that "
              "kill_chain_steps counts every escalation/pivot/callback step."
        )
        messages.append(AIMessage(content=json.dumps(result.model_dump())))
        messages.append(HumanMessage(content=corrective))
        result = invoke_structured(state.retrieve_info_llm, state.model_name, messages, CVEClassification, config={"callbacks": [langfuse_handler]})
        issues = validate_classification(result)

    if issues:
        warn = "\t[!] Classification still inconsistent after retries: " + "; ".join(issues)
        print(warn)
        try:
            with builtins.open(final_report_file, "a") as f:
                f.write("\n\nCLASSIFICATION CONSISTENCY WARNINGS:\n- " + "\n- ".join(issues) + "\n")
        except Exception:
            pass

    class_file = logs_dir_path / "classification.json"
    try:
        with builtins.open(class_file, "w") as f:
            json.dump(result.model_dump(), f, indent=4)
        print(f"\tClassification successfully saved in {class_file}")
    except Exception as e:
        print(f"\tCan't create classification.json file: {e}")

    return {"classification": result}