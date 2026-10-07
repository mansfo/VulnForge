import json
import builtins
import re
from langchain_core.messages import HumanMessage, SystemMessage # type: ignore

# My modules
from state import OverallState
from .utils.llm_utils import invoke_structured
from .utils.docker_utils import down_docker, remove_all_images

from prompts import (
    SYSTEM_PROMPT,
    CODING_PROMPT,
    REVISION_PROMPT,
    CODE_CORRECTION_PROMPT,
    FLAG_PLACEMENT_PREAMBLE,
    FLAG_RULES,
    LOCAL_EXPLOIT_SECTION,
    NETWORK_EXPLOIT_CONSTRAINT,
    REALISM_INTERNAL,
    REALISM_LOCAL,
    REALISM_NETWORK
)
from configuration import (
    langfuse_handler,
    Code,
)

REALISM_REMINDER = {
    "network": "The app must look like a real application: styled landing page, mock endpoints, realistic DB records. The vulnerability must blend into normal functionality.",
    "local": "The filesystem must look like a real system: multiple users, realistic shell history, red herring SUID binaries/crons. No obviously named vuln files.",
    "internal": "The internal service must have a plausible role, benign endpoints, realistic env vars. No host port exposure."
}

# Matches "FROM <image-name>:<tag>" — captures the image name (before the colon).
_FROM_IMAGE_RE = re.compile(r"FROM\s+([^:\s]+):[^\s]+", re.IGNORECASE)

def _detect_version_carousel(fixes: list[str], threshold: int = 3) -> str | None:
    """Return the stuck image name if the last `threshold` fixes all change only its tag.

    Technology-agnostic: works for any base image whose old version tags are
    unavailable on Docker Hub (Java services, Python services, databases, etc.).
    Returns None if the pattern is not detected.
    """
    if len(fixes) < threshold:
        return None
    recent = fixes[-threshold:]
    image_names: list[str] = []
    for fix in recent:
        matches = _FROM_IMAGE_RE.findall(fix)
        if not matches:
            return None
        image_names.extend(m.lower() for m in matches)
    unique = set(image_names)
    if len(unique) == 1:
        return unique.pop()
    return None


_CAROUSEL_HINT = (
    "VERSION-CAROUSEL DETECTED: the last several fixes all changed only the version tag "
    "of the base image '{image}', and every attempt produced the same build failure. "
    "The version tag is NOT the root cause. The image itself likely does not publish "
    "Docker Hub tags for those old versions.\n\n"
    "REQUIRED ACTION — stop varying the tag. Instead, rethink the installation strategy:\n"
    "1. Verify whether '{image}' actually ships Docker images for the required version. "
    "If it does not, you cannot use it as a base image.\n"
    "2. Switch to a general-purpose base image appropriate for the technology stack "
    "(e.g. an OS image or a language-runtime image) and install the software from its "
    "official release archive (tarball, zip, or package manager), pinning the exact "
    "vulnerable version required by the CVE.\n"
    "3. The vulnerable software and its exact version MUST still be present — you are "
    "only changing HOW it is installed, not WHAT is installed.\n"
    "Do NOT suggest any further tag-only changes to '{image}'."
)

def get_dynamic_constraints(classification, cve_id: str) -> str:
    if not classification:
        return ""
 
    vuln_type = classification.vulnerability_type.value
    rule_block = FLAG_RULES.get(vuln_type, FLAG_RULES["other"])
 
    dynamic_flag = FLAG_PLACEMENT_PREAMBLE.format(
        flag_path=classification.flag_path,
        flag_owner=classification.flag_owner,
        flag_permissions=classification.flag_permissions,
        cve_id=cve_id,
    ) + f"\n{rule_block}\n"
 
    if classification.attack_vector.value == "local":
        dynamic_net = LOCAL_EXPLOIT_SECTION
    else:
        dynamic_net = NETWORK_EXPLOIT_CONSTRAINT
 
    exec_user = getattr(classification, "execution_context_user", "the exploit runtime user")
    requires_auth = getattr(classification, "requires_auth", False)
    requires_oob = getattr(classification, "requires_oob_interaction", False)
    tech_stack = getattr(classification, "tech_stack", "unknown")
    vulnerable_component = getattr(classification, "vulnerable_component", "the vulnerable endpoint/component")
    secondary_spec = getattr(classification, "secondary_container_spec", None)
    kill_chain = getattr(classification, "kill_chain_steps", "N/A")
 
    exploit_context = f"""
        ═══════════════════════════════
        EXPLOITATION CONTEXT
        ═══════════════════════════════
        - TECH STACK: {tech_stack}
        - VULNERABLE COMPONENT: {vulnerable_component}
        - EXPLOIT MECHANICS: {classification.exploitation_summary}
        - KILL CHAIN LENGTH: {kill_chain} logical step(s)
        - POST-EXPLOIT EXECUTION CONTEXT: after completing the chain the attacker acts as '{exec_user}'.
        - RED TEAM HINT (how the attacker will proceed): {classification.red_team_initial_hint}
        """
 
    invariants = [
        (f"FLAG READABILITY vs EXECUTION CONTEXT (the single most common cause of a "
         f"'runs-but-not-exploitable' environment): the flag is specified as owner "
         f"'{classification.flag_owner}' / permissions '{classification.flag_permissions}'. The "
         f"{kill_chain}-step attack chain MUST terminate with the attacker acting as an identity that "
         f"can read it — i.e. '{classification.flag_owner}' itself, a member of its group, or root. The "
         f"post-exploit identity from classification is '{exec_user}': ensure '{exec_user}' can reach "
         f"'{classification.flag_owner}' — either they are the SAME identity, or the chain includes the "
         f"escalation from '{exec_user}' to '{classification.flag_owner}'. Keep the flag unreachable "
         f"through the app's INTENDED behaviour (web routes, static handlers, LFI-able web root, default "
         f"pages, logs) and before the exploit runs. Do NOT weaken this by exposing the flag via an endpoint."),
 
        (f"DO NOT PATCH: the environment MUST keep '{vulnerable_component}' vulnerable via the exact "
         f"mechanic described above. Do not add input validation, WAF-like filtering, or version bumps "
         f"that close this specific path, and do not create alternative or artificial paths to the flag."),
    ]
 
    if requires_auth:
        invariants.append(
            "AUTH REQUIRED: the exploit path is authenticated. Ship working, discoverable credentials "
            "(a seeded/default account) OR a reachable authentication-bypass consistent with the kill "
            "chain, so the attacker can actually reach the vulnerable component. Put those credentials "
            "in a realistic location — never inside the flag file."
        )
 
    if requires_oob:
        invariants.append(
            "OUT-OF-BAND INTERACTION: this exploit relies on a callback (reverse shell / DNS / HTTP). "
            "The attacker-facing container MUST be able to open OUTBOUND connections back to the host: "
            "do NOT declare its network as 'internal: true' and do not otherwise block egress, or the "
            "environment will silently swallow the callback and the exploit cannot complete."
        )
 
    if secondary_spec:
        invariants.append(
            f"INTERNAL TARGET: build the hidden container exactly as specified: {secondary_spec}. It "
            f"must be reachable from the vulnerable container over a shared network, bind to 0.0.0.0, "
            f"and expose NO host port."
        )
 
    numbered = "\n        ".join(f"{i}. {s}" for i, s in enumerate(invariants, 1))
    invariants_block = (
        "        ═══════════════════════════════\n"
        "        EXPLOITABILITY INVARIANTS\n"
        "        (the environment is valid ONLY if the documented attack works end-to-end)\n"
        "        ═══════════════════════════════\n"
        f"        {numbered}"
    )
 
    return f"\n{dynamic_flag}\n{dynamic_net}\n{exploit_context}\n{invariants_block}\n"
 

def generate_code(state: OverallState):
    """The agent generates/fixes the docker code to reproduce the CVE"""
    print("\nGenerating the code...")
    if state.code.directory_tree != "":
        print("\tCode already provided!")        
        return {}
    
    final_report_file = state.base_path / "dockers" / state.cve_id / state.web_search_tool/ "logs/final_report.txt"
    # Defensive: the logs dir is normally created during web_search, but guard the
    # debug entry-points (GenCode/TestCode) that skip it so this append never crashes.
    final_report_file.parent.mkdir(parents=True, exist_ok=True)
    
    services_summary = f"--- CVE METADATA & REQUIRED SERVICES ---\n"
    if state.web_search_result:
        services_summary += f"Description: {state.web_search_result.desc}\n"
        services_summary += f"Services to include:\n"
        for service in state.web_search_result.services:
            services_summary += f"- [{service.dependency_type}] {service.name} (Version: {service.version})\n"
    services_summary += "----------------------------------------\n\n"
    
    code_gen_query = services_summary + CODING_PROMPT.format(
        cve_id=state.cve_id, 
        cwd=state.base_path / "dockers" / state.cve_id / state.web_search_tool,
        realism_section=build_realism_section(state.classification),
    )
        
    dynamic_constraints = get_dynamic_constraints(state.classification, state.cve_id)
    code_gen_query += dynamic_constraints
    code_gen_query += "\n<|think|>"
    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=code_gen_query)]
    generated_code = invoke_structured(state.builder_llm, state.model_name, messages, Code, config={"callbacks": [langfuse_handler]}, max_tokens=16384*2)
    
    response = f"Directory tree:\n{generated_code.directory_tree}\n\n"
    for f in generated_code.files:
        response += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"
        
    output_string = f"\nThis is the first version of the generated code:\n\n{response}\n\n"
    with builtins.open(final_report_file, "a") as f:
        f.write(output_string)
        
    print("\tCode generated!")
    return {"code": generated_code}


def save_code(state: OverallState):
    print("\nSaving code...")

    code_dir_path = state.base_path / "dockers" / state.cve_id / state.web_search_tool
    code_dir_path.mkdir(parents=True, exist_ok=True)

    # --- Normalize file locations (strip accidental absolute / prefixed paths) ---
    for f in state.code.files:
        location = f.location

        if location.startswith(str(code_dir_path)):
            location = location.replace(str(code_dir_path), "", 1)

        bad_prefix_dockers = f"dockers/{state.cve_id}/{state.web_search_tool}"
        bad_prefix_cve = f"{state.cve_id}/{state.web_search_tool}"
        bad_prefix_tool = f"{state.web_search_tool}"
        # Match on a path-boundary so a legit file like "custom_no_tool_helper/x.py"
        # is NOT mangled into "_helper/x.py".
        for bad in (bad_prefix_dockers, bad_prefix_cve, bad_prefix_tool, state.cve_id):
            if location == bad or location.startswith(bad + "/") or location.startswith(bad + "\\"):
                location = location[len(bad):]
                break

        location = location.lstrip("/\\")
        f.location = location

    new_rel = {f.location for f in state.code.files}

    # --- Snapshot existing on-disk files (excluding logs) ---
    old_rel = set()
    for p in code_dir_path.rglob("*"):
        if p.is_file():
            rel = p.relative_to(code_dir_path)
            if rel.parts and rel.parts[0] == "logs":
                continue
            old_rel.add(str(rel))

    has_compose = any(r.endswith("docker-compose.yml") for r in new_rel)
    old_dockerfiles = {r for r in old_rel if r.endswith("Dockerfile")}
    missing_dockerfiles = old_dockerfiles - new_rel
    safe_to_prune = has_compose and not missing_dockerfiles

    # --- Persist the structured code for auditing ---
    code_file = code_dir_path / "logs/code.json"
    code_file.parent.mkdir(parents=True, exist_ok=True)
    with builtins.open(code_file, "w") as out_json:
        json.dump(state.code.model_dump(), out_json, indent=4)

    # --- Write all returned files (overwrite in place) ---
    for f in state.code.files:
        file_path = code_dir_path / f.location
        resolved_file_path = file_path.resolve()
        if not str(resolved_file_path).startswith(str(code_dir_path.resolve())):
            print(f"\t[-] Skipping file outside working dir: {f.location}")
            continue

        resolved_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved_file_path, "w") as out_file:
            out_file.write(f.content)
        print(f"\tSaved file: {resolved_file_path}")

    # --- Remove orphans only when the revision is complete ---
    if safe_to_prune:
        orphans = old_rel - new_rel
        for rel in orphans:
            orphan_path = (code_dir_path / rel).resolve()
            if not str(orphan_path).startswith(str(code_dir_path.resolve())):
                continue
            try:
                orphan_path.unlink()
                print(f"\tRemoved orphan file: {orphan_path}")
            except Exception as e:
                print(f"\t[-] Error while deleting orphan {rel}: {e}")

        # Prune now-empty directories (deepest first), never touching logs.
        for p in sorted(code_dir_path.rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if p.is_dir() and p.name != "logs":
                try:
                    next(p.iterdir())
                except StopIteration:
                    try:
                        p.rmdir()
                    except Exception:
                        pass
                except Exception:
                    pass
    else:
        reason = "no docker-compose.yml in revision" if not has_compose \
            else f"missing Dockerfile(s): {sorted(missing_dockerfiles)}"
        print(f"\t[!] Orphan pruning skipped ({reason}). "
              f"Keeping previous files to avoid an unbuildable tree.")

    print("\tCode saved!")
    return {"code": state.code}


def revise_code(state: OverallState):
    """The agent is tasked with revising the Docker's code to fix the errors"""
    print("\nRevising code...")
    state.milestones.docker_builds = False
    state.milestones.docker_runs = False
    state.milestones.code_hard_version = False
    state.milestones.network_setup = False
    state.stats.services_ok = False
    state.milestones.exploit_surface_ok = False
    state.milestones.flag_placed = False
    
    code_dir_path = state.base_path / "dockers" / state.cve_id / state.web_search_tool
    final_report_file = code_dir_path / "logs/final_report.txt"
    down_docker(code_dir_path=code_dir_path)
    if state.revision_type == "Not Vulnerable Version":
        remove_all_images()
            
    code = "This is the code you have to revise:\n"
    for f in state.code.files:
        code += "-" * 10 + f" {f.location} " + "-" * 10 + f"\n{f.content}\n\n"

    if not state.dynamic_hint:
        stuck_image = _detect_version_carousel(state.fixes)
        if stuck_image:
            state.dynamic_hint = _CAROUSEL_HINT.format(image=stuck_image)
            print(f"\t[!] Version carousel detected on '{stuck_image}' — injecting strategy hint.")
    
    active_explanation = state.fail_explanation or "The environment failed validation."
    if state.dynamic_hint != "":
        active_explanation += f"\n\n[CRITICAL ARCHITECT DIRECTIVE]:\n{state.dynamic_hint}"
    dynamic_constraints = get_dynamic_constraints(state.classification, state.cve_id)

    service_list = []
    hard_service_versions = ""
    for service in state.web_search_result.services:
        service_list.append(service.name)
        if service.dependency_type == "HARD":
            hard_service_versions += f"\n\t\t- {service.name}: {service.version}"

    attack_vector = state.classification.attack_vector if state.classification else "network"
    has_secondary = getattr(state.classification, "requires_secondary_container", False)
        
    reminder_parts = [REALISM_REMINDER.get(attack_vector, REALISM_REMINDER["network"])]
    if has_secondary:
        reminder_parts.append(REALISM_REMINDER["internal"])
    realism_reminder = "\n".join(reminder_parts)
        
    revision_query = REVISION_PROMPT.format(
        fail_explanation=active_explanation,
        revision_goal=state.revision_goal,
        revision_type=state.revision_type,
        cve_id=state.cve_id,
        service_versions=hard_service_versions,
        realism_reminder=realism_reminder,
        dynamic_constraints=dynamic_constraints
    )

    revision_query += "\n<|think|>"
    revision_query += f"\n\nFIXES ALREADY ATTEMPTED (do NOT repeat these):\n"
    for prev in state.fixes:
        revision_query += f"- {prev}\n"
    recent_messages = state.messages[1:]
        
    messages = [SystemMessage(content=SYSTEM_PROMPT + "  Never use Markdown in your answers.")]
    messages += recent_messages + [HumanMessage(content=code), HumanMessage(content=revision_query)]
    
    fix_suggestion = state.builder_llm.invoke(messages, config={"callbacks": [langfuse_handler]})

    code_correction_query = CODE_CORRECTION_PROMPT.format(
        fail_explanation=active_explanation,
        revision_goal=state.revision_goal,
        fix=fix_suggestion.content,
        cve_id=state.cve_id,
        fixes=state.fixes,
        cwd=code_dir_path,
        dynamic_constraints=dynamic_constraints
    )
    code_correction_query += "\n<|think|>"
    messages = [SystemMessage(content=SYSTEM_PROMPT)]
    messages += recent_messages + [HumanMessage(content=code), HumanMessage(content=code_correction_query)]
    
    result = invoke_structured(state.builder_llm, state.model_name, messages, Code, config={"callbacks": [langfuse_handler]}, max_tokens=16384*2)
    output_string = f"\t- ERROR: {state.fail_explanation}"
    output_string += f"\n\t- FIX: {fix_suggestion.content}"
        
    with builtins.open(final_report_file, "a") as f:
        f.write(f"\n{output_string}\n")

    state.stats.test_iteration += 1
    state.stats.total_iterations += 1
    return {
        "stats": state.stats,
        "milestones": state.milestones,
        "code": result,
        "fixes": state.fixes + [fix_suggestion.content],
        "dynamic_hint": "",
    }
    

def build_realism_section(classification) -> str:
    """Selects realism guidance based on attack_vector and requires_secondary_container."""
    
    parts = []
    if classification.attack_vector in ("network", "adjacent"):
        parts.append(REALISM_NETWORK)
    else:
        parts.append(REALISM_LOCAL)

    if getattr(classification, "requires_secondary_container", False):
        parts.append(REALISM_INTERNAL)

    return "\n\n".join(parts)