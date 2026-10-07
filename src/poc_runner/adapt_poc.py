import json
import re
from pathlib import Path
import subprocess
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from langchain_core.output_parsers import PydanticOutputParser  # type: ignore


class AdaptedPoC(BaseModel):
    script: str = Field(description="The adapted PoC script, ready to run")
    language: str = Field(description="'python' or 'bash'")
    explanation: str = Field(description="What was changed and why")


class RepairedPoC(BaseModel):
    script: str = Field(description="The repaired PoC script, ready to run")
    language: str = Field(description="'python' or 'bash'")
    diagnosis: str = Field(description="The most likely reason the previous attempt failed")
    changes: list[str] = Field(description="Small, concrete changes made to the previous PoC")
    explanation: str = Field(description="Why the repair should address the observed failure")


ADAPT_PROMPT = r"""
You are adapting an existing PoC to run against a local Docker environment.

CVE: {cve_id}

FLAG (capture oracle):
- A flag may be present at a known PATH inside the target, or may be exposed through
  the vulnerable application/database depending on the environment.
- The exact flag VALUE is unknown to you.
- The only valid capture is to obtain the value from the RUNNING target and print it.
- Never guess, derive, reconstruct, or hardcode a flag value.

CLASSIFICATION:
{classification}

DOCKER COMPOSE:
{compose_content}

GENERATED ENVIRONMENT FILES:
{env_files}

ORIGINAL PoC:
{poc_script}

Make ONLY the necessary changes to adapt the delivery mechanism and target variables,
preserving the core vulnerability technique:

1. Point the script to http://localhost:<correct_host_port>.
2. Analyze topology. If the vulnerable component is behind a proxy or custom web
   application, translate the original PoC's direct API calls into the equivalent
   exposed endpoints.
3. Add required authentication using credentials present in the environment context.
4. Adapt hardcoded paths, filenames, commands, endpoints, and target variables.
5. Hardcode CLI arguments required by the original PoC.
6. Print useful response/output and extract a flag-shaped value from live target output.
7. Remove Docker commands.
8. Convert Python 2 to Python 3 when necessary.

CRITICAL: look carefully to the environment files, in order to match the expected endpoints and URLs.

STRICT CONSTRAINTS:
- Network-only from the host machine.
- Do not use docker exec, docker cp, or any Docker command inside the adapted PoC.
- Do not read the flag directly from environment files.
- Preserve the vulnerability mechanism. Do not replace it with a different exploit.
- If the PoC cannot be adapted to a network-only execution, return an empty script.
- If the PoC is unrelated to {cve_id}, return an empty script.
- If the vulnerability is purely local privilege escalation and cannot be exercised
  remotely, return an empty script.
- Never hardcode a flag value.
- Use only Python standard libraries plus requests for Python PoCs.
- Output must be valid JSON.
- You already have the possibility to use tools like ysoserial or php, NEVER download anything. If the PoC requires to download something, omit that instructions from the adapted script.

CRITICAL — CLI ARGUMENTS:
The adapted PoC MUST be fully self-contained with zero CLI arguments.
If the original uses argparse, sys.argv, or getopt, remove ALL argument parsing
and hardcode every value directly in the script body.

WRONG (leaves argparse intact):
  parser.add_argument('-u', '--url', required=True)
  args = parser.parse_args()
  target = args.url

RIGHT (hardcoded):
  target = "http://localhost:port"
"""

OOB_BLOCK = """
OOB INTERACTION REQUIRED:
- Host IP reachable from containers: {host_ip}  ← use this, do NOT guess
- Start your listener with: threading.Thread(target=..., daemon=True).start()
  BEFORE sending the payload. Never sequential.
- Use port 9444 (guaranteed free). Never 80/8080/8000.
- Wait max 15 seconds for callback, then report failure explicitly.
"""

REPAIR_PROMPT = r"""
You are repairing an LLM-adapted PoC after a REAL execution against a local Docker
environment failed to capture the target flag.

CVE: {cve_id}

The flag value is unknown to you. It may be a file value or may be returned through
the vulnerable application/database. The only valid solution is to obtain it from
the running target at runtime. Never guess or hardcode it.

CLASSIFICATION:
{classification}

DOCKER COMPOSE:
{compose_content}

GENERATED ENVIRONMENT FILES:
{env_files}

ORIGINAL PoC:
{original_poc}

PREVIOUS ADAPTED PoC:
{adapted_poc}

AUTOMATIC DIAGNOSTIC HINT:
{diagnosis}

PREVIOUS EXECUTION OUTPUT:
{previous_output}

REPAIR HISTORY:
{repair_history}

TASK:
1. Inspect the complete execution output before deciding what failed.
2. Identify the most likely incorrect assumption in the previous adaptation.
3. Make the smallest possible change that addresses that failure.
4. Preserve the original vulnerability mechanism and the working parts of the previous
   PoC. Do NOT rewrite the exploit from scratch unless the previous script is clearly
   unusable.
5. Preserve working endpoint, authentication, payload, and target variables unless
   the execution evidence implicates them.
6. The repaired PoC must remain network-only from the host.
7. Do not use docker exec, docker cp, or any Docker command.
8. Never hardcode or reconstruct the flag.
9. If the previous PoC is fundamentally incompatible with the environment, return an
   empty script and explain why.
10. Return a complete runnable Python 3 or Bash PoC, not a patch or diff.

The automatic diagnostic is only a hint. It is NOT ground truth. Use the actual output.

IMPORTANT:
- Do not invent a new vulnerability.
- Do not change CVE technique merely because the first attempt failed.
- Prefer one or two targeted changes over a wholesale rewrite.
- Keep useful response printing and runtime flag extraction.

<|think|>
"""


_PLACEHOLDER_RE = re.compile(r"FLAG\{verified_[^}]*\}")


def build_env_files_context(code_dir: Path) -> str:
    skip_dirs = {"logs", "poc_runner"}
    skip_extensions = {".json", ".md", ".txt", ".log"}
    skip_filenames = {
        "final_exploit.py", "final_exploit.sh",
        "adapted_poc.py", "adapted_poc.sh",
        "opencode.json",
    }

    context = ""
    for f in sorted(code_dir.rglob("*")):
        if not f.is_file():
            continue
        if any(part in skip_dirs for part in f.parts):
            continue
        if f.name in skip_filenames:
            continue
        if f.name == "docker-compose.yml":
            continue
        if f.suffix.lower() in skip_extensions:
            continue

        rel_path = f.relative_to(code_dir)
        try:
            content = f.read_text(errors="ignore")
            content = _PLACEHOLDER_RE.sub("FLAG{__REDACTED__}", content)
            context += f"\n--- {rel_path} ---\n{content}\n"
        except Exception:
            continue

    return context if context else "No additional files found."


def _get_docker_host_ip() -> str:
    for cmd in [
        ["ip", "route", "show", "default"],
        ["ip", "-4", "route", "show", "dev", "docker0"],
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for token in r.stdout.split():
                if re.match(r"\d+\.\d+\.\d+\.\d+", token) and not token.startswith("0."):
                    return token
        except Exception:
            continue
    return "172.17.0.1"


def adapt_poc(
    cve_id: str,
    poc_script: str,
    classification: dict,
    code_dir: Path,
    compose_content: str,
    llm: ChatOpenAI,
    model_name: str,
) -> AdaptedPoC | None:
    env_files = build_env_files_context(code_dir)

    prompt = ADAPT_PROMPT.format(
        cve_id=cve_id,
        classification=json.dumps(classification, indent=2),
        compose_content=compose_content,
        env_files=env_files,
        poc_script=poc_script,
    )

    if classification.get("vulnerability_type") == "sqli":
        sqli_hint = f"""
            FLAG DATABASE STRUCTURE (use this exactly):
            - Table: flag_table
            - Column: flag  
            - The flag value matches: FLAG{{verified_{cve_id}}}

            Your SQL extraction MUST target: SELECT flag FROM flag_table LIMIT 1
            Do NOT query information_schema first — target flag_table directly.
        """
        prompt += sqli_hint

    if classification.get("requires_oob_interaction", False):
        prompt += OOB_BLOCK.format(host_ip=_get_docker_host_ip()) 

    prompt += "\n<|think|>"

    messages = [
        SystemMessage(
            content="You are a penetration tester adapting an existing PoC. "
                    "Output only the requested JSON."
        ),
        HumanMessage(content=prompt),
    ]

    try:
        return invoke_structured(llm, model_name, messages, AdaptedPoC)
    except Exception as e:
        print(f"  [!] Adaptation failed: {e}")
        return None


def repair_poc(
    cve_id: str,
    original_poc: str,
    adapted_poc: str,
    previous_output: str,
    diagnosis: str,
    classification: dict,
    code_dir: Path,
    compose_content: str,
    repair_history: list[dict],
    llm: ChatOpenAI,
    model_name: str,
) -> RepairedPoC | None:
    env_files = build_env_files_context(code_dir)

    history_text = json.dumps(repair_history, indent=2)
    if len(history_text) > 12000:
        history_text = history_text[-12000:]

    output_for_prompt = previous_output[-16000:]

    prompt = REPAIR_PROMPT.format(
        cve_id=cve_id,
        classification=json.dumps(classification, indent=2),
        compose_content=compose_content,
        env_files=env_files,
        original_poc=original_poc,
        adapted_poc=adapted_poc,
        diagnosis=diagnosis,
        previous_output=output_for_prompt,
        repair_history=history_text,
    )

    messages = [
        SystemMessage(
            content="You are repairing an existing penetration-testing PoC after "
                    "runtime feedback. Output only the requested JSON."
        ),
        HumanMessage(content=prompt),
    ]

    try:
        return invoke_structured(llm, model_name, messages, RepairedPoC)
    except Exception as e:
        print(f"  [!] Repair failed: {e}")
        return None


def invoke_structured(
    llm,
    model_name: str,
    messages: list,
    output_model: type[BaseModel],
    max_tokens: int = 8192,
    config: dict | None = None,
) -> BaseModel:
    config = config or {}

    bound_llm = llm.bind(max_tokens=max_tokens)

    if model_name in ["gpt-4o", "gpt-5"]:
        return bound_llm.with_structured_output(output_model).invoke(
            messages, config=config
        )

    parser = PydanticOutputParser(pydantic_object=output_model)
    format_instructions = (
        "Never use Markdown. Output ONLY valid JSON.\n\n"
        + parser.get_format_instructions()
    )
    messages[0] = SystemMessage(
        content=messages[0].content + f"\n\n{format_instructions}"
    )
    response = bound_llm.invoke(messages, config=config)
    return parse_llm_output(response.content, output_model)


def parse_llm_output(response_content: str, model: type[BaseModel]) -> BaseModel:
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", response_content.strip())
    cleaned = re.sub(r"\n?```\s*$", "", cleaned).strip()

    if not cleaned:
        raise ValueError("Empty LLM response")

    try:
        return model.model_validate_json(cleaned)
    except Exception:
        pass

    try:
        start = cleaned.index("{")
        depth = 0
        in_string = False
        escaped = False

        for i, ch in enumerate(cleaned[start:], start):
            if escaped:
                escaped = False
                continue

            if ch == "\\" and in_string:
                escaped = True
                continue

            if ch == '"':
                in_string = not in_string
                continue

            if in_string:
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = cleaned[start:i + 1]
                    return model.model_validate_json(candidate)
    except (ValueError, Exception):
        pass

    raise ValueError(f"Could not extract valid JSON from output: {response_content}")