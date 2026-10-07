import os
import re
import time
import json
import secrets
import builtins
import subprocess
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

# My modules
from state import OverallState
from nodes_dir.utils.docker_utils import remove_all_images, wait_for_service
from nodes_dir.utils.file_utils import docker_dir

from nodes_dir.utils.red_team_recon import recon, format_target_card, write_agent_tools
from red_team_prompt import build_red_team_prompt


def gen_opencode_json(work_dir: Path) -> None:
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "polito": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Polito LiteLLM",
                "options": {
                    "baseURL": "https://llm.polito.it",
                    "apiKey": "{env:LOCAL_KEY}"
                },
                "models": {
                    "gemma-4-31b": {"name": "Gemma 4 31B"},
                    "deepseek-v4": {"name": "DeepSeek V4"},
                }
            }
        },
        "tools": {
            "bash": True,
            "read": True,
            "write": True,
            "edit": True,
            "glob": True,
            "grep": True
        },
        "permission": {
            "bash": {
                "*": "allow",
                "docker *": "deny",
                "docker-compose *": "deny",
                "docker ps": "allow",
                "rm -rf *": "deny",
                "git *": "deny",
            },
            "external_directory": {
                "*": "deny",
                "~/tools/**": "allow",
                "~/bin/**": "allow",
                "/tmp/**": "allow",
                "~/.local/share/opencode/tool-output/**": "allow",
            },
            "webfetch": "deny",
            "websearch": "deny",
            "question": "deny",
            "task": "deny",
            "lsp": "deny",
        }
    }
    (work_dir / "opencode.json").write_text(json.dumps(opencode_config, indent=2))


_WEB_DOCROOTS = [
    "/usr/share/nginx/html", "/var/www/html", "/var/www",
    "/srv/http", "/srv/www", "/app/public", "/app/static",
    "/usr/local/apache2/htdocs",
]

def _url_to_candidate_paths(url: str) -> list[str]:
    p = urlparse(url)
    url_path = p.path or "/"
    if url_path.endswith("/"):
        url_path += "index.html"
    rel = url_path.lstrip("/")
    return [f"{root}/{rel}" for root in _WEB_DOCROOTS] + [url_path]

def _find_served_file(cid: str, candidates: list[str], placeholder: str) -> str | None:

    for path in candidates:
        try:
            if _exec_root(cid, 'test -f "$P"', {"P": path}).returncode == 0:
                return path
        except Exception:
            continue
    try:
        r = _exec_root(
            cid,
            'grep -rlF "$V" $R 2>/dev/null | head -n1',
            {"V": placeholder, "R": "/usr/share/nginx /var/www /srv /app /usr/local/apache2/htdocs"},
        )
        hit = (r.stdout or "").strip()
        return hit or None
    except Exception:
        return None


def find_exploit_scripts(work_dir: Path):
    seen, out = set(), []
    for base in (work_dir, work_dir / "logs"):
        if not base.exists():
            continue
        for pat in ("final_exploit*.py", "final_exploit*.sh"):
            for p in sorted(base.glob(pat)):
                if p.is_file() and p not in seen:
                    seen.add(p)
                    out.append(p)
    return out


_SENSITIVE_KEY_RE = re.compile(
    r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE|"
    r"LANGFUSE|OPENROUTER|OPENAI|ANTHROPIC|LOCAL_KEY|"
    r"GITHUB|AWS|GCP|AZURE|DIGITALOCEAN|"
    r"DATABASE_URL|POSTGRES|MYSQL|MONGO|REDIS_URL",
    re.IGNORECASE,
)

_EXPLICIT_BLOCK = frozenset({
    "MY_OPENROUTER_API_KEY", 
    "OPENROUTER_API_KEY",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_HOST",
    "LOCAL_KEY",
    "DOCKER_HOST",      
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "COMPOSE_FILE",
})

def minimal_exploit_env() -> dict:
    env = {}
    for k, v in os.environ.items():
        if k in _EXPLICIT_BLOCK:
            continue
        if _SENSITIVE_KEY_RE.search(k):
            continue
        env[k] = v

    env.update({
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def run_poc(work_dir: Path, flag_string: str):
    scripts = find_exploit_scripts(work_dir)
    if not scripts:
        print("\t[-] No final_exploit.* produced by the agent.")
        return False, "no_final_exploit"

    exploit_env = minimal_exploit_env()
    for sp in scripts:
        sp.chmod(0o755)
        cmd = ["python3", str(sp)] if sp.suffix == ".py" else ["bash", str(sp)]
        print(f"\tExecuting {sp.name}...")
        try:
            result = subprocess.run(cmd, cwd=work_dir, capture_output=True,
                                    text=True, timeout=180, env=exploit_env)
            combined = (result.stdout or "") + (result.stderr or "")
            if flag_string in combined:
                print(f"\t[VULNERABLE] Flag retrieved by {sp.name}.")
                return True, "flag_captured"
            print(f"\t[FAIL] {sp.name}: flag not in output. "
                  f"stdout head: {result.stdout[:200]!r}")
        except subprocess.TimeoutExpired:
            print(f"\t[!] {sp.name} timed out.")
        except Exception as e:
            print(f"\t[!] {sp.name} error: {e}")

    return False, "ran_no_flag"


_DOCKER_RE = re.compile(r"\bdocker(?:-compose)?\b")


def detect_cheating(work_dir: Path, flag_string: str) -> bool:
    for sp in find_exploit_scripts(work_dir):
        try:
            txt = sp.read_text(errors="ignore")
        except Exception:
            continue
        if _DOCKER_RE.search(txt):
            print(f"\t[CHEAT] {sp.name} contains a docker command.")
            return True
        if flag_string in txt:
            print(f"\t[CHEAT] {sp.name} hardcodes the flag string.")
            return True
    return False

def _exec_root(cid: str, script: str, env_pairs: dict) -> subprocess.CompletedProcess:
    """Run `sh -c <script>` as root inside cid, passing values via -e to avoid any
    shell-quoting/injection issues with the path or the nonce."""
    cmd = ["docker", "exec", "-u", "root"]
    for k, v in env_pairs.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [cid, "sh", "-c", script]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


def _compose_container_ids(code_dir_path: Path) -> list[str]:
    ps = subprocess.run(
        ["docker", "compose", "ps", "-q"],
        cwd=code_dir_path, capture_output=True, text=True,
    )
    return [c for c in ps.stdout.split() if c]


def _write_flag(cid: str, flag_path: str, nonce: str, owner: str, perms: str) -> bool:
    """Overwrite (or create) the flag file with `nonce`, then re-apply owner/perms.

    Using redirection (`> "$P"`) truncates the existing inode, preserving its owner
    and mode; we still re-apply the classification's owner/perms so the flag keeps
    the exact readability the exploit chain is expected to overcome."""
    try:
        res = _exec_root(cid, 'printf "%s" "$V" > "$P"',
                         {"P": flag_path, "V": nonce})
        if res.returncode != 0:
            return False
        if owner and owner.upper() != "N/A":
            _exec_root(cid, 'chown "$O" "$P" 2>/dev/null || true',
                       {"P": flag_path, "O": owner})
        if perms and perms.strip().isdigit():
            _exec_root(cid, 'chmod "$M" "$P" 2>/dev/null || true',
                       {"P": flag_path, "M": perms.strip()})
        return True
    except Exception:
        return False


def _resolve_fs_targets(cids: list[str], flag_path: str) -> list[tuple[str, str]]:
    targets = []
    for cid in cids:
        try:
            if _exec_root(cid, 'test -f "$P"', {"P": flag_path}).returncode == 0:
                targets.append(cid)
        except Exception:
            continue
    if not targets: 
        parent = str(Path(flag_path).parent)
        for cid in cids:
            try:
                if _exec_root(cid, 'test -d "$D"', {"D": parent}).returncode == 0:
                    targets.append(cid)
            except Exception:
                continue
    return [(cid, flag_path) for cid in targets]


def _served_value_matches(cid: str, url: str, expected: str) -> bool | None:
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    scheme = p.scheme or "http"
    target = f"{scheme}://127.0.0.1:{port}{path}"
    script = (
        'if command -v curl >/dev/null 2>&1; then curl -sk "$U"; '
        'elif command -v wget >/dev/null 2>&1; then wget -qO- --no-check-certificate "$U"; '
        'else echo __NO_HTTP_CLIENT__; fi'
    )
    try:
        r = _exec_root(cid, script, {"U": target})
    except Exception:
        return None
    body = (r.stdout or "")
    if "__NO_HTTP_CLIENT__" in body:
        return None
    return expected in body

def _is_static_docroot(path: str) -> bool:
    return any(path == r or path.startswith(r + "/") for r in _WEB_DOCROOTS)


def inject_flag_nonce(classification, cve_id, code_dir_path):
    placeholder = f"FLAG{{verified_{cve_id}}}"
    nonce = "FLAG{" + secrets.token_hex(16) + "}"
    flag_path = (getattr(classification, "flag_path", "") or "").strip() if classification else ""

    if flag_path.lower().startswith("database:"):
        return placeholder, False, "database flag: nonce injection not supported, using placeholder"

    is_url = flag_path.startswith("http://") or flag_path.startswith("https://")
    is_fs  = flag_path.startswith("/")
    if not flag_path or not (is_url or is_fs):
        return placeholder, False, f"unsupported flag_path ('{flag_path or 'N/A'}'); using placeholder"

    owner = (getattr(classification, "flag_owner", "") or "").strip()
    perms = (getattr(classification, "flag_permissions", "") or "").strip()
    cids = _compose_container_ids(code_dir_path)
    if not cids:
        return placeholder, False, "no running containers found; using placeholder"

    if is_fs:
        targets = _resolve_fs_targets(cids, flag_path)
        injected = [cid[:12] for cid, path in targets
                    if _write_flag(cid, path, nonce, owner, perms)]
        if injected:
            return nonce, True, f"nonce injected into {injected} (filesystem)"
        return placeholder, False, f"could not inject nonce at '{flag_path}'; using placeholder"

    candidates = _url_to_candidate_paths(flag_path)
    verified = []
    for cid in cids:
        hit = _find_served_file(cid, candidates, placeholder)
        if not hit:
            continue
        if not _write_flag(cid, hit, nonce, owner, perms):
            continue
        served = _served_value_matches(cid, flag_path, nonce)
        if served is True:
            verified.append(cid[:12])
        elif served is False:
            return placeholder, False, (
                f"nonce written to '{hit}' but served value differs "
                "(app-cached / non-static serving); using placeholder")
        elif _is_static_docroot(hit):     
            verified.append(cid[:12])
    if verified:
        return nonce, True, f"nonce injected & served-check {verified} (url→file)"
    return placeholder, False, f"could not verify served nonce for '{flag_path}'; using placeholder"

def _init_results_file(summary_file: Path) -> None:
    if not summary_file.exists():
        summary_file.write_text(
            "CVE_ID | Scout_Vulnerable | Exploit_Success | Result_Type | Stage\n"
            + "-" * 78 + "\n"
        )


def _write_result(summary_file: Path, cve_id, scout_vulnerable,
                  exploit_success, result_type, stage="-") -> None:
    with open(summary_file, "a") as f:
        f.write(f"{cve_id} | {scout_vulnerable} | {exploit_success} | "
                f"{result_type} | {stage}\n")


def red_team(state: OverallState):
    scout_vulnerable = state.stats.docker_scout_vulnerable
    summary_file = Path("results.txt")
    _init_results_file(summary_file)

    if not (state.milestones.docker_builds and state.milestones.docker_runs):
        _write_result(summary_file, state.cve_id, scout_vulnerable, False,
                      "Err", stage="precondition")
        return

    print("\nRunning red team phase...")
    cve_id = state.cve_id
    code_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool)
    logs_dir_path = code_dir_path / "logs"
    logs_dir_path.mkdir(parents=True, exist_ok=True)

    log_file_path = logs_dir_path / f"red_team_log{state.debug_retries}.txt"

    # ---- deploy ----
    print("\tStarting Docker container...")
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d", "--remove-orphans", "--build"],
            cwd=code_dir_path, check=True, capture_output=True,
        )
        ready, _ = wait_for_service(code_dir_path=code_dir_path)
        if not ready:
            time.sleep(30)
    except subprocess.CalledProcessError as e:
        print(f"\t[!] Docker compose failed: {e.stderr.decode() if e.stderr else e}")
        _write_result(summary_file, cve_id, scout_vulnerable, False,
                      "DockerError", stage="deploy")
        return

    recon_data = recon(code_dir_path)
    write_agent_tools(code_dir_path)
    target_card = format_target_card(recon_data, state.classification, cve_id)
    with builtins.open(logs_dir_path / "recon.json", "w") as f:
        json.dump(recon_data, f, indent=2)

    # ---- inject the capture-oracle nonce (must happen BEFORE the agent runs) ----
    # flag_string is the value we later look for; the agent is never told it.
    # `flag_detail` is intentionally nonce-free so it is safe to print/persist.
    result = inject_flag_nonce(state.classification, cve_id, code_dir_path)
    if result is None:
        print("\t[BUG] inject_flag_nonce returned None; falling back to placeholder")
        result = (f"FLAG{{verified_{cve_id}}}", False, "internal error; placeholder")
    flag_string, flag_injected, flag_detail = result

    gen_opencode_json(code_dir_path)
    local_model_key = os.environ.get("LOCAL_KEY", "")
    or_key = os.environ.get("MY_OPENROUTER_API_KEY", "")
    if not or_key:
        print("\t[WARN] OPENROUTER_API_KEY not found")
    agent_env = os.environ.copy()
    for key in ["OPENAI_BASE_URL", "LITELLM_API_BASE", "OPENAI_API_KEY", "OPENROUTER_API_KEY"]:
        agent_env.pop(key, None)
    agent_env.update({
        "OPENAI_API_KEY": or_key,
        "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
        "LITELLM_API_BASE": "https://openrouter.ai/api/v1",
        "OPENROUTER_API_KEY": or_key,
        "CI": "1", "NO_COLOR": "1",
        "LITELLM_MAX_RETRIES": "10", "MAX_RETRIES": "10",
        "RETRY_DELAY": "5", "TEMPERATURE": "0.2",
    })

    agent_env["PWD"] = str(code_dir_path)

    agent_prompt = build_red_team_prompt(state, code_dir_path, target_card)+"\n<|think|>"

    agent_model = os.environ.get("RED_TEAM_MODEL", 
                                 "openrouter/deepseek/deepseek-v4-flash")
    opencode_path = Path.home() / ".opencode" / "bin" / "opencode"

    exploit_success = False
    stage = "unknown"
    try:
        print(f"Launching agent ({agent_model}) in {code_dir_path}...")
        with open(log_file_path, "w") as log_file:
            subprocess.run(
                [opencode_path, "run", "--dir", str(code_dir_path),
                 "--model", agent_model, agent_prompt],
                cwd=code_dir_path, env=agent_env, text=True, timeout=600,
                stdout=log_file, stderr=subprocess.STDOUT, check=True,
            )
        print("\tAgent finished.")

        if detect_cheating(code_dir_path, flag_string):
            exploit_success, stage = False, "cheating"
        else:
            exploit_success, stage = run_poc(code_dir_path, flag_string)

        if scout_vulnerable and exploit_success:
            res = "TP"
        elif not scout_vulnerable and exploit_success:
            res = "FN"
        elif scout_vulnerable and not exploit_success:
            res = "FP"
        else:
            res = "TN"
        _write_result(summary_file, cve_id, scout_vulnerable,
                      exploit_success, res, stage=stage)

    except subprocess.TimeoutExpired:
        print("\t[!] Agent timed out.")
        stage = "agent_timeout"
        outcome = "FP (Timeout)" if scout_vulnerable else "TN (Timeout)"
        _write_result(summary_file, cve_id, scout_vulnerable, False,
                      outcome, stage=stage)

    except subprocess.CalledProcessError as e:
        print(f"\t[!] Agent process error: {e}")
        stage = "agent_error"
        outcome = "FP (AgentErr)" if scout_vulnerable else "TN (AgentErr)"
        _write_result(summary_file, cve_id, scout_vulnerable, False,
                      outcome, stage=stage)

    except Exception as e:
        print(f"\t[!] Unexpected error: {e}")
        stage = "exception"
        outcome = ("FP " if scout_vulnerable else "TN ") + "Error"
        _write_result(summary_file, cve_id, scout_vulnerable, False,
                      outcome, stage=stage)

    finally:
        print("\tShutting down container...")
        subprocess.run(
            ["docker", "compose", "down", "-v", "--remove-orphans"],
            cwd=code_dir_path, capture_output=True,
        )

    state.milestones.exploit_success = exploit_success
    state.stats.exploitable = exploit_success
    state.flag_captured = exploit_success

    with builtins.open(logs_dir_path / "stats.json", "w") as f:
        json.dump(state.stats.model_dump(), f, indent=4)
    with builtins.open(logs_dir_path / "milestones.json", "w") as f:
        json.dump(state.milestones.model_dump(), f, indent=4)
    with builtins.open(logs_dir_path / "red_team_diag.json", "w") as f:
        json.dump({"attempt": state.debug_retries, "stage": stage,
                   "exploit_success": exploit_success,
                   "flag_injected": flag_injected,
                   "flag_detail": flag_detail,
                   "flag_value": flag_string}, f, indent=2)

    remove_all_images()

    return {
        "stats": state.stats,
        "milestones": state.milestones,
        "flag_captured": exploit_success,  
    }


def route_after_red_team(state: OverallState) -> Literal["End", "Debugger"]:
    if state.milestones.exploit_success:
        return "End"
    elif state.debug_retries < 2:
        return "Debugger"
    else:
        return "End"