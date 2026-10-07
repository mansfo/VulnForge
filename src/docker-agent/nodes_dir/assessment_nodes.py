import os
import time
import json
import builtins
import subprocess
from typing import Literal
from pathlib import Path
from urllib.parse import urlparse

# My modules
from state import OverallState
from .utils.docker_utils import *
from .utils.red_team_recon import recon
from .utils.file_utils import docker_dir

from configuration import SanityCheckResult

def run_docker_scout(code_dir_path, index, iid):
    cve_file_path = f"{code_dir_path}/logs/cves{index}.json"
    try:
        with builtins.open(cve_file_path, "w") as f:
            subprocess.run(
                ["docker", "scout", "cves", iid, "--format", "gitlab"],
                cwd=code_dir_path,
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=300,
            )
            print(f"\tCVE List file saved to: {code_dir_path}/logs/cves{index}.json")
    
    except subprocess.TimeoutExpired:
        print(f"\tDocker Scout timed out after 180 seconds for image {iid}")
        return False
    
    if os.path.getsize(cve_file_path) == 0:
        print(f"\t\tThe file {cve_file_path} is empty. Docker Scout failed.")
        return False

    try:
        with open(cve_file_path, "r") as f:
            cve_list = json.load(f)
    except json.JSONDecodeError:
        print(f"\t\tCan't read JSON in {cve_file_path}.")
        return False
    return True
        

def check_docker_vulnerability(cve_id, code_dir_path):
    image_ids = get_image_ids()
    for index, iid in enumerate(image_ids):
        if run_docker_scout(code_dir_path=code_dir_path, index=index, iid=iid):
            cves_file_path = code_dir_path / f"logs/cves{index}.json"
            with builtins.open(cves_file_path, "r") as f:
                cve_list = json.load(f)
            cve_list = cve_list.get("vulnerabilities", [])
            for cve in cve_list:
                if cve["cve"] == cve_id:
                    return True
    return False


def assess_vuln(state: OverallState):
    """The Docker is checked for the presence of the CVE with Docker Scout (but only if the Docker runs)"""
    code_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool)
    final_report_file = code_dir_path / "logs/final_report.txt"        
    
    #down_docker(code_dir_path=code_dir_path)
    if state.milestones.docker_builds:
        print("\nAssessing Docker vulnerability...")
        if check_docker_vulnerability(cve_id=state.cve_id, code_dir_path=code_dir_path):
            output_string = f"Docker Scout says that a Docker Image is vulnerable to {state.cve_id}!"
            print(f"\t{output_string}")
            state.stats.docker_scout_vulnerable = True
            with builtins.open(final_report_file, "a") as f:
                f.write(output_string)

    stats_file = code_dir_path / "logs/stats.json"
    with builtins.open(stats_file, "w") as f:
        json.dump(state.stats.model_dump(), f, indent=4)
                
    milestone_file = code_dir_path / "logs/milestones.json"
    with builtins.open(milestone_file, "w") as f:
        json.dump(state.milestones.model_dump(), f, indent=4)
    
    print("\nAssess Vuln completed.\n")
    return {
        "stats": state.stats,
        "milestones": state.milestones
    }

def _leaks_flag(cmd: str, flag_string: str, timeout: int = 8) -> bool:
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True,
                             text=True, timeout=timeout)
    except Exception:
        return False
    return flag_string in ((res.stdout or "") + (res.stderr or ""))


def _flag_shape(flag_path: str) -> str:
    fp = flag_path.strip()
    low = fp.lower()
    if low.startswith(("http://", "https://")):
        return "url"          # SSRF / internal service
    if "table:" in low or "database:" in low:
        return "db"           # SQLi
    if fp.startswith("/"):
        return "fs"           # filesystem path
    return "other"


def _http_probes(host_ports, flag_path: str, shape: str):
    names = ["flag", "flag.txt", "flag.php", "flag.json"]
    extra_paths = set()

    if shape == "fs":
        names.append(Path(flag_path).name)
        extra_paths.add(flag_path)                       
    elif shape == "url":
        p = urlparse(flag_path).path or "/"
        extra_paths.add(p)                               
        names.append(Path(p).name)

    prefixes = ["", "static/", "public/", "files/", "assets/", "uploads/", "download/"]
    paths = set(extra_paths)
    for n in names:
        for pre in prefixes:
            paths.add(f"/{pre}{n}")

    paths.update([
        "/", "/admin", "/api", "/api/flag", "/actuator", "/actuator/env",
        "/.env", "/config", "/config.json", "/debug", "/server-status",
        "/phpinfo.php", "/.git/config", "/backup", "/backup.zip",
    ])

    probes = []
    for port in host_ports:
        for pth in sorted(paths):
            pth = pth if pth.startswith("/") else "/" + pth
            probes.append(f"curl -sk -m 6 -L 'http://localhost:{port}{pth}'")
    return probes


def _local_probes(code_dir_path: Path, flag_path: str):
    probes = [
        "sshpass -p 'ctfpass' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"-p 2222 ctfuser@localhost 'cat {flag_path}'"
    ]
    for cid in get_container_ids(code_dir_path):
        probes.append(f"docker exec -u ctfuser {cid} cat {flag_path}")
    return probes


def _db_static_advisory(code_dir_path: Path, flag_path: str):
    import re
    terms = []
    for key in ("table", "column"):
        m = re.search(rf"{key}:\s*([A-Za-z0-9_]+)", flag_path, re.I)
        if m:
            terms.append(m.group(1))
    if not terms:
        return []
    pattern = "|".join(terms)
    res = subprocess.run(
        f"grep -rEnI '{pattern}' {code_dir_path} "
        f"--include='*.py' --include='*.php' --include='*.js' --include='*.rb' "
        f"--include='*.java' --include='*.go' --include='*.html' "
        f"--exclude='init.sql' 2>/dev/null",
        shell=True, capture_output=True, text=True, timeout=15,
    )
    return [f"advisory(db-ref): {ln}" for ln in res.stdout.splitlines()[:10]]


def run_negative_control(state: OverallState, code_dir_path: Path,
                         host_ports, flag_string: str):
    """Ritorna (flag_exposed, exposed_via, attempts). Verdetto deterministico."""
    c = state.classification
    flag_path = c.flag_path
    shape = _flag_shape(flag_path)

    probes = _http_probes(host_ports, flag_path, shape)
    if c.attack_vector == "local" and shape == "fs":
        probes += _local_probes(code_dir_path, flag_path)

    attempts, exposed_via = [], None
    for cmd in probes:
        leaked = _leaks_flag(cmd, flag_string)
        attempts.append(("LEAK " if leaked else "ok   ") + cmd)
        if leaked and exposed_via is None:
            exposed_via = cmd

    if shape == "db":
        attempts += _db_static_advisory(code_dir_path, flag_path)

    return (exposed_via is not None), exposed_via, attempts


def sanity_check(state: OverallState):
    if not (state.milestones.docker_builds and state.milestones.docker_runs):
        return

    print("\nRunning sanity check (deterministic negative control)...")

    code_dir_path = docker_dir(state.base_path, state.cve_id, state.web_search_tool)
    logs_dir_path = code_dir_path / "logs"
    final_report_file = logs_dir_path / "final_report.txt"
    log_file = logs_dir_path / "sanity_check_log.txt"

    print("\tRe-launching Docker for dynamic checks...")
    success, _ = launch_docker(code_dir_path=code_dir_path, log_file=log_file)
    if not success:
        print("\tDocker failed to launch — skipping sanity check.")
        with builtins.open(final_report_file, "a") as f:
            f.write("\nSanity check skipped: Docker failed to re-launch.\n")
        return {}

    ready, host_port = wait_for_service(code_dir_path=code_dir_path)
    if not ready:
        return {}

    recon_data = recon(code_dir_path)
    host_ports = sorted({p["host_port"] for e in recon_data["exposed"]
                         for p in e["ports"] if p["host_port"] != 2222})
    if host_port and host_port != -1 and host_port not in host_ports:
        host_ports.append(host_port)

    flag_string = f"FLAG{{verified_{state.cve_id}}}"

    print(f"\tProbing {len(host_ports)} exposed port(s) for shortcut access...")
    flag_exposed, exposed_via, attempts = run_negative_control(
        state, code_dir_path, host_ports, flag_string
    )

    result = SanityCheckResult(
        flag_exposed=flag_exposed,
        attempts=attempts,
        exposed_via=exposed_via,
        verdict="REJECT" if flag_exposed else "PASS",
    )

    output_string = (
        f"\nSanity Check Result (negative control):\n"
        f"\t- Flag exposed without exploit: {result.flag_exposed}\n"
        f"\t- Probes run: {len(attempts)}\n"
        f"\t- Exposed via: {result.exposed_via}\n"
        f"\t- Verdict: {result.verdict}\n"
    )
    print(output_string)
    with builtins.open(log_file, "a") as f:
        f.write("\n\n=== NEGATIVE CONTROL PROBES ===\n")
        f.write("\n".join(attempts))
        f.write(output_string)
    with builtins.open(final_report_file, "a") as f:
        f.write(output_string)

    updated_milestones = state.milestones.model_copy(
        update={"flag_protected": not result.flag_exposed}
    )
    with builtins.open(logs_dir_path / "milestones.json", "w") as f:
        json.dump(updated_milestones.model_dump(), f, indent=4)

    return {
        "sanity_result": result,
        "milestones": updated_milestones,
        "sanity_retry_count": state.sanity_retry_count + 1,
        "revision_type": "Flag exposed!" if result.flag_exposed else "",
        "revision_goal": (
            "Fix the flag position so it is NOT reachable without exploiting the CVE. "
            f"It leaked via: {result.exposed_via}" if result.flag_exposed else ""
        ),
    }

def route_sanity(state: OverallState) -> Literal["Ok", "Exposed", "End"]:
    """Route to red team or back to code generation if flag is already exposed"""
    exposed = state.sanity_result is not None and state.sanity_result.flag_exposed
    retry = state.sanity_retry_count
    print(f"\nRouting sanity (flag_exposed={exposed}, retry={retry})")
    if not exposed:
        return "Ok"
    elif retry >= 2:
        # Max retries reached: log and exit
        print("\tMax sanity retries reached.")
        return "End"
    else:
        print("\tFlag exposed without exploit — regenerating Docker with corrected placement.")
        return "Exposed"