import os
import re
import time
import socket
import subprocess
from pathlib import Path


SIGNATURES = [
    ("missing_module", re.compile(r"ModuleNotFoundError|No module named|ImportError")),
    ("conn_refused", re.compile(r"Connection refused|Failed to establish a new connection|Max retries exceeded")),
    ("dns_wrong_host", re.compile(r"Name or service not known|nodename nor servname|getaddrinfo")),
    ("runner_timeout", re.compile(r"\[runner\] timed out")),
    ("runner_error", re.compile(r"\[runner\] error:")),
    ("http_4xx", re.compile(r"\b(401|403|404|405|422|429)\b")),
    ("http_5xx", re.compile(r"\b(500|502|503)\b")),
    ("ssl_error", re.compile(r"SSLError|CERTIFICATE_VERIFY")),
    ("py2_syntax", re.compile(r"Missing parentheses in call to 'print'|invalid syntax")),
    ("traceback_other", re.compile(r"Traceback \(most recent call last\)")),
]


def wait_for_port(host: str, port: int, timeout: int = 60, interval: int = 3) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(interval)
    return False


def extract_exposed_ports(compose_content: str) -> list[int]:
    matches = re.findall(r'[\s\-\'":](\d+):\d+', compose_content)
    return [int(p) for p in matches]


def start_docker(code_dir_path: Path, compose_content: str = "", timeout: int = 120) -> bool:
    try:
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--build", "--remove-orphans"],
            cwd=code_dir_path, capture_output=True, text=True, timeout=600
        )
    except Exception as e:
        print(f"  [!] Docker failed to start: {e}")
        return False

    if result.returncode != 0:
        print(f"  [!] Docker failed to start: {result.stderr[:300]}")
        return False

    ports = extract_exposed_ports(compose_content)
    if not ports:
        print("  [!] No exposed ports found, waiting 20s as fallback...")
        time.sleep(20)
        return True

    print(f"  Waiting for ports {ports} to be ready...")
    for port in ports:
        ready = wait_for_port("localhost", port, timeout=timeout)
        if ready:
            time.sleep(10)
            print(f"  [+] Port {port} is ready.")
        else:
            print(f"  [!] Port {port} not ready after {timeout}s — proceeding anyway.")

    return True


def stop_docker(code_dir_path: Path):
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        cwd=code_dir_path, capture_output=True
    )


def diagnose_output(text: str) -> str:
    """Return a lightweight runtime diagnosis used as a repair hint.

    The diagnosis is deliberately heuristic: the repair model must inspect the
    complete output before deciding what to change.
    """
    if "FLAG{" in text:
        return "flag_like_output"

    for name, rx in SIGNATURES:
        if rx.search(text):
            return name

    if text.strip() == "":
        return "empty_output"

    return "unclassified"


def output_fingerprint(text: str) -> dict:
    """Small structured summary that can be stored alongside the raw output."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    codes = sorted(set(re.findall(
        r"\b(200|201|204|301|302|400|401|403|404|405|422|429|500|502|503)\b",
        text,
    )))
    return {
        "length": len(text),
        "http_codes": codes,
        "first_line": lines[0][:200] if lines else "",
        "last_line": lines[-1][:200] if lines else "",
        "diagnosis": diagnose_output(text),
    }


def detect_cheat_in_adapted_poc(script: str, cve_id: str, flag_string: str = "") -> bool:
    """Reject adapted PoCs that shortcut the capture oracle.

    Block:
      * docker-based shortcuts (exec/cp);
      * the derivable placeholder flag;
      * the actual flag value, if it somehow leaked into the adaptation context.
    """
    placeholder = f"FLAG{{verified_{cve_id}}}"

    cheat_patterns_regex = [
        r"docker\s+exec",
        r"docker\s+cp",
        r"subprocess.*docker",
    ]

    for pattern in cheat_patterns_regex:
        if re.search(pattern, script, flags=re.IGNORECASE):
            print(f"  [CHEAT DETECTED] Pattern '{pattern}' found in adapted PoC")
            return True

    if placeholder in script:
        print("  [CHEAT DETECTED] Placeholder flag string hardcoded in adapted PoC")
        return True

    if flag_string and flag_string != placeholder and flag_string in script:
        print("  [CHEAT DETECTED] Injected flag value hardcoded in adapted PoC")
        return True

    return False


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


def run_adapted_poc(
    script: str,
    language: str,
    out_dir: Path,
    timeout: int = 180,
    env: dict | None = None,
) -> tuple[str, Path]:
    """Write and execute one PoC attempt.

    The caller chooses out_dir, allowing iterative repair attempts to be kept
    separately rather than overwriting the previous attempt.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    ext = ".py" if language == "python" else ".sh"
    script_path = out_dir / f"adapted_poc{ext}"
    script_path.write_text(script)
    script_path.chmod(0o755)

    cmd = ["python3", str(script_path)] if ext == ".py" else ["bash", str(script_path)]
    run_env = env if env is not None else minimal_exploit_env()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=run_env,
        )
        output = (result.stdout or "") + (result.stderr or "")
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        output = "[runner] timed out\n"
        exit_code = None
    except Exception as e:
        output = f"[runner] error: {e}\n"
        exit_code = None

    (out_dir / "output.txt").write_text(output)
    (out_dir / "runtime.json").write_text(
        __import__("json").dumps(
            {
                "exit_code": exit_code,
                **output_fingerprint(output),
            },
            indent=2,
        )
    )
    return output, script_path