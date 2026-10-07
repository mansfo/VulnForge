import subprocess
import builtins
import json
import time
import socket

def _as_text(x) -> str:
    """subprocess.TimeoutExpired.output can be bytes even with text=True: on timeout,
    Popen._communicate() returns whatever was already buffered before the text-decoding
    wrapper runs, so the normal `text=True` guarantee doesn't hold on that code path.
    Normalize defensively so callers never have to special-case it."""
    if x is None:
        return "No logs available"
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    return x


def launch_docker(code_dir_path, log_file, timeout=300):
    try:
        result = subprocess.run(
            ["docker", "compose", "up", "--build", "--detach", "--remove-orphans"],
            cwd=code_dir_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        logs = _as_text(result.stdout)
        success = (result.returncode == 0)
        with builtins.open(log_file, "w") as f:
            f.write(logs)

        return success, logs

    except subprocess.TimeoutExpired as e:
        logs = _as_text(e.output) + f"\n\n[TIMEOUT] docker compose up --build exceeded {timeout}s and was killed."
        print(f"\t{logs.splitlines()[-1]}")
        # docker compose was force-killed by subprocess, but `--build` may have left the
        # daemon mid-build; make sure nothing is left half-up before the next attempt.
        try:
            subprocess.run(["docker", "compose", "down", "--remove-orphans", "-t", "5"],
                           cwd=code_dir_path, capture_output=True, timeout=30)
        except Exception:
            pass
        with builtins.open(log_file, "w") as f:
            f.write(logs)
        return False, logs


def get_image_ids():
    result = subprocess.run(
        ["docker", "images", "-q"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.splitlines()


def get_container_ids(code_dir_path):
    result = subprocess.run(
        ["docker", "compose", "ps", "-a", "--quiet"],
        cwd=code_dir_path,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines()


def get_container_logs(cid, log_file):
    result = subprocess.run(
        ["docker", "logs", cid, "--details"],
        capture_output=True,
        text=True
    )
    
    log = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}\n\n"
    with builtins.open(log_file, "a") as f:
        f.write(log)
    
    log = f"\n\nsudo docker logs {cid} --details\nSTDOUT: {result.stdout.splitlines()[-100:]}\nSTDERR: {result.stderr.splitlines()[-100:]}\n\n"
    return log


def inspect_image(iid, log_file):
    result = subprocess.run(
        ["docker", "inspect", iid],
        capture_output=True,
        text=True
    )
    
    try:
        log = json.loads(result.stdout)        
        with builtins.open(log_file, "a") as f:
            f.write(f"\n\nsudo docker inspect {iid}")
            json.dump(log, f, indent=4)
            
    except json.JSONDecodeError:
        raise ValueError(f"Failed to parse JSON for container {iid}")
        
    return log[0]


def inspect_container(cid, log_file):
    result = subprocess.run(
        ["docker", "inspect", cid],
        capture_output=True,
        text=True
    )
    
    try:
        log = json.loads(result.stdout)        
        with builtins.open(log_file, "a") as f:
            f.write(f"\n\nsudo docker inspect {cid}")
            json.dump(log, f, indent=4)
            
    except json.JSONDecodeError:
        raise ValueError(f"Failed to parse JSON for container {cid}")
        
    return log[0]


def down_docker(code_dir_path):
    # Ensure Docker is down and containers and volumes are removed
    subprocess.run(
        ["docker", "compose", "down", "--volumes"],
        cwd=code_dir_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(10)


def remove_all_images():
    image_ids = subprocess.check_output(["docker", "images", "-aq"]).decode().split()

    if image_ids:
        subprocess.run(
            ["docker", "rmi", "-f"] + image_ids,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

def get_runtime_package_versions(container_ids: list[str], packages: list[str], log_file) -> str:
    """Queries dpkg/rpm inside each running container for the given OS package names."""
    if not packages:
        return "No OS-package services to check."

    output = ""
    for cid in container_ids:
        for pkg in packages:
            # Try dpkg (Debian/Ubuntu) first, then rpm (RHEL/CentOS) as fallback
            result = subprocess.run(
                ["docker", "exec", cid, "dpkg-query", "-W", "-f=${Version}", pkg],
                capture_output=True, text=True, timeout=10
            )
            version = result.stdout.strip()
            if not version:
                result = subprocess.run(
                    ["docker", "exec", cid, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg],
                    capture_output=True, text=True, timeout=10
                )
                version = result.stdout.strip()
            output += f"Container {cid} / package '{pkg}': {version or 'NOT FOUND or query failed'}\n"

    with builtins.open(log_file, "a") as f:
        f.write(f"\n\nRuntime package version check:\n{output}\n")
    return output


def wait_for_service(code_dir_path: str, timeout: int = 120, interval: int = 5):
    container_ids = get_container_ids(code_dir_path=code_dir_path)
    host_ports = set()
    for cid in container_ids:
        try:
            insp = subprocess.run(
                ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", cid],
                capture_output=True, text=True, check=True
            )
            ports_data = json.loads(insp.stdout.strip())
            for _, bindings in (ports_data or {}).items():
                if bindings:
                    host_ports.add(int(bindings[0]["HostPort"]))
        except Exception:
            continue

    if not host_ports:
        print("\t[WARN] No exposed port found, fallback to fixed time sleep (30s).")
        time.sleep(30)
        return False, -1

    deadline = time.time() + timeout
    while time.time() < deadline:
        for port in host_ports:
            try:
                with socket.create_connection(("localhost", port), timeout=2):
                    print(f"\t[+] Service ready on port {port}.")
                    return True, port
            except OSError:
                continue
        time.sleep(interval)

    print(f"\t[WARN] Timeout reached ({timeout}s), no ports ready.")
    return False, -1