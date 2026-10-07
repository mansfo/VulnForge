import re
import requests
import json
import time
from pathlib import Path
import os
import csv
import io
from langchain_core.messages import HumanMessage, SystemMessage

VULHUB_URL = "https://api.github.com/repos/vulhub/vulhub"
EXPLOITDB_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main"
TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main"
NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
GITHUB_API = "https://api.github.com"

HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"
}

POC_EXTENSIONS = {".py", ".sh", ".rb", ".pl", ".js", ".go", ".java", ".c", ".cpp", ".txt", ".ps1", ".yaml", ".yml"}
POC_NAMES = {"poc", "exp", "exploit", "payload", "attack", "rce", "lfi", "sqli", "ssrf", "traversal", "injection", "scanner", "check", "demo", "proof"}

def get_trickest_poc_links(cve_id: str) -> list[str]:
   
    year = cve_id.split("-")[1]
    url = f"{TRICKEST_RAW}/{year}/{cve_id}.md"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return []
        links = re.findall(r'https://github\.com/[^\s\)\"]+', r.text)
        repo_links = [l for l in links if l.count("/") == 4]
        return list(set(repo_links))
    except Exception as e:
        print(f"[{cve_id}] Trickest error: {e}")
        return []


def download_poc_from_github_repo(repo_url: str, cve_id: str) -> list[dict]:

    parts = repo_url.rstrip("/").split("/")
    owner, repo = parts[-2], parts[-1]
    
    api_url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/"
    try:
        r = requests.get(api_url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return []
        
        found = []
        for item in r.json():
            if item["type"] != "file":
                continue
            if is_poc_file(item["name"]):
                content = download_raw(item["path"] if "vulhub" in repo_url else None, 
                                       raw_url=item.get("download_url"))
                if content:
                    found.append({
                        "filename": item["name"],
                        "content": content,
                        "source": "trickest→github",
                        "repo": repo_url,
                    })
        return found
    except Exception as e:
        print(f"  Error fetching repo {repo_url}: {e}")
        return []


def download_raw(path: str = None, raw_url: str = None) -> str | None:
    url = raw_url or f"https://raw.githubusercontent.com/vulhub/vulhub/master/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(f"Error downloading: {e}")
    return None


def search_github_for_poc(cve_id: str, max_results: int = 3) -> list[dict]:
    
    url = f"{GITHUB_API}/search/repositories"
    params = {"q": f"{cve_id} poc exploit", "sort": "stars", "per_page": max_results}
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=10)
        if r.status_code != 200:
            return []
        
        found = []
        for repo in r.json().get("items", []):
            repo_url = repo["html_url"]
            if cve_id.upper() not in repo["full_name"].upper() and \
               cve_id.upper() not in (repo.get("description") or "").upper():
                continue
            scripts = download_poc_from_github_repo(repo_url, cve_id)
            found.extend(scripts)
        return found
    except Exception as e:
        print(f"[{cve_id}] GitHub search error: {e}")
        return []

def get_exploitdb_index() -> list[dict]:
    url = f"{EXPLOITDB_BASE}/files_exploits.csv"
    r = requests.get(url, timeout=30)
    reader = csv.DictReader(io.StringIO(r.text))
    return list(reader)


def search_exploitdb(cve_id: str, index: list[dict]) -> list[dict]:
    matches = []
    for row in index:
        if cve_id.upper() in row.get("codes", "").upper():
            matches.append({
                "edb_id": row["id"],
                "description": row["description"],
                "path": row["file"],   # es. exploits/webapps/php/12345.py
                "type": row["type"],
                "platform": row["platform"],
            })
    return matches


def download_exploitdb_poc(file_path: str) -> str | None:
    url = f"{EXPLOITDB_BASE}/{file_path}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(f"Error downloading {file_path}: {e}")
    return None

def get_vulhub_folder(cve_id: str) -> str | None:
    tree_url = f"{VULHUB_URL}/git/trees/master?recursive=1"
    try:
        r = requests.get(tree_url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("tree", []):
                path = item.get("path", "")
                if cve_id.upper() in path and item["type"] == "tree":
                    return path
        elif r.status_code in [403, 429]:
            print("GitHub rate limit hit — set GITHUB_TOKEN env var")
    except Exception as e:
        print(f"Error fetching tree: {e}")
    return None


def list_folder_files(folder_path: str) -> list[dict]:
    url = f"{VULHUB_URL}/contents/{folder_path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Error listing folder: {e}")
    return []

def is_poc_file(filename: str) -> bool:
    stem = Path(filename).stem.lower()
    suffix = Path(filename).suffix.lower()
    return suffix in POC_EXTENSIONS and any(kw in stem for kw in POC_NAMES)


def search_nuclei_template(cve_id: str) -> str | None:
    year = cve_id.split("-")[1]
    url = f"{NUCLEI_RAW}/cves/{year}/{cve_id}.yaml"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(f"[{cve_id}] Nuclei error: {e}")
    return None


def scrape_cve(cve_id: str, llm=None, model_name: str = "", exploitdb_index: list = None) -> dict:
    result = {
        "cve_id": cve_id,
        "source": "vulhub",
        "readme": None,
        "poc_scripts": [],      
        "poc_synthesized": None # PoC synthetized by LLM
    }

    folder = get_vulhub_folder(cve_id)
    if folder:
        print(f"[{cve_id}] Found at: {folder}")
        files = list_folder_files(folder)

        for f in files:
            name = f.get("name", "")
            path = f.get("path", "")

            if is_poc_file(name):
                content = download_raw(path)
                if content:
                    result["poc_scripts"].append({"filename": name, "content": content})
                    print(f"[{cve_id}] PoC script found: {name}")
            # README
            if name.lower() in ["readme.md", "readme.zh-cn.md"] and result["readme"] is None:
                content = download_raw(path)
                if content:
                    result["readme"] = content
                    print(f"[{cve_id}] README downloaded ({len(content)} chars)")
        if result["poc_scripts"]:
            result["source"] = "vulhub"

    return result

def get_all_vulhub_cves() -> list[str]:
    tree_url = f"{GITHUB_API}/repos/vulhub/vulhub/git/trees/master?recursive=1"
    try:
        r = requests.get(tree_url, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return []
        
        cves = set()
        for item in r.json().get("tree", []):
            path = item.get("path", "")
            match = re.search(r'(CVE-\d{4}-\d+)', path, re.IGNORECASE)
            if match:
                cves.add(match.group(1).upper())
        return sorted(cves)
    except Exception as e:
        print(f"Error fetching Vulhub tree: {e}")
        return []


def get_all_exploitdb_cves(index: list[dict]) -> list[str]:
    cves = set()
    for row in index:
        codes = row.get("codes", "")
        for match in re.finditer(r'CVE-\d{4}-\d+', codes, re.IGNORECASE):
            cves.add(match.group(0).upper())
    return sorted(cves)

def has_poc_in_vulhub(cve_id: str) -> bool:
    folder = get_vulhub_folder(cve_id)
    if not folder:
        return False
    files = list_folder_files(folder)
    return any(is_poc_file(f.get("name", "")) for f in files)


def has_poc_in_exploitdb(cve_id: str, index: list[dict]) -> bool:
    matches = search_exploitdb(cve_id, index)
    return any(
        Path(m["path"]).suffix.lower() in POC_EXTENSIONS
        for m in matches
    )

def get_candidate_cves(already_analyzed: list[str],
                       sources: list[str] = ["vulhub", "exploitdb"],
                       require_poc: bool = True,
                       min_size_bytes: int = 100) -> list[str]:
    """Filter ExploitDB POCs by file size to avoid empty/stub files."""
    already = set(c.upper() for c in already_analyzed)
    candidates = set()

    index = get_exploitdb_index() if "exploitdb" in sources else []

    if "vulhub" in sources:
        for cve in get_all_vulhub_cves():
            if cve in already:
                continue
            if not require_poc or has_poc_in_vulhub(cve):
                candidates.add(cve)

    if "exploitdb" in sources:
        for cve in get_all_exploitdb_cves(index):
            if cve in already:
                continue
            if not require_poc:
                candidates.add(cve)
                continue
            
            matches = search_exploitdb(cve, index)
            for match in matches:
                try:
                    content = download_exploitdb_poc(match["path"])
                    if content and len(content) > min_size_bytes:
                        candidates.add(cve)
                        break  
                except Exception:
                    continue

    return sorted(candidates)

SYNTH_PROMPT = """You are a penetration tester. Based on the following Vulhub README for {cve_id}, 
write a self-contained Python or bash PoC script that exploits the vulnerability.
The script must:
- Target http://localhost:<port> (read the port from docker-compose.yml if mentioned)
- Print the result or flag if successful
- Use only standard libraries + requests
- Include NO docker commands

README:
{readme}

Output ONLY the script, no explanations."""

def synthesize_poc(cve_id: str, readme: str, llm, model_name: str) -> str:
    messages = [
        SystemMessage(content="You are a cybersecurity expert. Output only code, no markdown."),
        HumanMessage(content=SYNTH_PROMPT.format(cve_id=cve_id, readme=readme[:8000]))
    ]
    response = llm.invoke(messages)
    return response.content


def scrape_dataset(cve_list: list[str], output_dir: str = "./poc_dataset", llm=None, model_name: str = "", delay: float = 1.5):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    exploitdb_index = get_exploitdb_index()
    for cve_id in cve_list:
        out_file = out / f"{cve_id}.json"
        if out_file.exists():
            print(f"[{cve_id}] Already scraped, skipping")
            continue

        result = scrape_cve(cve_id, llm=llm, model_name=model_name, exploitdb_index=exploitdb_index)
        if result == None or result["source"] == "not_found": continue
        with open(out_file, "w") as f:
            json.dump(result, f, indent=4)
        print(f"[{cve_id}] Saved to {out_file}")

        time.sleep(delay) 

def download_vulhub_environment(cve_id: str, folder_path: str, base_env_dir: Path):
    env_dir = base_env_dir / cve_id
    env_dir.mkdir(parents=True, exist_ok=True)
    print(f"[{cve_id}] Downloading Vulhub environment to {env_dir}...")

    def fetch_recursive(api_path: str, local_dir: Path):
        url = f"{GITHUB_API}/repos/vulhub/vulhub/contents/{api_path}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                for item in r.json():
                    if item["type"] == "file":
                        download_url = item.get("download_url")
                        if download_url:
                            file_resp = requests.get(download_url, headers=HEADERS, timeout=10)
                            if file_resp.status_code == 200:
                                (local_dir / item["name"]).write_bytes(file_resp.content)
                    elif item["type"] == "dir":
                        new_dir = local_dir / item["name"]
                        new_dir.mkdir(exist_ok=True)
                        fetch_recursive(item["path"], new_dir)
            
            time.sleep(0.2)
        except Exception as e:
            print(f"[{cve_id}] Error downloading env files from {api_path}: {e}")

    fetch_recursive(folder_path, env_dir)