from poc_scraper import scrape_dataset, get_candidate_cves, get_vulhub_folder, download_vulhub_environment
from langchain_openai import ChatOpenAI
import os
import json
from pathlib import Path
import sys
import time

llm = ChatOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
    model="deepseek/deepseek-v4-flash",
    temperature=0.3,
)

def load_analyzed_cves() -> list[str]:
    analyzed = set()
    if Path("CVEs.txt").exists():
        analyzed.update(l.strip() for l in open("CVEs.txt") if l.strip())
    if Path("../docker-agent/results.txt").exists():
        for line in open("../docker-agent/results.txt"):
            if "|" in line and "CVE_ID" not in line and "---" not in line:
                analyzed.add(line.split("|")[0].strip())
    #return list(analyzed)
    return []

if __name__ == "__main__":
    if "--find-new" in sys.argv:
        analyzed = load_analyzed_cves()
        candidates = get_candidate_cves(
            already_analyzed=analyzed,
            sources=["exploitdb"]
        )
        Path("new_candidates.txt").write_text("\n".join(candidates))
        
    elif "--download-vulhub" in sys.argv:
        env_base_dir = Path("../../vulhub-dockers")
        env_base_dir.mkdir(parents=True, exist_ok=True)
        with open("new_candidates.txt", "r") as f:
            cve_list = set([line.strip() for line in f ])
            
        print(f"Starting Vulhub download for {len(cve_list)} CVEs...")
        
        for cve_id in cve_list:
            if (env_base_dir / cve_id).exists():
                print(f"[{cve_id}] Environment already downloaded, skipping...")
                continue
                
            folder_path = get_vulhub_folder(cve_id)
            if folder_path:
                download_vulhub_environment(cve_id, folder_path, env_base_dir)
            else:
                print(f"[{cve_id}] Not found on Vulhub")
            
            time.sleep(1.5)
            
    else:    
        with open("../poc_runner/poc_runner_results.json") as f:
            results = json.load(f)

        cve_to_not_retry = set([cve for cve, data in results.items() ])#if data.get("success", False)])
        dockers_dir = Path("../../dockers")
        cve_to_try = set()
        for cve_id in dockers_dir.iterdir():
            if cve_id.is_dir() and cve_id.name.startswith("CVE-"):
                cve_to_try.add(cve_id.name)
        with open("../docker-agent/results.txt") as f:
            cve_list = set([line[:line.find("|")].strip(" ") for line in f if "--" not in line and "ID" not in line and "Max" not in line and "Workflow" not in line])
        cves = cve_to_try.intersection(cve_list)
        cves = list(cves.difference(cve_to_not_retry))[:4]
        print(cves)
        cves = set()
        for cve_id in dockers_dir.iterdir():
            if cve_id.is_dir() and cve_id.name.startswith("CVE-"):
                cves.add(cve_id.name)
        scrape_dataset(list(cves), output_dir="./poc_dataset1", llm=llm, model_name="deepseek4")