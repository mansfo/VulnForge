import os
import re
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from langchain_openai import ChatOpenAI

from shared.flag_nonce import inject_flag_nonce
from adapt_poc import adapt_poc, repair_poc
from run_poc import (
    start_docker,
    stop_docker,
    detect_cheat_in_adapted_poc,
    diagnose_output,
    run_adapted_poc,
    minimal_exploit_env,
)


DOCKERS_DIR = Path("./../../dockers")
POC_DATASET_DIR = Path("./../scraper/poc_dataset")
RESULTS_FILE = Path("poc_runner_results.json")
OUT_SUBDIR = "poc_runner"

# Iterative-repair budget.
MAX_REPAIRS_PER_CANDIDATE = 2
MAX_TOTAL_EXECUTIONS_PER_CVE = 8


def load_existing_results() -> dict:
    if RESULTS_FILE.exists():
        return json.loads(RESULTS_FILE.read_text())
    return {}


def save_results(results: dict):
    RESULTS_FILE.write_text(json.dumps(results, indent=4))


def should_skip(cve_id: str, results: dict) -> bool:
    if cve_id not in results:
        return False
    return bool(results[cve_id].get("success"))


def _slug(s: str, maxlen: int = 40) -> str:
    s = (s or "unknown").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-.")
    return (s or "unknown")[:maxlen]


def _candidate_dirname(index: int, poc_entry: dict) -> str:
    source = _slug(poc_entry.get("source") or "src")
    stem = _slug(Path(poc_entry.get("filename") or "").stem)
    name = f"{index:02d}_{source}"
    if stem and stem != "unknown":
        name += f"_{stem}"
    return name


def _write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _write_attempt_meta(
    attempt_dir: Path,
    attempt: int,
    language: str,
    diagnosis: str | None,
    output: str | None,
    success: bool,
    cheat_detected: bool,
    repair_info: dict | None = None,
):
    data = {
        "attempt": attempt,
        "language": language,
        "ran": output is not None,
        "success": success,
        "cheat_detected": cheat_detected,
        "diagnosis": diagnosis,
    }
    if repair_info is not None:
        data["repair"] = repair_info
    _write_json(attempt_dir / "meta.json", data)


def main(model_name: str = "deepseek4", web_search_tool: str = "custom_no_tool", o_r: bool = False):

    if o_r:
        llm = ChatOpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("MY_OPENROUTER_API_KEY"),
            model="deepseek/deepseek-v4-flash",
            temperature=0.2,
            max_retries=2,
        )

    else:
        llm = ChatOpenAI(
            base_url="https://llm.polito.it",
            api_key=os.getenv("LOCAL_KEY"),
            model="gemma-4-31b",
            temperature=0.1, 
            max_retries=2, 
            max_completion_tokens=10000
        )

    results = load_existing_results()
    skip = True
    for poc_file in sorted(POC_DATASET_DIR.glob("CVE-*.json")):
        skip = True
        cve_id = poc_file.stem
        if cve_id == "CVE-2011-1060":
            skip = False
        if skip:#should_skip(cve_id, results) or skip:
            print(f"[{cve_id}] Already captured, skipping.")
            continue

        code_dir = DOCKERS_DIR / cve_id / web_search_tool
        compose_path = code_dir / "docker-compose.yml"
        classification_path = code_dir / "logs/classification.json"

        if not compose_path.exists() or not classification_path.exists():
            print(f"[{cve_id}] Environment not found, skipping.")
            continue

        poc_data = json.loads(poc_file.read_text())
        scripts = poc_data.get("poc_scripts", [])
        if not scripts:
            print(f"[{cve_id}] No scripts in dataset, skipping.")
            continue

        classification = json.loads(classification_path.read_text())
        compose_content = compose_path.read_text()

        out_dir = code_dir / OUT_SUBDIR
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n[{cve_id}] Starting Docker...")
        if not start_docker(code_dir, compose_content=compose_content):
            results[cve_id] = {"success": False, "reason": "docker_failed"}
            save_results(results)
            _write_json(out_dir / "summary.json", {
                "cve_id": cve_id,
                "tool": web_search_tool,
                "success": False,
                "reason": "docker_failed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            continue

        # The nonce mechanism remains unchanged. For DB-backed flags,
        # inject_flag_nonce() may legitimately return flag_injected=False.
        nonce_result = inject_flag_nonce(classification, cve_id, code_dir)
        if nonce_result is None:
            nonce_result = (
                f"FLAG{{verified_{cve_id}}}",
                False,
                "internal error; placeholder",
            )

        flag_string, flag_injected, flag_detail = nonce_result
        print(f"  [flag] {flag_detail}")

        exploit_env = minimal_exploit_env()
        success = False
        used_poc = None
        used_adapted = None
        used_script_path = None
        used_index = None
        used_attempt = None

        total_executions = 0
        candidates_meta = []

        for i, poc_entry in enumerate(scripts, start=1):
            if total_executions >= MAX_TOTAL_EXECUTIONS_PER_CVE:
                print(
                    f"  [!] Reached execution budget "
                    f"({MAX_TOTAL_EXECUTIONS_PER_CVE}) for {cve_id}."
                )
                break

            cand_dir = out_dir / _candidate_dirname(i, poc_entry)
            cand_dir.mkdir(parents=True, exist_ok=True)

            candidate_meta = {
                "index": i,
                "source": poc_entry.get("source"),
                "filename": poc_entry.get("filename"),
                "adapted": False,
                "language": None,
                "cheat_detected": False,
                "ran": False,
                "success": False,
                "num_repairs": 0,
                "attempts": [],
                "explanation": None,
            }

            poc_script = poc_entry.get("content", "")
            if not poc_script:
                candidate_meta["explanation"] = "empty source content"
                _write_json(cand_dir / "meta.json", candidate_meta)
                candidates_meta.append(candidate_meta)
                continue

            print(
                f"  [{i:02d}] Adapting: "
                f"{poc_entry.get('filename', '?')} "
                f"(source: {poc_entry.get('source', '?')})"
            )

            adapted = adapt_poc(
                cve_id=cve_id,
                poc_script=poc_script,
                classification=classification,
                compose_content=compose_content,
                code_dir=code_dir,
                llm=llm,
                model_name=model_name,
            )

            if not adapted or not adapted.script:
                candidate_meta["explanation"] = (
                    adapted.explanation
                    if adapted
                    else "adaptation failed (no output)"
                )
                _write_json(cand_dir / "meta.json", candidate_meta)
                candidates_meta.append(candidate_meta)
                continue

            candidate_meta["adapted"] = True
            candidate_meta["language"] = adapted.language
            candidate_meta["explanation"] = adapted.explanation

            current_script = adapted.script
            current_language = adapted.language
            repair_history = []

            for attempt in range(MAX_REPAIRS_PER_CANDIDATE + 1):
                attempt_dir = cand_dir / f"attempt_{attempt}"
                attempt_dir.mkdir(parents=True, exist_ok=True)

                if detect_cheat_in_adapted_poc(
                    current_script,
                    cve_id,
                    flag_string,
                ):
                    candidate_meta["cheat_detected"] = True
                    candidate_meta["attempts"].append({
                        "attempt": attempt,
                        "cheat_detected": True,
                        "success": False,
                        "diagnosis": "cheat_detected",
                    })

                    rejected_ext = ".py" if current_language == "python" else ".sh"
                    (attempt_dir / f"adapted_poc_rejected{rejected_ext}").write_text(
                        current_script
                    )
                    _write_attempt_meta(
                        attempt_dir,
                        attempt,
                        current_language,
                        "cheat_detected",
                        None,
                        False,
                        True,
                    )
                    break

                print(
                    f"  [{i:02d}] Running attempt {attempt} "
                    f"(repair {attempt}/{MAX_REPAIRS_PER_CANDIDATE})..."
                )

                output, script_path = run_adapted_poc(
                    script=current_script,
                    language=current_language,
                    out_dir=attempt_dir,
                    env=exploit_env,
                )
                total_executions += 1

                diagnosis = diagnose_output(output)
                attempt_record = {
                    "attempt": attempt,
                    "success": False,
                    "diagnosis": diagnosis,
                    "output_length": len(output),
                }

                candidate_meta["ran"] = True
                candidate_meta["attempts"].append(attempt_record)

                if flag_string in output:
                    print(f"  [{i:02d}] [SUCCESS] Flag captured on attempt {attempt}!")
                    attempt_record["success"] = True
                    candidate_meta["success"] = True

                    _write_attempt_meta(
                        attempt_dir,
                        attempt,
                        current_language,
                        diagnosis,
                        output,
                        True,
                        False,
                    )
                    _write_json(cand_dir / "meta.json", candidate_meta)

                    success = True
                    used_poc = poc_entry
                    used_adapted = adapted
                    used_script_path = script_path
                    used_index = i
                    used_attempt = attempt
                    break

                print(
                    f"  [{i:02d}] [FAIL] Flag not found "
                    f"(diagnosis={diagnosis})."
                )

                _write_attempt_meta(
                    attempt_dir,
                    attempt,
                    current_language,
                    diagnosis,
                    output,
                    False,
                    False,
                )

                if attempt >= MAX_REPAIRS_PER_CANDIDATE:
                    break

                if total_executions >= MAX_TOTAL_EXECUTIONS_PER_CVE:
                    break

                print(f"  [{i:02d}] Repairing after attempt {attempt}...")

                repaired = repair_poc(
                    cve_id=cve_id,
                    original_poc=poc_script,
                    adapted_poc=current_script,
                    previous_output=output,
                    diagnosis=diagnosis,
                    classification=classification,
                    code_dir=code_dir,
                    compose_content=compose_content,
                    repair_history=repair_history,
                    llm=llm,
                    model_name=model_name,
                )

                if not repaired or not repaired.script:
                    print(f"  [{i:02d}] Repair produced no usable script.")
                    break

                repair_info = {
                    "attempt": attempt + 1,
                    "diagnosis": repaired.diagnosis,
                    "changes": repaired.changes,
                    "explanation": repaired.explanation,
                }

                repair_history.append(repair_info)
                candidate_meta["num_repairs"] += 1

                next_attempt_dir = cand_dir / f"attempt_{attempt + 1}"
                next_attempt_dir.mkdir(parents=True, exist_ok=True)

                _write_json(
                    next_attempt_dir / "repair_request.json",
                    {
                        "repair_of_attempt": attempt,
                        "diagnosis": diagnosis,
                        "repair": repair_info,
                    },
                )

                current_script = repaired.script
                current_language = repaired.language
                candidate_meta["language"] = current_language

            _write_json(cand_dir / "meta.json", candidate_meta)
            candidates_meta.append(candidate_meta)

            if success:
                break

        stop_docker(code_dir)

        summary = {
            "cve_id": cve_id,
            "tool": web_search_tool,
            "success": success,
            "flag_injected": flag_injected,
            "flag_detail": flag_detail,
            "num_candidates": len(scripts),
            "num_adapted": sum(
                1 for m in candidates_meta if m["adapted"]
            ),
            "num_cheated": sum(
                1 for m in candidates_meta if m["cheat_detected"]
            ),
            "num_repairs": sum(
                m.get("num_repairs", 0) for m in candidates_meta
            ),
            "num_executions": total_executions,
            "winning_candidate": (
                {
                    "index": used_index,
                    "attempt": used_attempt,
                    "source": used_poc.get("source"),
                    "filename": used_poc.get("filename"),
                }
                if used_poc
                else None
            ),
            "adapted_script_path": (
                str(used_script_path) if used_script_path else None
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _write_json(out_dir / "summary.json", summary)

        results[cve_id] = {
            "success": success,
            "source": used_poc.get("source") if used_poc else None,
            "filename": used_poc.get("filename") if used_poc else None,
            "adapted_script_path": (
                str(used_script_path) if used_script_path else None
            ),
            "adaptation_explanation": (
                used_adapted.explanation if used_adapted else None
            ),
            "winning_attempt": used_attempt,
            "flag_injected": flag_injected,
            "flag_detail": flag_detail,
            "num_repairs": summary["num_repairs"],
            "num_executions": total_executions,
        }
        save_results(results)

        print(
            f"[{cve_id}] Done. Success: {success} "
            f"(flag_injected={flag_injected}, "
            f"repairs={summary['num_repairs']}, "
            f"executions={total_executions})"
        )


if __name__ == "__main__":
    main(o_r=True)