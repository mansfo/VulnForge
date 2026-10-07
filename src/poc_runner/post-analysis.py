#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

HTTP_RE = re.compile(r"\b(100|101|200|201|202|204|301|302|307|308|400|401|403|404|405|409|413|415|422|429|500|501|502|503|504)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)", re.I)
EXCEPTION_RE = re.compile(r"(?:^|\n)\s*([A-Za-z_][\w.]*(?:Error|Exception|Failure))(?::\s*(.*))?$", re.M)
FLAG_RE = re.compile(r"FLAG\{[^}\n]{1,256}\}")
CONNECTION_RE = re.compile(r"connection (?:refused|reset|aborted)|failed to establish a new connection|max retries exceeded|connection timed out|connect timeout", re.I)
DNS_RE = re.compile(r"name or service not known|nodename nor servname|temporary failure in name resolution|getaddrinfo failed", re.I)
TIMEOUT_RE = re.compile(r"timed out|timeout|read timeout|connect timeout|\[runner\] timed out", re.I)
SSL_RE = re.compile(r"sslerror|certificate verify failed|wrong version number|tlsv\d", re.I)
PYTHON_SYNTAX_RE = re.compile(r"syntaxerror|missing parentheses in call to 'print'|invalid syntax", re.I)
IMPORT_RE = re.compile(r"modulenotfounderror|no module named|importerror", re.I)
FILE_RE = re.compile(r"filenotfounderror|no such file or directory|permissionerror|is a directory", re.I)
SHELL_RE = re.compile(r"command not found|permission denied|bad substitution|bad interpreter|syntax error.*shell", re.I)
ARG_RE = re.compile(r"unrecognized arguments|invalid option|too few arguments|too many arguments", re.I)
AUTH_RE = re.compile(r"\b(401|403)\b|unauthorized|forbidden|authentication required|invalid credentials|login required", re.I)
NOT_FOUND_RE = re.compile(r"\b404\b|not found|no such endpoint|unknown route|cannot find the requested resource", re.I)
METHOD_RE = re.compile(r"\b405\b|method not allowed|unsupported method|invalid http method", re.I)
PAYLOAD_RE = re.compile(r"invalid payload|bad request|malformed|invalid parameter|missing parameter|unexpected token|parse error|\b400\b", re.I)
DATABASE_RE = re.compile(r"sql|mysql|mariadb|postgres|sqlite|database|dbapi|query failed|syntax error.*sql", re.I)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
HEX_LONG_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
NUMBER_RE = re.compile(r"\b\d+\b")

FAILURE_ORDER = {
    "connectivity_refused_or_reset": 0, "dns_or_hostname": 0, "timeout": 1,
    "tls_ssl": 1, "missing_dependency": 2, "python_syntax": 2,
    "shell_runtime": 2, "local_file_or_permission": 2, "cli_argument": 3,
    "wrong_endpoint_or_path": 4, "authentication_or_authorization": 5,
    "wrong_http_method": 5, "bad_request_or_payload": 6,
    "server_side_error": 7, "database_or_query": 8,
    "python_runtime_exception": 5, "application_semantic_failure": 9,
    "flag_like_output": 10, "empty_output": 0, "nonzero_exit_unclassified": 3,
}

@dataclass
class Attempt:
    cve_id: str
    candidate: str
    attempt: int
    source: str
    filename: str
    output_path: str
    exit_code: Optional[int]
    old_diagnosis: Optional[str]
    failure_class: str
    confidence: float
    http_codes: list[str]
    urls: list[str]
    exceptions: list[str]
    flags_seen: list[str]
    output_len: int
    output_hash: str
    normalized_hash: str
    first_line: str
    last_line: str
    repair_changes: list[str]
    repair_diagnosis: str
    repair_explanation: str
    candidate_success: bool
    progress_from_previous: Optional[bool] = None
    progress_reason: str = ""
    same_as_previous: bool = False

def read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}

def read_text(path):
    try:
        return path.read_text(errors="replace")
    except Exception:
        return ""

def sha256(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def normalize_output(text):
    s = UUID_RE.sub("<UUID>", text)
    s = HEX_LONG_RE.sub("<HEX>", s)
    s = URL_RE.sub("<URL>", s)
    s = FLAG_RE.sub("FLAG{<VALUE>}", s)
    s = NUMBER_RE.sub("<N>", s)
    return "\n".join(re.sub(r"\s+", " ", x.strip()) for x in s.splitlines() if x.strip())

def extract_http_codes(text):
    return sorted(set(HTTP_RE.findall(text)), key=int)

def extract_urls(text):
    return list(dict.fromkeys(URL_RE.findall(text)))[:20]

def extract_exceptions(text):
    result = []
    for m in EXCEPTION_RE.finditer(text):
        result.append(f"{m.group(1)}: {(m.group(2) or '').strip()}".rstrip(": "))
    if TRACEBACK_RE.search(text):
        for line in reversed([x.strip() for x in text.splitlines() if x.strip()]):
            if re.search(r"(Error|Exception|Failure)(?::|$)", line):
                if line not in result:
                    result.append(line[:500])
                break
    return result[:5]

def classify_failure(text, exit_code):
    if not text.strip(): return "empty_output", 0.95
    if FLAG_RE.search(text): return "flag_like_output", 0.95
    if CONNECTION_RE.search(text): return "connectivity_refused_or_reset", 0.95
    if DNS_RE.search(text): return "dns_or_hostname", 0.95
    if TIMEOUT_RE.search(text): return "timeout", 0.90
    if SSL_RE.search(text): return "tls_ssl", 0.95
    if PYTHON_SYNTAX_RE.search(text): return "python_syntax", 0.98
    if IMPORT_RE.search(text): return "missing_dependency", 0.98
    if FILE_RE.search(text): return "local_file_or_permission", 0.92
    if SHELL_RE.search(text): return "shell_runtime", 0.90
    if ARG_RE.search(text): return "cli_argument", 0.85
    codes = extract_http_codes(text)
    if "401" in codes or "403" in codes or AUTH_RE.search(text): return "authentication_or_authorization", 0.90
    if "404" in codes or NOT_FOUND_RE.search(text): return "wrong_endpoint_or_path", 0.90
    if "405" in codes or METHOD_RE.search(text): return "wrong_http_method", 0.92
    if "400" in codes or PAYLOAD_RE.search(text): return "bad_request_or_payload", 0.80
    if any(x in codes for x in ("500","502","503","504")): return "server_side_error", 0.85
    if DATABASE_RE.search(text): return "database_or_query", 0.70
    if TRACEBACK_RE.search(text): return "python_runtime_exception", 0.88
    if exit_code not in (None, 0): return "nonzero_exit_unclassified", 0.55
    return "application_semantic_failure", 0.35

def markers(text):
    out = {f"http:{x}" for x in extract_http_codes(text)}
    if CONNECTION_RE.search(text): out.add("connectivity_error")
    if DNS_RE.search(text): out.add("dns_error")
    if TRACEBACK_RE.search(text): out.add("traceback")
    if FLAG_RE.search(text): out.add("flag_like_output")
    return out

def compare_progress(prev, cur):
    if cur.normalized_hash == prev.normalized_hash:
        return False, "identical normalized output"
    if cur.failure_class == "flag_like_output":
        return True, "flag-like output appeared"
    old_rank = FAILURE_ORDER.get(prev.failure_class, 4)
    new_rank = FAILURE_ORDER.get(cur.failure_class, 4)
    if new_rank > old_rank:
        return True, f"failure class moved forward: {prev.failure_class} -> {cur.failure_class}"
    if new_rank < old_rank:
        return False, f"failure class regressed: {prev.failure_class} -> {cur.failure_class}"
    if markers(read_text(Path(prev.output_path))) != markers(read_text(Path(cur.output_path))):
        return True, "execution markers changed"
    return False, f"same failure class: {cur.failure_class}"

def discover(dockers_dir):
    result = []
    for output_path in sorted(dockers_dir.glob("CVE-*/*/poc_runner/*/attempt_*/output.txt")):
        attempt_dir = output_path.parent
        candidate_dir = attempt_dir.parent
        m = re.fullmatch(r"attempt_(\d+)", attempt_dir.name)
        if not m: continue
        cve = candidate_dir.parents[2].name
        attempt = int(m.group(1))
        meta = read_json(candidate_dir / "meta.json")
        ameta = read_json(attempt_dir / "meta.json")
        runtime = read_json(attempt_dir / "runtime.json")
        repair = ameta.get("repair") or read_json(attempt_dir / "repair_request.json").get("repair") or {}
        text = read_text(output_path)
        exit_code = runtime.get("exit_code", ameta.get("exit_code"))
        if not isinstance(exit_code, int): exit_code = None
        norm = normalize_output(text)
        cls, conf = classify_failure(text, exit_code)
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        result.append(Attempt(
            cve_id=cve, candidate=candidate_dir.name, attempt=attempt,
            source=str(meta.get("source") or ""), filename=str(meta.get("filename") or ""),
            output_path=str(output_path), exit_code=exit_code,
            old_diagnosis=ameta.get("diagnosis"), failure_class=cls, confidence=conf,
            http_codes=extract_http_codes(text), urls=extract_urls(text),
            exceptions=extract_exceptions(text), flags_seen=FLAG_RE.findall(text)[:10],
            output_len=len(text), output_hash=sha256(text), normalized_hash=sha256(norm),
            first_line=lines[0][:300] if lines else "", last_line=lines[-1][:300] if lines else "",
            repair_changes=repair.get("changes") or [],
            repair_diagnosis=str(repair.get("diagnosis") or ""),
            repair_explanation=str(repair.get("explanation") or ""),
            candidate_success=bool(meta.get("success")),
        ))
    groups = defaultdict(list)
    for a in result: groups[(a.cve_id, a.candidate)].append(a)
    for xs in groups.values():
        xs.sort(key=lambda x: x.attempt)
        for prev, cur in zip(xs, xs[1:]):
            cur.progress_from_previous, cur.progress_reason = compare_progress(prev, cur)
            cur.same_as_previous = cur.normalized_hash == prev.normalized_hash
    return result

def jsonable(a):
    d = asdict(a)
    for k in ("http_codes","urls","exceptions","flags_seen","repair_changes"):
        d[k] = " | ".join(d[k])
    return d

def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text(""); return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dockers_dir", nargs="?", default="../../dockers")
    ap.add_argument("--out", default="post_analysis")
    ap.add_argument("--only-unclassified", action="store_true")
    args = ap.parse_args()

    root = Path(args.dockers_dir).resolve()
    out = Path(args.out).resolve()
    attempts = discover(root)
    if args.only_unclassified:
        attempts = [a for a in attempts if a.old_diagnosis == "unclassified"]

    groups = defaultdict(list)
    for a in attempts: groups[(a.cve_id, a.candidate)].append(a)

    candidate_rows = []
    for (cve, cand), xs in sorted(groups.items()):
        xs.sort(key=lambda x: x.attempt)
        candidate_rows.append({
            "cve_id": cve, "candidate": cand, "source": xs[0].source,
            "filename": xs[0].filename, "attempts": len(xs),
            "success": xs[-1].candidate_success,
            "failure_sequence": " -> ".join(x.failure_class for x in xs),
            "progress_count": sum(x.progress_from_previous is True for x in xs),
            "no_progress_count": sum(x.progress_from_previous is False for x in xs),
            "identical_repeats": sum(x.same_as_previous for x in xs),
            "http_sequence": " -> ".join(",".join(x.http_codes) or "-" for x in xs),
        })

    cve_groups = defaultdict(list)
    for a in attempts: cve_groups[a.cve_id].append(a)
    cve_rows = []
    for cve, xs in sorted(cve_groups.items()):
        cands = defaultdict(list)
        for a in xs: cands[a.candidate].append(a)
        finals = Counter(v[-1].failure_class for v in cands.values())
        cve_rows.append({
            "cve_id": cve, "candidates": len(cands), "attempts": len(xs),
            "success": any(v[-1].candidate_success for v in cands.values()),
            "final_failure_classes": json.dumps(dict(finals)),
        })

    write_csv(out / "attempts.csv", [jsonable(a) for a in attempts])
    write_csv(out / "candidates.csv", candidate_rows)
    write_csv(out / "cves.csv", cve_rows)

    failure_groups = defaultdict(list)
    for a in attempts:
        failure_groups[a.failure_class].append({
            "cve": a.cve_id, "candidate": a.candidate, "attempt": a.attempt,
            "path": a.output_path, "confidence": a.confidence,
            "http": a.http_codes, "exceptions": a.exceptions,
            "first_line": a.first_line, "last_line": a.last_line,
            "progress": a.progress_from_previous,
            "progress_reason": a.progress_reason,
        })
    write_json = lambda path, data: (path.parent.mkdir(parents=True, exist_ok=True), path.write_text(json.dumps(data, indent=2)))
    write_json(out / "failure_groups.json", dict(failure_groups))
    write_csv(out / "unclassified_analysis.csv", [jsonable(a) for a in attempts if a.old_diagnosis == "unclassified"])

    clusters = defaultdict(list)
    for a in attempts: clusters[a.normalized_hash].append(a)
    cluster_rows = []
    for h, xs in sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(xs) < 2: continue
        cluster_rows.append({
            "normalized_hash": h, "count": len(xs),
            "failure_classes": json.dumps(dict(Counter(x.failure_class for x in xs))),
            "examples": " | ".join(f"{x.cve_id}/{x.candidate}/attempt_{x.attempt}" for x in xs[:10]),
            "first_lines": " | ".join(x.first_line[:120] for x in xs[:5]),
        })
    write_csv(out / "output_clusters.csv", cluster_rows)

    print(f"\n=== PoC post-analysis — {len(cve_rows)} CVEs, {len(attempts)} attempts ===\n")
    print("New failure classes:")
    counts = Counter(a.failure_class for a in attempts)
    for cls, n in counts.most_common():
        ex = next(a for a in attempts if a.failure_class == cls)
        print(f"  {cls:35s} {n:4d}  e.g. {ex.cve_id}/{ex.candidate}/attempt_{ex.attempt}")

    print("\nOld 'unclassified' -> new classes:")
    comp = Counter((a.old_diagnosis or "<none>", a.failure_class) for a in attempts)
    for (old, new), n in comp.most_common(25):
        print(f"  {old:20s} -> {new:35s} {n:4d}")

    print("\nRepair progress:")
    print(f"  progress:       {sum(a.progress_from_previous is True for a in attempts)}")
    print(f"  no progress:    {sum(a.progress_from_previous is False for a in attempts)}")
    print(f"  identical:      {sum(a.same_as_previous for a in attempts)}")

    seq = Counter(r["failure_sequence"] for r in candidate_rows if r["attempts"] > 1)
    print("\nMost common failure sequences:")
    for s, n in seq.most_common(20): print(f"  {n:3d}x {s}")

    print("\nReports:")
    for name in ("attempts.csv","candidates.csv","cves.csv","failure_groups.json","unclassified_analysis.csv","output_clusters.csv"):
        print(f"  {out / name}")

if __name__ == "__main__":
    main()