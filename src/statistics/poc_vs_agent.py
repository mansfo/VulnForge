import json
from pathlib import Path
from collections import defaultdict
 
 
def load_results_txt(path: Path) -> dict:
    """CVE_ID -> {scout_vulnerable, exploit_success, result_type}"""
    data = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "|" not in line or "CVE_ID" in line or line.startswith("-"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue
            cve, scout, exploit, rtype = parts[0], parts[1], parts[2], parts[3]
            data[cve] = {
                "scout_vulnerable": scout.lower() == "true",
                "exploit_success":  exploit.lower() == "true",
                "result_type":      rtype,
            }
    return data
 
 
def load_poc_results(path: Path) -> dict:
    """CVE_ID -> {success, source, filename, ...}"""
    with open(path) as f:
        return json.load(f)
 
 
def pct(num, den):
    return f"{100 * num / den:.1f}%" if den else "N/A"
 
 
def analyze(pipeline: dict, poc: dict):
 
    common = sorted(set(pipeline) & set(poc))
    only_pipeline = sorted(set(pipeline) - set(poc))
    only_poc      = sorted(set(poc) - set(pipeline))
 
    print("\n" + "═" * 68)
    print("  STATISTICS: Pipeline (results.txt) × PoC Runner")
    print("═" * 68)
    print(f"\n  Common CVEs:             {len(common)}")
    print(f"  Only in results.txt:     {len(only_pipeline)}")
    print(f"  Only in poc_runner:       {len(only_poc)}     {only_poc}")
 
    c = defaultdict(int)
    rows = []
 
    for cve in common:
        p = pipeline[cve]
        k = poc[cve]
 
        pipe_ok = p["exploit_success"]
        poc_ok  = k["success"]
        rtype   = p["result_type"]
        scout   = p["scout_vulnerable"]
        source  = k.get("source") or "—"
 
        c["total"] += 1
 
        if pipe_ok and poc_ok:
            c["both_ok"] += 1
        elif pipe_ok and not poc_ok:
            c["pipe_ok_poc_fail"] += 1
        elif not pipe_ok and poc_ok:
            c["poc_ok_pipe_fail"] += 1
        else:
            c["both_fail"] += 1
 
        if scout:
            c["scout_yes"] += 1
            if poc_ok:  c["scout_yes_poc_ok"] += 1
            else:       c["scout_yes_poc_fail"] += 1
            if pipe_ok: c["scout_yes_pipe_ok"] += 1
            else:       c["scout_yes_pipe_fail"] += 1
        else:
            c["scout_no"] += 1
            if poc_ok:  c["scout_no_poc_ok"] += 1
            else:       c["scout_no_poc_fail"] += 1
            if pipe_ok: c["scout_no_pipe_ok"] += 1
            else:       c["scout_no_pipe_fail"] += 1
 
        c[f"rtype_{rtype}"] += 1
        if poc_ok:
            c[f"rtype_{rtype}_poc_ok"] += 1
 
        rows.append((cve, pipe_ok, poc_ok, scout, rtype, source))
 
    T = c["total"]
 
    print(f"\n── Pipeline × PoC Matrix (on {T} common CVE ) ──────────────────")
    print(f"  Pipeline ✓  &  PoC ✓   →  {c['both_ok']:>4}  {pct(c['both_ok'], T):>7}  (both captured the flag)")
    print(f"  Pipeline ✓  &  PoC ✗   →  {c['pipe_ok_poc_fail']:>4}  {pct(c['pipe_ok_poc_fail'], T):>7}  (pipeline succeed, PoC don't)")
    print(f"  Pipeline ✗  &  PoC ✓   →  {c['poc_ok_pipe_fail']:>4}  {pct(c['poc_ok_pipe_fail'], T):>7}  (PoC succeed, pipeline don't)")
    print(f"  Pipeline ✗  &  PoC ✗   →  {c['both_fail']:>4}  {pct(c['both_fail'], T):>7}  (both failed)")
 
    agree = c["both_ok"] + c["both_fail"]
    print(f"\n  Same results: {agree}/{T} ({pct(agree, T)})")
 
    poc_ok_total = c["both_ok"] + c["poc_ok_pipe_fail"]
    print(f"\n── When PoC success ({poc_ok_total} CVE) ─────────────────────────")
    print(f"  Pipeline captured the flag:  {c['both_ok']:>4}  ({pct(c['both_ok'], poc_ok_total)})")
    print(f"  Pipeline failed:             {c['poc_ok_pipe_fail']:>4}  ({pct(c['poc_ok_pipe_fail'], poc_ok_total)})")
 
    pipe_ok_total = c["both_ok"] + c["pipe_ok_poc_fail"]
    print(f"\n── When pipeline success ({pipe_ok_total} CVE) ───────────────────")
    print(f"  PoC captured the flag:   {c['both_ok']:>4}  ({pct(c['both_ok'], pipe_ok_total)})")
    print(f"  PoC failed:              {c['pipe_ok_poc_fail']:>4}  ({pct(c['pipe_ok_poc_fail'], pipe_ok_total)})")
 
    print(f"\n── Breakdown for Result Type (pipeline) ─────────────────────────")
    for rtype in ["TP", "TN", "FP", "FN"]:
        n = c[f"rtype_{rtype}"]
        if n == 0:
            continue
        poc_ok_here = c[f"rtype_{rtype}_poc_ok"]
        print(f"  {rtype}:  {n:>4} CVE  →  PoC success: {poc_ok_here}/{n} ({pct(poc_ok_here, n)})")
 
    print(f"\n── Scout Vulnerable × PoC ───────────────────────────────────────")
    print(f"  Scout ✓  ({c['scout_yes']:>3} CVE)  →  PoC ✓: {c['scout_yes_poc_ok']}/{c['scout_yes']} ({pct(c['scout_yes_poc_ok'], c['scout_yes'])})  |  Pipeline ✓: {c['scout_yes_pipe_ok']}/{c['scout_yes']} ({pct(c['scout_yes_pipe_ok'], c['scout_yes'])})")
    print(f"  Scout ✗  ({c['scout_no']:>3} CVE)  →  PoC ✓: {c['scout_no_poc_ok']}/{c['scout_no']} ({pct(c['scout_no_poc_ok'], c['scout_no'])})  |  Pipeline ✓: {c['scout_no_pipe_ok']}/{c['scout_no']} ({pct(c['scout_no_pipe_ok'], c['scout_no'])})")
 

    print(f"\n── Analysis for each CVE ────────────────────────────────────────────")
    print(f"  {'CVE':<22} {'Pipe':>5} {'PoC':>5} {'Scout':>6}   {'Type':>5}")
    print("  " + "-" * 62)
    for cve, pipe_ok, poc_ok, scout, rtype, _ in rows:
        p_sym = "✓" if pipe_ok else "✗"
        k_sym = "✓" if poc_ok  else "✗"
        s_sym = "✓" if scout   else "✗"
        print(f"  {cve:<22} {p_sym:>5} {k_sym:>5} {s_sym:>6}   {rtype:>5}")
 
    print("\n" + "═" * 68)
 
 
def main():
    pipeline = load_results_txt(Path("../docker-agent/results.txt"))
    poc      = load_poc_results(Path("../poc_runner/poc_runner_results.json"))
 
    analyze(pipeline, poc)
 
 
if __name__ == "__main__":
    main()