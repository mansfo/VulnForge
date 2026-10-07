import argparse
import json
import re
from collections import Counter
from pathlib import Path

# Logical progression of the milestones (see configuration.py:Milestones).
MILESTONE_ORDER = [
    "cve_id_ok",
    "docker_builds",
    "docker_runs",
    "code_hard_version",
    "network_setup",
    "exploit_surface_ok",
    "flag_placed",
    "flag_protected",
    "exploit_success",
]

# Lines written by revise_code start (after a tab) with "- ERROR:".
ERROR_LINE_RE = re.compile(r"^\s*-\s*ERROR:\s*(.*)$")


def load_json(path: Path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def parse_errors(report_path: Path):
    """Return the ordered list of ERROR strings from a final_report.txt."""
    errors = []
    if not report_path.exists():
        return errors
    try:
        text = report_path.read_text(errors="replace")
    except Exception:
        return errors
    for line in text.splitlines():
        m = ERROR_LINE_RE.match(line)
        if m:
            errors.append(m.group(1).strip())
    return errors


def normalize_err(e: str) -> str:
    """Collapse whitespace and clip so near-identical errors compare equal."""
    return re.sub(r"\s+", " ", e).strip().lower()[:200]


def trajectory_verdict(errors):
    """Classify the error sequence of a single case."""
    norm = [normalize_err(e) for e in errors if e]
    n = len(norm)
    if n == 0:
        return {"n_errors": 0, "n_unique": 0, "max_repeat": 0, "verdict": "NO_ERRORS"}
    n_unique = len(set(norm))
    # longest run of consecutive identical errors
    max_repeat = cur = 1
    for i in range(1, n):
        cur = cur + 1 if norm[i] == norm[i - 1] else 1
        max_repeat = max(max_repeat, cur)
    if max_repeat >= 3 or (n >= 5 and n_unique <= 2):
        verdict = "STUCK"          # revise keeps failing on the same cause
    elif n_unique / n > 0.7:
        verdict = "CHURN"          # every fix breaks something else
    else:
        verdict = "MIXED"
    return {"n_errors": n, "n_unique": n_unique, "max_repeat": max_repeat, "verdict": verdict}


def first_blocker(miles: dict):
    """First milestone in the ordered chain that is False (the blame point)."""
    for m in MILESTONE_ORDER:
        if not miles.get(m, False):
            return m
    return None  # everything reached


def classify_outcome(miles: dict, stats: dict, cap: int):
    success = miles.get("exploit_success", False) or stats.get("exploitable", False)
    no_expl = miles.get("exploit_surface_ok", False)
    hit_cap = stats.get("test_iteration", 0) >= cap
    if success:
        return "SUCCESS"
    if no_expl:
        return "RUNS_NO_EXPLOIT"      # environment builds+runs, exploit never lands
    if hit_cap:
        return "MAXITER_NOT_RUNNABLE" # never produced a runnable env within cap
    return "OTHER"


def discover_cases(root: Path):
    """Yield (cve_id, tool, logs_dir) for every logs/milestones.json under root."""
    for miles_path in root.rglob("logs/milestones.json"):
        logs_dir = miles_path.parent
        tool = logs_dir.parent.name
        cve = logs_dir.parent.parent.name
        yield cve, tool, logs_dir


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path, help="Path to the dockers/ tree (or any root above logs/).")
    ap.add_argument("--cap", type=int, default=10, help="Max revise iterations (default 10).")
    ap.add_argument("--csv", type=Path, default=None, help="Optional per-case CSV dump.")
    args = ap.parse_args()

    rows = []
    for cve, tool, logs_dir in discover_cases(args.root):
        miles = load_json(logs_dir / "milestones.json")
        stats = load_json(logs_dir / "stats.json")
        errors = parse_errors(logs_dir / "final_report.txt")
        outcome = classify_outcome(miles, stats, args.cap)
        traj = trajectory_verdict(errors)
        it = stats.get("test_iteration", 0)
        rows.append({
            "cve": cve,
            "tool": tool,
            "outcome": outcome,
            "blocker": first_blocker(miles),
            "iters": it,                       # as recorded in stats.json
            "true_iters": max(it, traj["n_errors"]),  # cross-check vs report
            **traj,
        })

    for r in rows:
        if r["blocker"] and "builds" in r["blocker"]: print(r["cve"])

    if not rows:
        print(f"No logs/milestones.json found under {args.root}")
        return

    total = len(rows)
    print(f"\n=== CASES DISCOVERED: {total} ===\n")

    # 1. Outcome partition
    print("--- 1. OUTCOME PARTITION ---")
    oc = Counter(r["outcome"] for r in rows)
    for name in ("SUCCESS", "RUNS_NO_EXPLOIT", "MAXITER_NOT_RUNNABLE", "OTHER"):
        if oc.get(name):
            print(f"  {name:<22} {oc[name]:>3}  ({oc[name]/total:5.1%})")
    print()

    # 2. Blocker distribution for everything that never became exploitable
    print("--- 2. BLOCKER MILESTONE (non-successful cases) ---")
    unresolved = [r for r in rows if r["outcome"] != "SUCCESS"]
    bc = Counter(r["blocker"] for r in unresolved)
    for m in MILESTONE_ORDER:
        if bc.get(m):
            print(f"  stuck before {m:<20} {bc[m]:>3}")
    if bc.get(None):
        print(f"  all milestones reached (no exploit anyway) {bc[None]:>3}")
    print()

    # 3. Error trajectory for EVERY non-successful case, grouped by outcome.
    #    (The revise loop may exit early — this shows how deep it actually went.)
    print("--- 3. ERROR TRAJECTORY (all non-success) ---")
    for bucket in ("MAXITER_NOT_RUNNABLE", "RUNS_NO_EXPLOIT", "OTHER"):
        cases = [r for r in rows if r["outcome"] == bucket]
        if not cases:
            continue
        vc = Counter(r["verdict"] for r in cases)
        vsum = "  ".join(f"{v}={vc[v]}" for v in
                         ("STUCK", "CHURN", "MIXED", "NO_ERRORS") if vc.get(v))
        print(f"\n  [{bucket}]  {vsum}")
        for r in sorted(cases, key=lambda x: x["cve"]):
            print(f"    {r['cve']:<20} report_errs={r['n_errors']:>2} "
                  f"unique={r['n_unique']:>2} maxrep={r['max_repeat']:>2}  "
                  f"{r['verdict']:<8} blocker={r['blocker']}")
    print()

    # 3b. Did anything actually reach the cap? Trust the deeper of the two signals.
    print("--- 3b. CAP CHECK (stats.test_iteration vs report ERROR count) ---")
    reached = [r for r in rows if r["true_iters"] >= args.cap]
    stale = [r for r in rows if r["n_errors"] > r["iters"]]
    print(f"  cases reaching cap ({args.cap}) by EITHER signal: {len(reached)}")
    for r in sorted(reached, key=lambda x: x["cve"]):
        print(f"    {r['cve']:<20} stats={r['iters']:>2}  report={r['n_errors']:>2}")
    if stale:
        print(f"  [!] {len(stale)} case(s) where the report has MORE errors than "
              f"stats.test_iteration → stats.json is stale, trust report_errs:")
        for r in sorted(stale, key=lambda x: x["cve"]):
            print(f"    {r['cve']:<20} stats={r['iters']:>2}  report={r['n_errors']:>2}")
    print()

    # 4. Iteration-to-success — use the REPORT error count (true total across
    #    hard-fix phases), NOT stats.test_iteration which resets on every Hard Fix.
    print("--- 4. ITERATION-TO-SUCCESS (SUCCESS cases) ---")
    succ = [r for r in rows if r["outcome"] == "SUCCESS"]
    if succ:
        true_iters = sorted(r["n_errors"] for r in succ)      # failed revises before success
        phase_iters = sorted(r["iters"] for r in succ)        # what stats.json recorded
        print(f"  true iters (report-based): {true_iters}")
        print(f"  phase iters (stats-based): {phase_iters}   <- contaminated by Hard-Fix reset")
        contaminated = [r["cve"] for r in succ if r["n_errors"] != r["iters"]]
        if contaminated:
            print(f"  [!] hard-fix reset detected in success cases: {contaminated}")
        print(f"  true max={max(true_iters)}  →  cap ({args.cap}) is per-phase; "
              f"total budget per CVE is ~{args.cap}*(1+max_debug_retries).")
    else:
        print("  (no successes)")
    print()

    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"Per-case CSV written to {args.csv}")


if __name__ == "__main__":
    main()