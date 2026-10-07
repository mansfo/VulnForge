import argparse
import json
import re
import sys
from pathlib import Path
from collections import Counter, defaultdict

import pandas as pd

# --------------------------------------------------------------------------- #
# Import base infrastructure from container_stats_fixed
# --------------------------------------------------------------------------- #
try:
    from src.statistics.container_stats import (
        load_runs,
        compute_outcome_stage,
        OUTCOME_STAGE_ORDER,
    )
except ImportError:
    print("[!] container_stats_fixed.py must be in the same directory.")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# ANALYSIS 1 — Root-cause classification of build/run failures
# --------------------------------------------------------------------------- #

# Each entry: (bucket_name, compiled_regex).
# Order matters: first match wins.
BUILD_RUN_SIGNATURES = [
    # === IMAGE RETRIEVAL ===
    ("image_pull_registry_auth_denied",
     re.compile(
         r"pull access denied|insufficient_scope|authorization failed|"
         r"Authenticate with your docker credentials",
         re.I)),
    
    ("image_not_found",
     re.compile(
         r"manifest unknown|no such manifest|"
         r"repository does not exist or may require authorization: server message|"
         r"failed to resolve source metadata|"
         r"Error response from daemon.*No such image",
         re.I)),

    ("image_pull_timeout",
     re.compile(r"context deadline exceeded.*pull|timeout.*pulling|TLS handshake timeout", re.I)),

    # === BUILD TIMEOUT ===
    ("build_timeout",
     re.compile(r"exceeded.*and was killed|TIMEOUT.*docker compose|context deadline exceeded", re.I)),

    # === PINNED EXTERNAL ARTIFACTS (HTTP/HTTPS) ===
    # GitHub Releases, SourceForge, vendor archives, etc. that 404/expired
    # Exit codes: curl 22 (HTTP error), curl 78 (FTP-style remote not found),
    #            wget 8 (server error)
    ("pinned_artifact_http_404",
     re.compile(
         r"curl:\s*\(22\)\s*The requested URL returned error|"
         r"curl:\s*\(78\)|"
         r"wget.*ERROR\s*(?:404|Not Found)",
         re.I | re.M)),

    ("pinned_artifact_corrupted",
     re.compile(
         r"cannot find zipfile directory|"
         r"(?:unzip|tar|gzip|bzip2): .*(?:not a |corrupted|unexpected end-of-file|cannot open)",
         re.I)),

    ("pinned_artifact_download_http_error",
     re.compile(
         r"HTTP.*404 Not Found|"
         r"2\d{3}\s+ERROR 404: Not Found",
         re.I)),

    # === DEPENDENCY / PACKAGE MANAGER ===
    ("apk_package_not_found",
     re.compile(
         r"ERROR:\s*unsatisfiable constraints|"
         r"apk (?:add|update).*did not complete successfully|"
         r"breaks:\s*world\[",
         re.I)),

    ("apt_package_not_found",
     re.compile(
         r"E: Unable to locate package|"
         r"E: Package.*has no installation candidate|"
         r"dpkg.*error processing|"
         r"apt-get.*failed|"
         r"yum.*No package",
         re.I)),

    # === SCRIPT/BINARY EXECUTION ===
    ("entrypoint_syntax_error",
     re.compile(
         r"Syntax error:|"
         r"command not found|"
         r"(?:bin/sh|bash|python):\s*line.*: unexpected",
         re.I)),

    ("runtime_oom_killed",
     re.compile(
         r"killed by signal 9|Killed\b|OOMKilled|"
         r"exited with code (?:137|143|139)|"
         r"Cannot allocate memory|"
         r"Segmentation fault.*memory",
         re.I)),
    
    ("runtime_missing_lib",
     re.compile(
         r"error while loading shared libraries|"
         r"cannot open shared object file|"
         r"(?:libcrypto|libssl|libc\.so)\.so|"
         r"No such file or directory.*\.so\b|"
         r"undefined symbol",
         re.I)),
    
    ("runtime_permission_denied",
     re.compile(
         r"Permission denied.*(?:execute|exec|bin)|"
         r"bash: .+: Permission denied|"
         r"^.+: line \d+: .+: Permission denied",
         re.I | re.M)),
    
    ("runtime_artifact_invalid",
     re.compile(
         r"exec: no such file or directory|"
         r"(?:Exec format error|cannot execute|not a.*file)|"
         r"(?:corrupted|invalid).+(?:jar|war|bin|elf)",
         re.I)),
    
    ("runtime_service_startup_failed",
     re.compile(
         r"(?:ENTRYPOINT|CMD).*(?:failed|error)|"
         r"(?:failed to start|startup failed)|"
         r"Exception.*(?:startup|init|boot)|"
         r"Error.*(?:initializing|connecting)|"
         r"unable to bind|"
         r"connection refused.*(?:startup|boot)",
         re.I)),
    
    ("runtime_exit_nonzero_unspecified",
     re.compile(
         r"exited with code (?!(?:137|143|139))[0-9]+|"
         r"killed by signal (?!9)[0-9]+",
         re.I)),

    # === PACKAGE/APK/DEPENDENCY ===
    ("apk_package_not_found",
     re.compile(
         r"ERROR:\s*unsatisfiable constraints|"
         r"apk (?:add|update).*did not complete successfully|"
         r"breaks:\s*world\[",
         re.I)),

    ("apt_package_not_found",
     re.compile(
         r"E: Unable to locate package|"
         r"E: Package.*has no installation candidate|"
         r"dpkg.*error processing|"
         r"apt-get.*failed",
         re.I)),

    # === NETWORK/BINDING ===
    ("loopback_bind",
     re.compile(
         r"(?:bind|listen) on.*127\.0\.0\.1|"
         r"Address already in use.*127\.0\.0\.1",
         re.I)),

    ("port_conflict",
     re.compile(
         r"(?:Address|Port) already in use|"
         r"EADDRINUSE|"
         r"bind.*EACCES",
         re.I)),

    # === MEMORY ===
    ("oom_killed",
     re.compile(
         r"Killed|OOMKilled|out of memory|"
         r"Cannot allocate memory|"
         r"killed by signal 9",
         re.I)),

    # === FALLBACK ===
    ("unclassified", re.compile(r".*"))  # Always matches; goes last
]

UNKNOWN_BUCKET = "unclassified"


def classify_log_text(text: str) -> str:
    """Return the first matching bucket name, or UNKNOWN_BUCKET."""
    for bucket, rx in BUILD_RUN_SIGNATURES:
        if rx.search(text):
            return bucket
    return UNKNOWN_BUCKET


def _read_last_log(tool_dir: Path) -> str:
    """Read the highest-indexed logN.txt available, falling back to log0.txt."""
    logs_dir = tool_dir / "logs"
    candidates = sorted(logs_dir.glob("log*.txt"),
                        key=lambda p: int(re.sub(r"\D", "", p.stem) or "0"))
    if not candidates:
        return ""
    try:
        return candidates[-1].read_text(errors="replace")
    except Exception:
        return ""


def _read_final_report(tool_dir: Path) -> str:
    p = tool_dir / "logs" / "final_report.txt"
    try:
        return p.read_text(errors="replace") if p.exists() else ""
    except Exception:
        return ""


def enrich_with_root_cause(df: pd.DataFrame, base_dir: Path) -> pd.DataFrame:
    """Add a 'build_run_root_cause' column to df by parsing log files."""
    causes = []
    for _, row in df.iterrows():
        tool_dir = base_dir / row["cve_id"] / row["tool"]
        stage = row.get("outcome_stage", "")
        if stage not in ("docker_build_failed", "container_run_failed"):
            causes.append(None)
            continue
        text = _read_last_log(tool_dir) + "\n" + _read_final_report(tool_dir)
        causes.append(classify_log_text(text) if text.strip() else UNKNOWN_BUCKET)
    df = df.copy()
    df["build_run_root_cause"] = causes
    return df


def print_root_cause_analysis(df: pd.DataFrame):
    failed = df[df["build_run_root_cause"].notna()].copy()

    print("=" * 70)
    print(f"ANALYSIS 1 — ROOT-CAUSE OF BUILD/RUN FAILURES")
    print(f"  Population: runs with outcome_stage in {{docker_build_failed, "
          f"container_run_failed}}")
    print(f"  Total failing runs: {len(failed)}")
    print("=" * 70)

    if failed.empty:
        print("  (no failing runs found)\n")
        return

    # --- Global distribution ---
    dist = failed["build_run_root_cause"].value_counts()
    print("\nGlobal root-cause distribution:")
    for bucket, n in dist.items():
        pct = 100 * n / len(failed)
        print(f"  {bucket:<35} {n:>4}  ({pct:.1f}%)")

    # --- By outcome stage ---
    print("\nBy outcome stage:")
    stage_cross = pd.crosstab(
        failed["build_run_root_cause"], failed["outcome_stage"])
    print(stage_cross.to_string())

    # --- By CWE (only where classification exists) ---
    cwe_known = failed[failed["cwe_name"] != "Unknown"]
    if not cwe_known.empty:
        print(f"\nRoot-cause × CWE  "
              f"(runs with known classification: {len(cwe_known)}/{len(failed)}):")
        cross = pd.crosstab(cwe_known["build_run_root_cause"], cwe_known["cwe_name"])
        print(cross.to_string())
    else:
        print("\n  (no runs with known CWE in this population)")

    # --- By tech_stack ---
    tech_known = failed[failed["tech_stack"] != "Unknown"]
    if not tech_known.empty:
        print(f"\nRoot-cause × tech_stack  "
              f"({len(tech_known)} runs):")
        cross = pd.crosstab(tech_known["build_run_root_cause"], tech_known["tech_stack"])
        print(cross.to_string())

    # --- Unclassified sample: show first lines to guide future regex ---
    unclassified = failed[failed["build_run_root_cause"] == UNKNOWN_BUCKET]
    if not unclassified.empty:
        print(f"\nUnclassified failures ({len(unclassified)}) — first log line per run:")
        print("  (use these to extend BUILD_RUN_SIGNATURES if a pattern recurs)")
        base_dir_ref = None  # will be passed at call site; we skip preview here
        for _, r in unclassified.head(10).iterrows():
            print(f"  [{r['cve_id']}]")

    print("-" * 70)


# --------------------------------------------------------------------------- #
# ANALYSIS 2 — Red-team agent outcome breakdown (Stage 2)
# --------------------------------------------------------------------------- #

# Canonical stage values written by red_team_nodes.py, plus what we infer.
# Some stages are set directly in the code; others are derived from exceptions.
AGENT_STAGE_ORDER = [
    "flag_captured",       # exploit succeeded, flag in output
    "ran_no_flag",         # agent finished, final_exploit ran but no flag
    "no_final_exploit",    # agent finished, but no final_exploit.* produced
    "cheating",            # detect_cheating() fired
    "agent_timeout",       # subprocess.TimeoutExpired
    "agent_error",         # subprocess.CalledProcessError
    "exception",           # unexpected Exception in the try/except
    "deploy",              # docker compose up inside red_team() failed
    "precondition",        # milestones precondition not met (should not reach diag)
    "unknown",             # field missing or unrecognised value
]


def _read_redteam_diag(tool_dir: Path) -> dict:
    p = tool_dir / "logs" / "red_team_diag.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def enrich_with_redteam_stage(df: pd.DataFrame, base_dir: Path) -> pd.DataFrame:
    """Add 'agent_stage', 'flag_injected_rt', 'debug_attempt' columns from
    red_team_diag.json. Only meaningful for Stage 2 rows."""
    stages, injected, attempts = [], [], []
    for _, row in df.iterrows():
        if not row.get("exploit_attempted", False):
            stages.append(None)
            injected.append(None)
            attempts.append(None)
            continue
        tool_dir = base_dir / row["cve_id"] / row["tool"]
        diag = _read_redteam_diag(tool_dir)
        raw_stage = diag.get("stage", "unknown")
        # Normalise: any value not in the known list → "unknown"
        stages.append(raw_stage if raw_stage in AGENT_STAGE_ORDER else "unknown")
        injected.append(diag.get("flag_injected", None))
        attempts.append(diag.get("attempt", 0))
    df = df.copy()
    df["agent_stage"] = stages
    df["flag_injected_rt"] = injected
    df["debug_attempt"] = attempts
    return df


def _crosstab_with_pct(index_col: pd.Series, column_col: pd.Series,
                        index_name: str = "stage", col_name: str = "CWE") -> str:
    """Return a crosstab string with absolute counts and row-% side by side."""
    ct = pd.crosstab(index_col, column_col)
    row_totals = ct.sum(axis=1)
    pct = ct.div(row_totals, axis=0).mul(100).round(1)
    # Interleave: col_n, col_%, col_n, col_%  — only when few columns
    if len(ct.columns) <= 8:
        result = ct.copy().astype(str)
        for col in ct.columns:
            result[col] = ct[col].astype(str) + " (" + pct[col].astype(str) + "%)"
        return result.to_string()
    return ct.to_string() + "\n\n% row:\n" + pct.to_string()


def print_redteam_breakdown(df: pd.DataFrame):
    stage2 = df[
        (df["docker_builds"] == True) & 
        (df["docker_runs"] == True) & 
        (df["exploit_attempted"] == True)
    ].copy()

    print("=" * 70)
    print(f"ANALYSIS 2 — RED-TEAM AGENT OUTCOME BREAKDOWN (Stage 2)")
    print(f"  Population: runs where the opencode agent was actually invoked")
    print(f"  Total Stage 2 runs: {len(stage2)}")
    print("=" * 70)

    if stage2.empty:
        print("  (no Stage 2 runs found)\n")
        return

    # --- Global stage distribution ---
    stage_dist = stage2["agent_stage"].value_counts()
    print("\nGlobal agent_stage distribution:")
    for stage, n in stage_dist.items():
        pct = 100 * n / len(stage2)
        bar = "█" * int(pct / 3)
        print(f"  {stage:<30} {n:>4}  ({pct:5.1f}%)  {bar}")

    # --- Multi-attempt runs (debugger was invoked) ---
    multi = stage2[stage2["debug_attempt"] > 0]
    print(f"\nMulti-attempt runs (debug_attempt > 0): {len(multi)} / {len(stage2)}")
    if not multi.empty:
        success_multi = multi["exploitable"].sum()
        success_single = stage2[stage2["debug_attempt"] == 0]["exploitable"].sum()
        n_single = len(stage2[stage2["debug_attempt"] == 0])
        print(f"  Success rate with  debug retry: "
              f"{success_multi}/{len(multi)} "
              f"({100*success_multi/len(multi):.1f}%)")
        print(f"  Success rate without debug retry: "
              f"{success_single}/{n_single} "
              f"({100*success_single/n_single:.1f}%)" if n_single else "")
        print("\n  Stage distribution for multi-attempt runs:")
        for stage, n in multi["agent_stage"].value_counts().items():
            print(f"    {stage:<30} {n}")

    # --- Stage × CWE ---
    cwe_known = stage2[stage2["cwe_name"] != "Unknown"]
    if not cwe_known.empty:
        print(f"\nagent_stage × CWE  ({len(cwe_known)} runs with known CWE):")
        print(_crosstab_with_pct(
            cwe_known["agent_stage"], cwe_known["cwe_name"],
            "agent_stage", "cwe_name"))

    # --- Stage × kill_chain_steps ---
    kc_known = stage2[stage2["kill_chain_steps"].notna()]
    if not kc_known.empty:
        print(f"\nagent_stage × kill_chain_steps  ({len(kc_known)} runs):")
        print(_crosstab_with_pct(
            kc_known["agent_stage"], kc_known["kill_chain_steps"].astype(int),
            "agent_stage", "kill_chain_steps"))

    # --- Stage × attack_vector ---
    av_known = stage2[stage2["attack_vector"] != "Unknown"]
    if not av_known.empty:
        print(f"\nagent_stage × attack_vector  ({len(av_known)} runs):")
        print(_crosstab_with_pct(
            av_known["agent_stage"], av_known["attack_vector"],
            "agent_stage", "attack_vector"))

    print("-" * 70)


# --------------------------------------------------------------------------- #
# ANALYSIS 3 — Oracle bias: flag_injected vs exploit success
# --------------------------------------------------------------------------- #

def print_oracle_bias(df: pd.DataFrame):
    stage2 = df[
        (df["docker_builds"] == True) & 
        (df["docker_runs"] == True) & 
        (df["exploit_attempted"] == True)
    ].copy()
    stage2 = stage2[stage2["flag_injected_rt"].notna()]

    print("=" * 70)
    print(f"ANALYSIS 3 — ORACLE BIAS: flag_injected vs exploit success (Stage 2)")
    print(f"  flag_injected=True  → nonce used (strong oracle)")
    print(f"  flag_injected=False → placeholder FLAG{{verified_<CVE>}} used "
          f"(derivable from CVE-ID, weaker oracle)")
    print(f"  Stage 2 runs with diag data: {len(stage2)}")
    print("=" * 70)

    if stage2.empty:
        print("  (no Stage 2 runs with red_team_diag.json found)\n")
        return

    injected_true = stage2[stage2["flag_injected_rt"] == True]
    injected_false = stage2[stage2["flag_injected_rt"] == False]

    def _stats(sub, label):
        if sub.empty:
            print(f"  {label}: 0 runs")
            return
        n_succ = sub["exploitable"].sum()
        print(f"  {label}: {len(sub)} runs, "
              f"{n_succ} successes ({100*n_succ/len(sub):.1f}%)")

    print("\nSuccess rate by oracle type:")
    _stats(injected_true, "flag_injected=True  (nonce, strong)")
    _stats(injected_false, "flag_injected=False (placeholder, weak)")

    # --- The critical cell: injected=False AND exploitable=True ---
    suspicious = stage2[(stage2["flag_injected_rt"] == False) &
                        (stage2["exploitable"] == True)]
    print(f"\nSuspicious successes (injected=False AND exploitable=True): "
          f"{len(suspicious)}")
    if not suspicious.empty:
        print("  These runs may be inflated by the agent guessing/hardcoding "
              "the placeholder.")
        print("  CVEs to review manually:")
        for _, r in suspicious.iterrows():
            stage_val = r.get("agent_stage", "?")
            print(f"    [{r['cve_id']}]  agent_stage={stage_val}  "
                  f"cwe={r.get('cwe_name','?')}")

    # --- Injection failure rate by vulnerability_type ---
    vt_col = "vulnerability_type" if "vulnerability_type" in stage2.columns else "cwe_name"
    vt_known = stage2[stage2[vt_col].notna() & (stage2[vt_col] != "Unknown")]
    if not vt_known.empty:
        print(f"\nflag_injected=False rate by {vt_col}:")
        grp = vt_known.groupby(vt_col)["flag_injected_rt"].agg(
            Total="count",
            Injected=lambda x: (x == True).sum(),
            NotInjected=lambda x: (x == False).sum(),
        )
        grp["Not-injected %"] = (100 * grp["NotInjected"] / grp["Total"]).round(1)
        print(grp.sort_values("Not-injected %", ascending=False).to_string())

    # --- Does injection failure correlate with CWE? ---
    cwe_known = stage2[stage2["cwe_name"] != "Unknown"]
    if not cwe_known.empty:
        print(f"\nOracle type × CWE  ({len(cwe_known)} runs):")
        ct = pd.crosstab(cwe_known["flag_injected_rt"], cwe_known["cwe_name"])
        ct.index = ["injected=False", "injected=True"]
        print(ct.to_string())

    # --- Reminder about known injection limitations ---
    print("\nKnown injection limitations (from inject_flag_nonce in red_team_nodes.py):")
    print("  - database: (SQLi)  → always placeholder  (DB record injection not supported)")
    print("  - http://... (SSRF) → placeholder if served-value check fails")
    print("  - Filesystem flags  → nonce injected via docker exec as root")
    if not injected_false.empty:
        by_cwe = injected_false["cwe_name"].value_counts()
        print("\n  CWE distribution of placeholder-only runs:")
        for cwe, n in by_cwe.items():
            print(f"    {cwe:<40} {n}")

    print("-" * 70)

import json
import re
from pathlib import Path
from collections import Counter

def _find_max_red_team_log_index(tool_dir: Path) -> int:
    """Return the highest N such that logs/red_team_log{N}.txt exists for this
    run, or -1 if none exists (red-team was never invoked)."""
    max_n = -1
    logs_dir = tool_dir / "logs"
    if not logs_dir.exists():
        return max_n
    for p in logs_dir.glob("red_team_log*.txt"):
        try:
            n = int(p.stem.replace("red_team_log", ""))
            max_n = max(max_n, n)
        except ValueError:
            continue
    return max_n


def _classify_transition(tool_dir: Path, prev_log: Path, next_log: Path) -> str:
    
    code_file = tool_dir / "logs" / "code.json"
    if not code_file.exists():
        return "unknown"
    try:
        code_mtime = code_file.stat().st_mtime
        t_prev = prev_log.stat().st_mtime
        t_next = next_log.stat().st_mtime
    except OSError:
        return "unknown"
    tolerance = 1.0  # seconds
    if t_prev - tolerance <= code_mtime <= t_next + tolerance:
        return "hard"
    return "soft"


def _has_dangling_hard_fix(tool_dir: Path, max_n: int) -> bool:
   
    logs_dir = tool_dir / "logs"

    stats_file = logs_dir / "stats.json"
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
            if stats.get("debug_retries", 0) >= max_n + 1:
                return True
        except Exception:
            pass

    last_log = logs_dir / f"red_team_log{max_n}.txt"
    report_file = logs_dir / "final_report.txt"
    if last_log.exists() and report_file.exists():
        try:
            if report_file.stat().st_mtime > last_log.stat().st_mtime:
                text = report_file.read_text(errors="ignore")
                if "Test iteration #" in text and "failed!" in text:
                    return True
        except OSError:
            pass

    return False


def _has_any_hard_fix_via_stats(tool_dir: Path):
    
    stats_file = tool_dir / "logs" / "stats.json"
    if not stats_file.exists():
        return None
    try:
        stats = json.loads(stats_file.read_text())
    except Exception:
        return None
    if "total_iterations" not in stats or "test_iteration" not in stats:
        return None
    return stats["total_iterations"] > stats["test_iteration"]


def analyze_debugger_impact(dockers_dir: Path):
    """Analyze the impact of the debugger on Stage 2 runs, using red_team_logN.txt"""
    OUTCOME_ORDER = [
        "flag_captured",
        "next_soft_fix",
        "next_hard_fix",
        "gave_up_retry_cap",
        "dead_end_max_iter",   # Hard Fix only
        "unknown_terminal",
    ]
    soft_inv = Counter()       # (A) per-invocation outcomes, Soft Fixes
    hard_inv = Counter()       # (A) per-invocation outcomes, Hard Fixes
    unknown_inv = 0            # invocations whose type could not be classified

    n_env_no_debug = 0         # (B) stage-2 envs that needed no debugging at all
    n_env_debugged = 0         # (B) envs with >= 1 debugger invocation
    env_soft = env_hard = env_both = 0
    env_soft_only = env_hard_only = 0
    env_soft_flag = env_hard_flag = 0

    dangling_cves = []
    mismatch_cves = []         # primary says >=1 Hard Fix, secondary found 0
    primary_unavailable = 0    # stats.json missing/unreadable -- no cross-check
    unknown_trans_cves = []    # at least one transition type unresolved

    for log0 in dockers_dir.rglob("logs/red_team_log0.txt"):
        tool_dir = log0.parent.parent
        logs_dir = tool_dir / "logs"
        cve_id = tool_dir.parent.name

        max_n = _find_max_red_team_log_index(tool_dir)
        if max_n < 0:
            continue  # shouldn't happen: log0 just matched above

        # A Hard Fix can dead-end (never return a working environment) even on
        # the very first debugger invocation, leaving only red_team_log0 on
        # disk (max_n == 0). Such an environment WAS debugged, so it must not
        # be counted as "no debugging". Compute dangling before that decision.
        dangling = _has_dangling_hard_fix(tool_dir, max_n)

        if max_n == 0 and not dangling:
            n_env_no_debug += 1
            continue  # genuinely no debugger invocation for this environment

        diag_file = logs_dir / "red_team_diag.json"
        try:
            diag = json.loads(diag_file.read_text())
            last_success = diag.get("exploit_success", False)
        except Exception:
            last_success = False

        # ---- classify each materialized transition (1..max_n) ---------------
        has_hard_fix_primary = _has_any_hard_fix_via_stats(tool_dir)
        if has_hard_fix_primary is None:
            primary_unavailable += 1

        transition_types = {}
        if has_hard_fix_primary is False:
            for k in range(1, max_n + 1):
                transition_types[k] = "soft"
        else:
            any_hard_secondary = False
            for k in range(1, max_n + 1):
                prev_log = logs_dir / f"red_team_log{k - 1}.txt"
                next_log = logs_dir / f"red_team_log{k}.txt"
                if not (prev_log.exists() and next_log.exists()):
                    continue
                fix_type = _classify_transition(tool_dir, prev_log, next_log)
                transition_types[k] = fix_type
                if fix_type == "hard":
                    any_hard_secondary = True
            # A dangling Hard Fix is itself a Hard Fix that the transition-based
            # method cannot see (it produced no red_team_log), so it explains a
            # primary "hard fix occurred" signal on its own: only flag a real
            # mismatch when there is neither a materialized nor a dangling Hard.
            if (has_hard_fix_primary is True
                    and not any_hard_secondary and not dangling):
                mismatch_cves.append(cve_id)

        if dangling:
            dangling_cves.append(cve_id)

        # ---- (A) per-invocation outcomes ------------------------------------
        for k in range(1, max_n + 1):
            ftype = transition_types.get(k, "unknown")
            if k == max_n and last_success:
                outcome = "flag_captured"
            elif k < max_n:
                # attempt k failed and was followed by invocation k+1, which
                # produced a new (materialized) attempt.
                nxt = transition_types.get(k + 1, "unknown")
                outcome = {"soft": "next_soft_fix",
                           "hard": "next_hard_fix"}.get(nxt, "unknown_terminal")
            else:
                # k == max_n and the last attempt failed.
                if dangling:
                    # the (max_n+1)-th invocation was a Hard Fix that never
                    # returned a working environment.
                    outcome = "next_hard_fix"
                elif max_n >= 2:
                    outcome = "gave_up_retry_cap"   # debug_retries hit the cap
                else:
                    outcome = "unknown_terminal"
            if ftype == "soft":
                soft_inv[outcome] += 1
            elif ftype == "hard":
                hard_inv[outcome] += 1
            else:
                unknown_inv += 1

        if dangling:
            # the dangling invocation itself: necessarily a Hard Fix, ending in
            # the max test-iteration cap without ever reaching red-team again.
            hard_inv["dead_end_max_iter"] += 1

        # ---- (B) environment-level frequency & final outcome ----------------
        n_env_debugged += 1
        used_soft = any(t == "soft" for t in transition_types.values())
        used_hard = any(t == "hard" for t in transition_types.values()) or dangling
        if any(t == "unknown" for t in transition_types.values()):
            unknown_trans_cves.append(cve_id)
        if used_soft:
            env_soft += 1
        if used_hard:
            env_hard += 1
        if used_soft and used_hard:
            env_both += 1
        if used_soft and not used_hard:
            env_soft_only += 1
        if used_hard and not used_soft:
            env_hard_only += 1
        if used_soft and last_success:
            env_soft_flag += 1
        if used_hard and last_success:
            env_hard_flag += 1

    # ----------------------------- reporting --------------------------------
    def _pct(a, b):
        return f"{100 * a / b:.1f}%" if b else "n/a"

    print("=" * 60)
    print("DEBUGGER IMPACT")
    print("=" * 60)

    print("\n(B) Environment-level frequency & final outcome")
    print(f"  Stage-2 environments needing no debugging: {n_env_no_debug}")
    print(f"  Environments with >=1 debugger invocation: {n_env_debugged}")
    if n_env_debugged:
        print(f"    used >=1 Soft Fix : {env_soft:>3}  ({_pct(env_soft, n_env_debugged)})"
              f"  -> flag captured: {env_soft_flag}  ({_pct(env_soft_flag, env_soft)})")
        print(f"    used >=1 Hard Fix : {env_hard:>3}  ({_pct(env_hard, n_env_debugged)})"
              f"  -> flag captured: {env_hard_flag}  ({_pct(env_hard_flag, env_hard)})")
        print(f"    Soft Fix only     : {env_soft_only:>3}")
        print(f"    Hard Fix only     : {env_hard_only:>3}")
        print(f"    both kinds        : {env_both:>3}")

    print("\n(A) Per-invocation outcome dynamics")
    header = f"  {'outcome':<20}{'Soft Fix':>12}{'Hard Fix':>12}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    n_soft = sum(soft_inv.values())
    n_hard = sum(hard_inv.values())
    for key in OUTCOME_ORDER:
        s, h = soft_inv.get(key, 0), hard_inv.get(key, 0)
        s_cell = f"{s} ({_pct(s, n_soft)})" if s else "-"
        h_cell = f"{h} ({_pct(h, n_hard)})" if h else "-"
        print(f"  {key:<20}{s_cell:>12}{h_cell:>12}")
    print(f"  {'TOTAL invocations':<20}{n_soft:>12}{n_hard:>12}")

    # ----------------------------- diagnostics ------------------------------
    if unknown_inv:
        print(f"\n  [!] {unknown_inv} invocation(s) could not be typed "
              f"(missing logs/code.json) and were excluded from view (A).")
    if unknown_trans_cves:
        print(f"  [!] Unresolved transition type in {len(unknown_trans_cves)} "
              f"CVE(s); their soft/hard classification in view (B) may be "
              f"incomplete: {', '.join(unknown_trans_cves)}")
    if dangling_cves:
        print(f"  [i] Dangling Hard Fix (never reached a new environment) in "
              f"{len(dangling_cves)} CVE(s): {', '.join(dangling_cves)}")
    if mismatch_cves:
        print(f"  [!] Cross-validation mismatch: stats.json proves a Hard Fix "
              f"occurred (total_iterations > test_iteration) but the code.json-"
              f"mtime method found none, in {len(mismatch_cves)} CVE(s): "
              f"{', '.join(mismatch_cves)}")
    if primary_unavailable:
        print(f"  [i] Primary signal (stats.json) unavailable for "
              f"{primary_unavailable} CVE(s); classification for those relied "
              f"solely on the code.json-mtime method with no cross-check.")

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dockers_dir", nargs="?", default="../../dockers",
                    help="Base directory containing CVE-* folders")
    ap.add_argument("--skip-root-cause", action="store_true",
                    help="Skip Analysis 1 (file parsing can be slow on large datasets)")
    ap.add_argument("--skip-redteam", action="store_true",
                    help="Skip Analysis 2")
    ap.add_argument("--skip-oracle", action="store_true",
                    help="Skip Analysis 3")
    args = ap.parse_args()

    base_path = Path(args.dockers_dir).resolve()
    if not base_path.exists():
        print(f"[-] {base_path} does not exist.")
        sys.exit(1)

    print(f"Loading runs from {base_path} ...")
    df = load_runs(base_path)
    if df.empty:
        print("[-] No stats.json found. Check the directory path.")
        sys.exit(1)

    df["outcome_stage"] = df.apply(compute_outcome_stage, axis=1)
    print(f"Loaded {len(df)} runs.\n")

    # Normalize cwe_name using cwe_id as the stable key, so that string
    # variants of the same CWE-ID (e.g. a long official title vs a shorter
    # abbreviated one) are not treated as distinct categories in the
    # crosstabs computed downstream.
    if "cwe_id" in df.columns and "cwe_name" in df.columns:
        name_map = (
            df.dropna(subset=["cwe_id"])
              .groupby("cwe_id")["cwe_name"]
              .agg(lambda s: s.mode().iat[0])
        )
        df["cwe_name"] = df["cwe_id"].map(name_map).fillna(df["cwe_name"])

    # Enrich once so all analyses share the same enriched df
    if not args.skip_root_cause:
        df = enrich_with_root_cause(df, base_path)

    if not args.skip_redteam or not args.skip_oracle:
        df = enrich_with_redteam_stage(df, base_path)

    if not args.skip_root_cause:
        print()
        print_root_cause_analysis(df)

    if not args.skip_redteam:
        print()
        print_redteam_breakdown(df)

    if not args.skip_oracle:
        print()
        print_oracle_bias(df)
    print("-"*60)
    analyze_debugger_impact(base_path)

if __name__ == "__main__":
    main()