#!/usr/bin/env python3
"""
[STATISTICS] Coherent success-rate / confusion-matrix computation for DOCKER-AGENT runs.

WHY THIS SCRIPT EXISTS
-----------------------
container_stats.py's load_stats() applies NO filter (it includes every run that has
a logs/stats.json, regardless of whether Docker ever built/ran or whether an exploit
was ever attempted). Individual analysis functions inside print_statistics() then each
apply their OWN, different filter (some none, some docker_builds+docker_runs). The
result: different numbers in the SAME report answer different questions without this
being explicit anywhere, and none of them isolate "exploit attempted" from "exploit
never reached" runs.

Concretely: a CVE that hits MaxIter inside test_exploit_surface (route_test ->
"Stop Testing") gets stats.json + milestones.json written with docker_builds=True,
docker_runs=True, exploitable=False (the field's DEFAULT, never touched). It is then
scored as a genuine "TN" / exploit failure in container_stats.py's confusion matrix
and CWE/kill-chain win-rate tables, even though red_team.py was never invoked.

THIS SCRIPT instead defines three explicit, disjoint-by-inclusion populations and
reports each one separately, so a reader always knows which population a number
refers to:

  STAGE 0  all_runs           any (cve, tool) dir with a logs/stats.json.
  STAGE 1  built_and_ran      STAGE 0 AND milestones.docker_builds AND
                               milestones.docker_runs.
  STAGE 2  exploit_attempted  STAGE 1 AND logs/red_team_diag.json exists.

logs/red_team_diag.json is written by red_team_nodes.py only AFTER the opencode
agent has actually been invoked (success, timeout, error, or exception all reach
that write) -- NOT if the initial "docker compose up" in red_team() itself fails
(stage="deploy") and NOT if the milestones precondition fails (stage="precondition").
It is therefore the most reliable available signal that an exploit attempt genuinely
happened, as opposed to being inferred (and silently wrong) from docker_builds/
docker_runs alone.

Only STAGE 2 is used for anything exploit-outcome-related: global success rate,
Scout-vs-exploit confusion matrix, win-rate by CWE / CVE year / kill-chain steps,
EPSS virality correlation. STAGE 0/1 are used only for infra metrics (build/run
failure rates), where "was the exploit attempted" is not a meaningful question.

Additionally: docker_scout_vulnerable defaults to False and is only set inside
assess_vuln(), which the graph reaches ONLY via skip_to_scout=True. Trusting the
boolean blindly silently turns "Scout was never run for this CVE" into "Scout said
not vulnerable". This script instead checks for the presence of logs/cves*.json
(written by run_docker_scout) to know whether Scout actually ran, and warns loudly
if it looks like it never did.
"""
import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd
import requests
import yaml


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

def get_intended_containers(tool_dir: Path) -> int:
    compose_path = tool_dir / "docker-compose.yml"
    if compose_path.exists():
        try:
            with open(compose_path, "r") as f:
                compose_data = yaml.safe_load(f)
                if compose_data and "services" in compose_data:
                    return len(compose_data["services"])
        except Exception:
            pass
    dockerfiles = list(tool_dir.rglob("Dockerfile*"))
    return len(dockerfiles) if dockerfiles else 1


def scout_was_run(tool_dir: Path) -> bool:
    return True #any((tool_dir / "logs").glob("cves*.json"))


def exploit_attempted(tool_dir: Path) -> bool:
    """True only if red_team.py got past the initial docker deploy and actually
    invoked the opencode agent (see module docstring)."""
    return (tool_dir / "logs" / "red_team_diag.json").exists()


def load_runs(base_dir: Path) -> pd.DataFrame:
    rows = []
    for cve_dir in sorted(base_dir.iterdir()):
        if not cve_dir.is_dir() or not cve_dir.name.startswith("CVE-"):
            continue
        for tool_dir in cve_dir.iterdir():
            if not tool_dir.is_dir():
                continue

            stats_file = tool_dir / "logs" / "stats.json"
            if not stats_file.exists():
                continue  # STAGE 0 requires at least a stats.json to exist

            milestones_file = tool_dir / "logs" / "milestones.json"
            classification_file = tool_dir / "logs" / "classification.json"

            try:
                stats = json.loads(stats_file.read_text())
            except Exception as e:
                print(f"[-] Error reading {stats_file}: {e}")
                continue

            row = dict(stats)
            row["cve_id"] = cve_dir.name
            row["tool"] = tool_dir.name

            row["docker_builds"] = False
            row["docker_runs"] = False
            row["code_hard_version"] = False
            row["network_setup"] = False
            row["flag_placed"] = False
            row["exploit_surface_ok"] = False
            if milestones_file.exists():
                try:
                    milestones = json.loads(milestones_file.read_text())
                    row["docker_builds"] = milestones.get("docker_builds", False)
                    row["docker_runs"] = milestones.get("docker_runs", False)
                    row["code_hard_version"] = milestones.get("code_hard_version", False)
                    row["network_setup"] = milestones.get("network_setup", False)
                    row["flag_placed"] = milestones.get("flag_placed", False)
                    row["exploit_surface_ok"] = milestones.get("exploit_surface_ok", False)
                except Exception:
                    pass

            if row.get("num_containers", 0) == 0:
                row["num_containers"] = get_intended_containers(tool_dir)

            classification_fields = {
                "kill_chain_steps": None,
                "cwe_id": "Unknown",
                "cwe_name": "Unknown",
                "attack_vector": "Unknown",
                "tech_stack": "Unknown",
                "requires_secondary_container": None,
                "requires_oob_interaction": None,
            }
            if classification_file.exists():
                try:
                    classification = json.loads(classification_file.read_text())
                    for key, default in classification_fields.items():
                        row[key] = classification.get(key, default)
                except Exception:
                    row.update(classification_fields)
            else:
                # Most runs that stop before classify_cve (CVE not found, platform
                # infeasible) never even reach this stage -- these fields are
                # legitimately unknown, not a parsing error.
                row.update(classification_fields)

            row["scout_was_run"] = scout_was_run(tool_dir)
            row["exploit_attempted"] = exploit_attempted(tool_dir)

            rows.append(row)

    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Per-run outcome stage (used both by the funnel and by the breakdown-by-dimension
# tables below). This is the SAME ladder route_test / graph.py enforces, expressed
# as a single categorical value per run so it can be cross-tabulated against any
# dimension (CWE, attack_vector, tech_stack, CVE year, ...) over the FULL
# population -- not just the stage-2 survivors.
# --------------------------------------------------------------------------- #

OUTCOME_STAGE_ORDER = [
    "docker_build_failed",
    "container_run_failed",
    "wrong_version",
    "network_misconfigured",
    "flag_not_placed",
    "exploit_surface_not_ready",
    "exploit_not_attempted",      
    "exploit_attempted_failed",
    "exploit_attempted_success",
]


def compute_outcome_stage(row) -> str:
    if not row.get("docker_builds", False):
        return "docker_build_failed"
    if not row.get("docker_runs", False):
        return "container_run_failed"
    if not row.get("code_hard_version", False):
        return "wrong_version"
    if not row.get("network_setup", False):
        return "network_misconfigured"
    if not row.get("flag_placed", False):
        return "flag_not_placed"
    if not row.get("exploit_surface_ok", False):
        return "exploit_surface_not_ready"
    if not row.get("exploit_attempted", False):
        return "exploit_not_attempted"
    if not row.get("exploitable", False):
        return "exploit_attempted_failed"
    return "exploit_attempted_success"


def print_outcome_breakdown(df: pd.DataFrame, dimension: str, label: str = None,
                             min_count: int = 1):
    """Cross-tabulate outcome_stage against `dimension` over the FULL population
    (stage 0). Answers 'is this type of environment hard to GENERATE vs hard to
    EXPLOIT' rather than just a win-rate among survivors.

    Groups with fewer than `min_count` runs are NOT dropped from the output -- they
    are moved to a separate 'long tail' section (raw stage counts only, no
    percentages, since a percentage over 1-2 samples is meaningless) so rare
    CWEs/groups stay visible. This matters for coverage purposes: e.g. spotting
    which vulnerability types currently have only 1-2 generated environments, so
    more CVEs of that type can be sourced deliberately."""
    if dimension not in df.columns:
        print(f"[-] Column '{dimension}' not available, skipping breakdown.")
        return

    sub = df.dropna(subset=[dimension]).copy()
    if sub.empty:
        print(f"[-] No rows with a known '{dimension}', skipping.")
        return

    sub["outcome_stage"] = pd.Categorical(
        sub["outcome_stage"], categories=OUTCOME_STAGE_ORDER, ordered=True)

    counts = pd.crosstab(sub[dimension], sub["outcome_stage"])
    counts = counts.reindex(columns=OUTCOME_STAGE_ORDER, fill_value=0)
    counts["Total"] = counts.sum(axis=1)
    counts = counts.sort_values("Total", ascending=False)

    main_groups = counts[counts["Total"] >= min_count]
    long_tail = counts[counts["Total"] < min_count]

    print("=" * 60)
    print(f"OUTCOME BREAKDOWN BY {label or dimension} (full population, stage 0, "
          f"n={len(sub)} runs, {counts.shape[0]} distinct groups)")
    print("=" * 60)

    if not main_groups.empty:
        pct = main_groups.drop(columns="Total").div(main_groups["Total"], axis=0) * 100
        print(f"\nGroups with >= {min_count} runs -- counts:")
        print(main_groups.to_string())
        print("\n% within each group (rows sum to 100):")
        print(pct.round(1).to_string())

        if "total_iterations" in sub.columns:
            iters = sub.groupby(dimension, observed=True)["total_iterations"].mean().round(2)
            print("\nAvg total_iterations (generation-loop cost) per group:")
            print(iters.reindex(main_groups.index).to_string())
    else:
        print(f"\n[!] No group reaches {min_count} runs -- see long tail below.")

    if not long_tail.empty:
        print(f"\n--- LONG TAIL: groups with < {min_count} runs "
              f"({len(long_tail)} groups, {int(long_tail['Total'].sum())} runs total) ---")
        print("(raw stage counts only, no %, too few samples to be meaningful. "
              "These are the candidates for 'find more CVEs of this type'.)")
        print(long_tail.to_string())

    print("-" * 60)


# --------------------------------------------------------------------------- #
# Funnel
# --------------------------------------------------------------------------- #

def print_funnel(df: pd.DataFrame):
    n0 = len(df)
    n1 = df[(df["docker_builds"]) & (df["docker_runs"])]
    n2 = n1[n1["exploit_attempted"]]

    stuck_pre_build = df[~(df["docker_builds"])]
    stuck_pre_exploit = n1[~n1["exploit_attempted"]]

    print("=" * 60)
    print("VALIDATION FUNNEL")
    print("=" * 60)
    print(f"STAGE 0  all_runs (have stats.json)      : {n0}")
    print(f"STAGE 1  built_and_ran                    : {len(n1)}"
          f"  ({100 * len(n1) / n0:.1f}% of stage 0)" if n0 else "")
    print(f"STAGE 2  exploit_attempted                 : {len(n2)}"
          f"  ({100 * len(n2) / len(n1):.1f}% of stage 1)" if len(n1) else "")
    print()
    print(f"  Never built/ran (docker_builds=False)    : {len(stuck_pre_build)}")
    print(f"  Built+ran but exploit NEVER attempted     : {len(stuck_pre_exploit)}")
    if len(stuck_pre_exploit):
        # Best-effort attribution using the milestone fields we captured.
        no_network = stuck_pre_exploit[~stuck_pre_exploit.get("exploit_surface_ok", False).astype(bool)]
        print(f"    -> of these, exploit_surface_ok never True: {len(no_network)}")
        print("    (these are NOT exploit failures -- red_team.py was never invoked "
              "for them; do not count them as TN/FN.)")
    print("-" * 60)
    return n2  # the only population used from here on for exploit-outcome stats


# --------------------------------------------------------------------------- #
# Infra metrics (STAGE 0 / STAGE 1 -- no exploit-outcome claims here)
# --------------------------------------------------------------------------- #

def print_infra_stats(df: pd.DataFrame):
    print("=" * 60)
    print(f"INFRA STATS (Stage 0, {len(df)} runs -- build/run only, "
          f"NOT exploit outcomes)")
    print("=" * 60)

    error_cols = ["image_build_failures", "container_run_failures",
                  "not_vuln_version_fail", "docker_misconfigured"]
    for col in error_cols:
        if col in df.columns:
            total = df[col].sum()
            avg = df[col].mean()
            print(f"- {col}: {total} total (avg {avg:.2f} per run)")

    if "test_iteration" in df.columns:
        print(f"- avg test_iteration (all runs): {df['test_iteration'].mean():.2f}")
    print("-" * 60)


# --------------------------------------------------------------------------- #
# Exploit-outcome metrics (STAGE 2 ONLY)
# --------------------------------------------------------------------------- #

def determine_outcome(row):
    scout = row.get("docker_scout_vulnerable", False)
    exploit = row.get("exploitable", False)
    if scout and exploit:
        return "TP"
    if not scout and not exploit:
        return "TN"
    if scout and not exploit:
        return "FP"
    return "FN"

def print_exploit_stats(df2: pd.DataFrame):
    if df2.empty:
        print("[!] No runs reached exploit_attempted -- nothing to report here.")
        return

    print("=" * 60)
    print(f"EXPLOIT-OUTCOME STATS (Stage 2, {len(df2)} runs where the red-team "
          f"agent was actually invoked)")
    print("=" * 60)

    success_rate = df2["exploitable"].mean() * 100
    print(f"Global exploit success rate: {success_rate:.2f}%\n")

    n_scouted = df2["scout_was_run"].sum()
    if n_scouted == 0:
        print("[!] WARNING: logs/cves*.json was never found for ANY stage-2 run. "
              "docker_scout_vulnerable is sitting at its default (False) for all "
              "of them because assess_vuln() was never reached (it requires "
              "skip_to_scout=True). Skipping the Scout-vs-exploit confusion "
              "matrix -- it would just show 100% 'TN'.")
    else:
        if n_scouted < len(df2):
            print(f"[!] Scout was actually run for {n_scouted}/{len(df2)} stage-2 "
                  f"runs. Restricting the confusion matrix to those.")
        scouted_df = df2[df2["scout_was_run"]].copy()
        scouted_df["Outcome"] = scouted_df.apply(determine_outcome, axis=1)
        print("\nCONFUSION MATRIX (Scout vs exploit, Scout-verified runs only):")
        print(scouted_df["Outcome"].value_counts().to_string())
    print("-" * 60)

    if "num_containers" in df2.columns:
        print("\nSUCCESS RATE BY CONTAINER COUNT (stage 2 only):")
        cs = df2.groupby("num_containers").agg(
            Total=("cve_id", "count"), Vulnerable=("exploitable", "sum"))
        cs["Win Rate (%)"] = (100 * cs["Vulnerable"] / cs["Total"]).round(2)
        print(cs.to_string())
        print("-" * 60)

    if "cwe_name" in df2.columns and "cwe_id" in df2.columns:
        print("\nWIN RATE BY VULNERABILITY TYPE / CWE (stage 2 only):")
        cwe = df2.groupby("cwe_id", observed=True).agg(
            Total=("cve_id", "count"),
            Exploitable=("exploitable", "sum"),
            cwe_name=("cwe_name", "first")
        ).sort_values("Total", ascending=False)
        cwe["Win Rate (%)"] = (100 * cwe["Exploitable"] / cwe["Total"]).round(2)
        cwe = cwe[["cwe_name", "Total", "Exploitable", "Win Rate (%)"]]
        print(cwe.to_string())
        print("-" * 60)

    kc_df = df2.dropna(subset=["kill_chain_steps"])
    if not kc_df.empty:
        print("\nWIN RATE BY KILL CHAIN STEPS (stage 2 only):")
        kc = kc_df.groupby("kill_chain_steps").agg(
            Total=("cve_id", "count"), Exploitable=("exploitable", "sum"))
        kc["Win Rate (%)"] = (100 * kc["Exploitable"] / kc["Total"]).round(2)
        print(kc.to_string())
        print("-" * 60)

    try:
        df2 = df2.copy()
        df2["cve_year"] = df2["cve_id"].str.extract(r"CVE-(\d{4})-").astype(int)
        print("\nSUCCESS RATE PER CVE YEAR (stage 2 only):")
        yr = df2.groupby("cve_year").agg(
            Total=("cve_id", "count"), Vulnerable=("exploitable", "sum"))
        yr["Win Rate (%)"] = (100 * yr["Vulnerable"] / yr["Total"]).round(2)
        print(yr.to_string())
        print("-" * 60)
        
        def get_period(year):
            if year <= 2018:
                return "Until 2018"
            elif 2019 <= year <= 2024:
                return "2019-2024"
            else:
                return "2025+"
                
        df2["cve_period"] = df2["cve_year"].apply(get_period)
        print("\nSUCCESS RATE PER CVE PERIOD (stage 2 only):")
        period_order = ["Until 2018", "2019-2024", "2025+"]
        df2["cve_period"] = pd.Categorical(df2["cve_period"], categories=period_order, ordered=True)
        per = df2.groupby("cve_period", observed=False).agg(
            Total=("cve_id", "count"), Vulnerable=("exploitable", "sum"))
        per["Win Rate (%)"] = (100 * per["Vulnerable"] / per["Total"]).round(2)
        print(per.to_string())
        print("-" * 60)
        
    except Exception as e:
        print(f"[-] CVE-year analysis skipped: {e}")

def fetch_epss_score(cve_id: str) -> float:
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("data"):
                time.sleep(0.1)
                return float(data["data"][0]["epss"])
        elif r.status_code == 429:
            time.sleep(3)
            return fetch_epss_score(cve_id)
    except requests.exceptions.RequestException as e:
        print(f"   [!] EPSS network error for {cve_id}: {e}")
    time.sleep(0.1)
    return -1.0


def print_virality(df2: pd.DataFrame):
    if df2.empty:
        return
    print("\nVIRALITY ANALYSIS (EPSS score, stage 2 only):")
    unique_cves = df2["cve_id"].unique()
    epss_map = {cve: fetch_epss_score(cve) for cve in unique_cves}
    df2 = df2.copy()
    df2["epss_score"] = df2["cve_id"].map(epss_map)

    if df2["epss_score"].nunique() > 1:
        try:
            df2["Virality"] = pd.qcut(df2["epss_score"], q=2,
                                       labels=["Low", "High"])
        except ValueError:
            median = df2["epss_score"].median()
            df2["Virality"] = df2["epss_score"].apply(
                lambda x: "High" if x > median else "Low")
    else:
        print("   [!] Not enough EPSS variance.")
        return

    v = df2.groupby("Virality").agg(
        Total=("cve_id", "count"), Vulnerable=("exploitable", "sum"))
    v["Win Rate (%)"] = (100 * v["Vulnerable"] / v["Total"]).round(2)
    print(v.to_string())
    print("-" * 60)


def print_poc_comparison(base_path: Path):
    print("\n" + "=" * 60)
    print("PoC COMPARISON (Agent vs Public PoC)")
    print("=" * 60)
    poc_data = []
    for poc_file in base_path.rglob("poc_comparison.json"):
        try:
            data = json.loads(poc_file.read_text())
            data["cve_id"] = poc_file.parts[-3]
            poc_data.append(data)
        except Exception as e:
            print(f"[-] Error reading {poc_file}: {e}")
    if not poc_data:
        print("[-] No poc_comparison.json found.")
        return
    df = pd.DataFrame(poc_data)
    print(f"Comparisons performed: {len(df)}")
    print(f"Average Kill Chain Similarity (1-10): {df['kill_chain_similarity'].mean():.2f}")
    hardcoded_rate = (df["hardcoded_data_agent"].sum() / len(df)) * 100
    print(f"Hardcoding rate (Agent cheating): {hardcoded_rate:.2f}%")
    print("=" * 60)

def print_epss_band_breakdown(df: pd.DataFrame, epss_map: dict = None,
                              bin_width: float = 0.1):
    """[STATISTICS] Breakdown per fascia di EPSS sulla POPOLAZIONE COMPLETA (stage 0).

    A differenza di print_virality() (che scarica l'EPSS solo per lo stage 2 e
    divide in quantili Low/High), questa funzione:

      * usa fasce a larghezza fissa (0.0-0.1, 0.1-0.2, ... [left-closed]),
      * lavora su TUTTI gli ambienti generati (serve per contare 'quanti in
        totale' per fascia, inclusi quelli che non hanno mai raggiunto il red team),
      * per ogni fascia riporta:
          - CVEs               : numero di CVE UNICI nella fascia
          - Environments       : numero di ambienti/run (cve, tool) nella fascia
          - Reached evaluator  : run con exploit_attempted=True (red team invocato)
          - Flag captured      : run con exploitable=True (flag catturato)
        piu' due tassi derivati (% reached su env, % captured su reached).

    NB: 'evaluator' qui = white-box red team agent; 'flag captured' = exploitable.
        exploitable=True implica exploit_attempted=True, ma il conteggio fa
        comunque l'AND per robustezza contro stats.json malformati.

    epss_map: opzionale, {cve_id: epss_float}. Se None viene costruita qui via
    fetch_epss_score() (chiamate di rete a first.org). Passala se hai gia'
    scaricato gli score altrove per evitare doppie richieste.
    """
    if df.empty:
        print("[!] Nessun run: skip EPSS band breakdown.")
        return

    df = df.copy()

    # Normalizza i due flag booleani (default False se assenti/NaN)
    df["_reached_eval"] = df["exploit_attempted"] & df["docker_runs"] & df["docker_builds"]
    df["_reached_eval"] = df["_reached_eval"].fillna(False).astype(bool)
    df["_flag_captured"] = df.get("exploitable", False)
    df["_flag_captured"] = df["_flag_captured"].fillna(False).astype(bool)
    # flag catturato SOLO se il red team e' stato davvero invocato
    df["_flag_captured"] = df["_flag_captured"] & df["_reached_eval"]

    # Mappa EPSS su TUTTI i CVE unici della popolazione completa
    if epss_map is None:
        unique_cves = df["cve_id"].unique()
        print(f"\n[i] Scarico EPSS per {len(unique_cves)} CVE unici "
              f"(popolazione completa, non solo stage 2)...")
        epss_map = {cve: fetch_epss_score(cve) for cve in unique_cves}

    df["epss_score"] = df["cve_id"].map(epss_map)

    # Separa i fetch falliti (-1.0) o mancanti: non hanno una fascia valida
    unknown_mask = df["epss_score"].isna() | (df["epss_score"] < 0)
    unknown = df[unknown_mask]
    valid = df[~unknown_mask].copy()

    print("\n" + "=" * 72)
    print(f"EPSS BAND BREAKDOWN (full population, stage 0, n={len(df)} ambienti, "
          f"{df['cve_id'].nunique()} CVE unici)")
    print("Fasce EPSS a larghezza {:.2f}, left-closed [a, b). "
          "'evaluator' = red team agent.".format(bin_width))
    print("=" * 72)

    if valid.empty:
        print("[!] Nessun EPSS valido (tutti i fetch falliti?). "
              "Controlla la rete / first.org.")
    else:
        # Costruzione delle fasce [0.0,0.1), [0.1,0.2), ... con 1.0 incluso in cima
        n_bins = int(round(1.0 / bin_width))
        edges = [round(i * bin_width, 10) for i in range(n_bins + 1)]  # 0.0 .. 1.0
        labels = [f"{edges[i]:.2f}-{edges[i + 1]:.2f}" for i in range(n_bins)]
        cut_edges = list(edges)
        cut_edges[-1] = edges[-1] + 1e-9  # cattura anche epss == 1.0 nell'ultima fascia

        valid["epss_band"] = pd.cut(
            valid["epss_score"], bins=cut_edges, labels=labels,
            right=False, include_lowest=True)

        g = valid.groupby("epss_band", observed=False)
        table = pd.DataFrame({
            "CVEs": g["cve_id"].nunique(),
            "Environments": g.size(),
            "Reached evaluator": g["_reached_eval"].sum(),
            "Flag captured": g["_flag_captured"].sum(),
        })
        # Tassi derivati (NaN dove il denominatore e' 0 -> gestiti a valle)
        table["% reached (of env)"] = (
            100 * table["Reached evaluator"] / table["Environments"]).round(1)
        table["% captured (of reached)"] = (
            100 * table["Flag captured"] / table["Reached evaluator"]).round(1)

        # Riga TOTAL
        total = pd.DataFrame({
            "CVEs": [valid["cve_id"].nunique()],
            "Environments": [len(valid)],
            "Reached evaluator": [int(valid["_reached_eval"].sum())],
            "Flag captured": [int(valid["_flag_captured"].sum())],
        }, index=["TOTAL"])
        total["% reached (of env)"] = (
            100 * total["Reached evaluator"] / total["Environments"]).round(1)
        total["% captured (of reached)"] = (
            100 * total["Flag captured"] / total["Reached evaluator"]).round(1)

        out = pd.concat([table, total])
        # Rendi leggibili i denominatori nulli
        out = out.fillna("-")
        print(out.to_string())

    if not unknown.empty:
        print(f"\n[!] EPSS sconosciuto (fetch fallito / -1.0): "
              f"{unknown['cve_id'].nunique()} CVE, {len(unknown)} ambienti "
              f"esclusi dalle fasce. CVE: {', '.join(sorted(unknown['cve_id'].unique()))}")
    print("-" * 72)

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dockers_dir", nargs="?", default="../../dockers")
    ap.add_argument("--skip-epss", action="store_true",
                     help="Skip the EPSS virality analysis (avoids network calls).")
    ap.add_argument("--skip-poc-comparison", action="store_true")
    args = ap.parse_args()

    base_path = Path(args.dockers_dir).resolve()
    if not base_path.exists():
        print(f"[-] {base_path} does not exist.")
        return

    df = load_runs(base_path)
    if df.empty:
        print(f"[-] No stats.json found under {base_path}.")
        return

    df["outcome_stage"] = df.apply(compute_outcome_stage, axis=1)
    try:
        df["cve_year"] = df["cve_id"].str.extract(r"CVE-(\d{4})-")
    except Exception:
        df["cve_year"] = None

    df2 = print_funnel(df)
    print_infra_stats(df)
    print_exploit_stats(df2)

    if "cwe_id" not in df2.columns or "cve_id" not in df2.columns:
        print("[-] Missing 'cwe_id' or 'cve_id' column for mapping.")
        return

    # Ensure cwe_name exists for display fallback
    if "cwe_name" not in df2.columns:
        df2 = df2.copy()
        df2["cwe_name"] = "Unknown"

    # Group by cwe_id to avoid name fragmentation, collecting unique CVEs and the first name
    grouped = df2.dropna(subset=["cwe_id", "cve_id"]).groupby("cwe_id").agg(
        cves=("cve_id", "unique"),
        cwe_name=("cwe_name", "first")
    )
    
    # Format into a list for sorting
    cwe_items = [
        (cwe_id, row["cwe_name"], row["cves"]) 
        for cwe_id, row in grouped.iterrows()
    ]
    
    # Sort by the number of CVEs descending, then alphabetically by CWE ID
    cwe_items.sort(key=lambda x: (-len(x[2]), str(x[0])))
    #for cwe_id, cwe_name, cves in cwe_items:
    #    print(f"\n{cwe_id} - {cwe_name} ({len(cves)} CVEs):")
    #    print(", ".join(sorted(cves)))
        
    #print("-" * 60)

    print("\n" + "#" * 60)
    print("# OUTCOME BREAKDOWN BY DIMENSION (full population)")
    print("# Separates 'hard to GENERATE' (early stages) from")
    print("# 'hard to EXPLOIT' (exploit_attempted_* stages) per group.")
    print("#" * 60 + "\n")

    df = df.copy()
    if "cwe_id" in df.columns and "cwe_name" in df.columns:
        name_map = (
            df.dropna(subset=["cwe_id"])
            .groupby("cwe_id")["cwe_name"]
            .agg(lambda s: s.mode().iat[0])
        )
        df["cwe_name"] = df["cwe_id"].map(name_map).fillna(df["cwe_name"])

    for dim, label, min_count in [
            ("cwe_name", "CWE / vulnerability type", 3),
            ("attack_vector", "attack vector", 1),
            ("tech_stack", "tech stack", 3),
            ("requires_secondary_container", "requires secondary container (SSRF-style)", 1),
            ("cve_year", "CVE year", 3),
            ("kill_chain_steps", "kill chain steps", 3),
        ]:
        print_outcome_breakdown(df, dim, label, min_count=min_count)

    #if not args.skip_epss:
        #print_virality(df2)
    print_epss_band_breakdown(df)
    #if not args.skip_poc_comparison:
    #    print_poc_comparison(base_path)


if __name__ == "__main__":
    main()