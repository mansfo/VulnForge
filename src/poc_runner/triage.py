#!/usr/bin/env python3
"""
PoC-runner triage — classify environments and summarize iterative-repair results.

Walks dockers/CVE-*/<tool>/poc_runner/ and inspects artifacts produced by main.py.

Usage:
    python3 triage.py [DOCKERS_DIR] [--results poc_runner_results.json]
    python3 triage.py [DOCKERS_DIR] --dump unclassified
    python3 triage.py [DOCKERS_DIR] --dump noadapt
"""
import sys
import re
import json
from pathlib import Path
from collections import Counter, defaultdict


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


HTTP_CODES = re.compile(
    r"\b(200|201|204|301|302|400|401|403|404|405|422|429|500|502|503)\b"
)


def classify(summary: dict, metas: list[dict]) -> str:
    if summary.get("reason") == "docker_failed":
        return "docker_failed"
    if summary.get("success"):
        return "success"
    if not metas:
        return "no_artifacts"
    if all(not m.get("adapted") for m in metas):
        return "no_adaptation"
    if any(m.get("cheat_detected") for m in metas) and not any(
        m.get("ran") for m in metas
    ):
        return "all_cheated"
    if any(m.get("ran") for m in metas):
        return "ran_but_failed"
    return "other"


def scan_output(text: str) -> str:
    for name, rx in SIGNATURES:
        if rx.search(text):
            return name
    if text.strip() == "":
        return "empty_output"
    return "unclassified"


def fingerprint(text: str) -> str:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    codes = ",".join(sorted(set(HTTP_CODES.findall(text)))) or "-"
    first = (lines[0][:90] + "...") if lines and len(lines[0]) > 90 else (lines[0] if lines else "")
    last = (lines[-1][:90] + "...") if lines and len(lines[-1]) > 90 else (lines[-1] if lines else "")
    return f"len={len(text):<6} http={codes:<12} first={first!r} last={last!r}"


def load_candidate_metas(poc_dir: Path) -> list[dict]:
    metas = []
    for mp in sorted(poc_dir.glob("*/meta.json")):
        try:
            metas.append(json.loads(mp.read_text()))
        except Exception:
            pass
    return metas


def load_attempts(poc_dir: Path) -> list[dict]:
    attempts = []
    for mp in sorted(poc_dir.glob("*/attempt_*/meta.json")):
        try:
            data = json.loads(mp.read_text())
            data["_path"] = str(mp)
            attempts.append(data)
        except Exception:
            pass
    return attempts


def main():
    args = [a for a in sys.argv[1:]]
    results_path = None

    if "--results" in args:
        i = args.index("--results")
        results_path = Path(args[i + 1])
        del args[i:i + 2]

    dockers_dir = Path(args[0]) if args else Path("./../../dockers")

    dump = None
    if "--dump" in args:
        i = args.index("--dump")
        dump = args[i + 1]
        del args[i:i + 2]
        dockers_dir = Path(args[0]) if args else Path("./../../dockers")

    summaries = sorted(dockers_dir.glob("CVE-*/*/poc_runner/summary.json"))

    stage_counts = Counter()
    stage_examples = defaultdict(list)
    sig_counts = Counter()
    sig_examples = defaultdict(list)

    repair_counts = Counter()
    repair_success = Counter()
    winning_attempts = Counter()

    flag_inject_false = []
    served_desync = []
    _dump_rows = []

    for sp in summaries:
        cve = sp.parts[-4]
        summary = json.loads(sp.read_text())
        poc_dir = sp.parent

        metas = load_candidate_metas(poc_dir)
        stage = classify(summary, metas)

        stage_counts[stage] += 1
        if len(stage_examples[stage]) < 5:
            stage_examples[stage].append(cve)

        if dump == "noadapt" and stage == "no_adaptation":
            for m in metas:
                _dump_rows.append(
                    f"{cve:20s} [{m.get('source')}] "
                    f"{str(m.get('explanation'))[:160]}"
                )

        if dump == "unclassified" and stage == "ran_but_failed":
            for out in sorted(poc_dir.glob("*/attempt_*/output.txt")):
                text = out.read_text(errors="ignore")
                if scan_output(text) == "unclassified":
                    _dump_rows.append(
                        f"{cve}/{out.parent.parent.name}/{out.parent.name}\n"
                        f"    {fingerprint(text)}"
                    )

        if summary.get("flag_injected") is False and stage != "docker_failed":
            flag_inject_false.append(cve)

        if stage == "docker_failed":
            print(cve)

        if stage == "ran_but_failed":
            for out in sorted(poc_dir.glob("*/attempt_*/output.txt")):
                text = out.read_text(errors="ignore")
                sig = scan_output(text)
                sig_counts[sig] += 1

                if len(sig_examples[sig]) < 3:
                    sig_examples[sig].append(
                        f"{cve}/{out.parent.parent.name}/{out.parent.name}"
                    )

                if "FLAG{" in text and sig not in (
                    "missing_module",
                    "conn_refused",
                ):
                    served_desync.append(
                        f"{cve}/{out.parent.parent.name}/{out.parent.name}"
                    )

        # Candidate-level repair statistics.
        for meta in metas:
            repairs = int(meta.get("num_repairs", 0))
            repair_counts[repairs] += 1

            if meta.get("success") and repairs:
                repair_success[repairs] += 1

        if summary.get("success") and summary.get("winning_candidate"):
            winning_attempts[summary["winning_candidate"].get("attempt", 0)] += 1

    if dump:
        print(f"\n=== dump: {dump} ({len(_dump_rows)} rows) ===")
        for row in _dump_rows:
            print("  " + row)
        return

    total = sum(stage_counts.values())

    print(f"\n=== PoC-runner triage — {total} environments with artifacts ===\n")

    if total == 0:
        print(
            "No poc_runner/summary.json found. Either the run used an older "
            "main.py, or the path is wrong."
        )
        print(f"Tried: {dockers_dir.resolve()}")

        if results_path and results_path.exists():
            res = json.loads(results_path.read_text())
            ok = sum(1 for v in res.values() if v.get("success"))
            inj = sum(
                1 for v in res.values()
                if v.get("flag_injected") is False
            )
            print(
                f"\nFrom {results_path}: {ok}/{len(res)} success; "
                f"{inj} with flag_injected=false."
            )
        return

    print("Failure stage distribution:")
    order = [
        "success",
        "ran_but_failed",
        "no_adaptation",
        "all_cheated",
        "docker_failed",
        "no_artifacts",
        "other",
    ]

    for stage in order:
        if stage_counts.get(stage):
            examples = ", ".join(stage_examples[stage][:5])
            print(f"  {stage:16s} {stage_counts[stage]:3d}   e.g. {examples}")
    print()

    if sig_counts:
        print("Runtime output signatures (per repair attempt):")
        for sig, n in sig_counts.most_common():
            examples = ", ".join(sig_examples[sig][:3])
            print(f"  {sig:16s} {n:3d}   e.g. {examples}")
        print()

    total_repairs = sum(
        n * repairs for repairs, n in repair_counts.items()
    )

    if repair_counts:
        print("Repair distribution (per candidate):")
        for repairs in sorted(repair_counts):
            print(f"  repairs={repairs:<2d} {repair_counts[repairs]:3d}")
        print(f"  total repair calls recorded: {total_repairs}")

        if winning_attempts:
            print("\nWinning attempt distribution:")
            for attempt, n in sorted(winning_attempts.items()):
                print(f"  attempt={attempt:<2d} {n:3d}")

        print("\nSuccesses by number of repairs used:")
        for repairs in sorted(repair_success):
            print(f"  repairs={repairs:<2d} {repair_success[repairs]:3d}")
        print()

    if flag_inject_false:
        print(
            f"flag_injected=false: {len(flag_inject_false)} "
            f"(expected for environments where nonce injection is not supported)"
        )
        print(
            "  -> " + ", ".join(flag_inject_false[:8])
            + (" ..." if len(flag_inject_false) > 8 else "")
        )

    if served_desync:
        uniq = sorted(set(served_desync))
        print(
            f"\n[!] Possible oracle desync ({len(uniq)}): a FLAG{{...}} "
            "was printed but did NOT match the searched value."
        )
        print(
            "    Check whether the printed value is the injected nonce, "
            "placeholder, or a stale database/file value."
        )


if __name__ == "__main__":
    main()