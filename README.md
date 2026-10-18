# Vuln-Forge

**Creating Containerized Vulnerable Environments with LLM-based Agents**

Master's thesis in Cybersecurity — Politecnico di Torino, A.A. 2025/2026
Candidate: Manuele Sforzini

---

## What is this?

Vuln-Forge is a dual-agent pipeline that automatically generates containerized,
intentionally vulnerable environments starting **only from a CVE-ID**, and then
dynamically validates whether the generated environment is actually exploitable.

Capture-The-Flag (CTF) style vulnerable environments are widely used to evaluate
offensive-security AI agents, but building them by hand doesn't scale with the
growing number of disclosed vulnerabilities. Vuln-Forge investigates whether this
process can be automated with agentic AI, without requiring the target
application's source code or a public Proof of Concept (PoC) as input — which
also makes the approach applicable to very recent CVEs.

The pipeline is built around two cooperating agents:

- **The Forger** — given a CVE-ID, searches the web for technical context,
  classifies the vulnerability, generates a Docker/Docker Compose environment
  reproducing it, iteratively tests and fixes the environment, and plants a CTF
  flag reachable only by exploiting the intended flaw.
- **The Evaluator** — an autonomous, white-box red-team agent that attacks the
  generated environment over the network and attempts to retrieve the flag,
  providing dynamic evidence that the vulnerability is actually exploitable
  (as opposed to just "a vulnerable package version is installed").

The environments are validated in three complementary ways: static analysis
(Docker Scout), dynamic exploitation by the Evaluator, and — where available —
execution of a public PoC adapted to the generated environment. The thesis
evaluates the pipeline on 226 CVEs across 25 CWE classes.

## Results in short

- The Forger produced a working, testable environment in **66.4%** of attempts.
- The Evaluator confirmed exploitability in **38.0%** of those environments.
- On the subset with a public PoC, the Evaluator's verdict matched the PoC's
  outcome **78.7%** of the time.
- Static analysis alone (Docker Scout) is shown to be an unreliable proxy for
  exploitability — it disagrees with dynamic validation in a large share of
  cases, both as false positives and false negatives.

Full methodology, experiments, and discussion are in `thesis.pdf` (the thesis
document).

## Project structure

```
.
├── docker-agent/      # Main pipeline: CVE-ID -> vulnerable environment + validation
│   ├── agent.py            # Entry point / agent loop
│   ├── graph.py             # LangGraph workflow definition
│   ├── state.py              # Shared pipeline state (Pydantic)
│   ├── configuration.py       # Structured-output schemas, config, env vars
│   ├── prompts.py              # All prompts used across pipeline stages
│   ├── nodes_dir/                # Individual graph nodes (one stage each)
│   │   ├── set_up_nodes.py          # Setup, LLM init, CVE-ID validation
│   │   ├── services_nodes.py         # Web search / service discovery
│   │   ├── platform_check_nodes.py    # Linux/Docker feasibility check
│   │   ├── classification_nodes.py     # CVE classification + flag placement
│   │   ├── code_nodes.py                # Environment code generation/revision
│   │   ├── test_code_nodes.py            # Build/run/network/flag tests
│   │   ├── assessment_nodes.py            # Docker Scout + sanity check
│   │   ├── red_team_nodes.py               # Evaluator orchestration, nonce injection
│   │   └── debugger_nodes.py                # Soft/Hard fix after failed exploit
│   ├── red_team_prompt.py      # Dynamic red-team prompt construction
│   └── utils/                   # Docker orchestration, file I/O helpers
│
├── scraper/            # [SCRAPER] Public PoC discovery (Vulhub, ExploitDB, Trickest, GitHub)
│   ├── poc_scraper.py
│   └── run_scraper.py
│
├── poc-runner/          # [POC-RUNNER] Adapts & executes public PoCs against generated envs
│   ├── main.py
│   ├── adapt_poc.py
│   ├── run_poc.py
│   └── triage.py / post-analysis.py
│
├── statistics/            # [STATISTICS] Result aggregation and analysis scripts
│   ├── container_stats_fixed.py
│   ├── extended_stats.py
│   ├── poc_vs_agent.py
│   └── stats.py / count_cve_types.py / ...
│
└── thesis.pdf             # Full thesis document
```

## How it works (high level)

1. **Input gathering** — the forger validates the CVE-ID against the MITRE
   database, searches the web (Google/SerpAPI, NVD, GitHub Security Advisories)
   and summarizes the vulnerability and the services involved.
2. **Classification** — an LLM determines the CWE, attack vector, exploitation
   mechanics, kill-chain length, and where/how the CTF flag should be placed,
   subject to deterministic consistency checks.
3. **Code generation & iterative testing** — the forger writes a
   `docker-compose.yml` + supporting files, then builds and tests the
   environment (image build, container health, correct vulnerable version,
   network reachability, flag placement), revising the code on any failure.
4. **Sanity check** — probes the running environment to make sure the flag
   isn't trivially reachable without exploiting the vulnerability.
5. **Validation** — Docker Scout performs static analysis; the Evaluator agent
   (running sandboxed, with no access to the Docker daemon) attempts to
   exploit the environment over the network and capture the flag, which has
   been replaced at runtime with an unguessable nonce to prevent cheating.
6. **Debugging loop** — on a failed exploit, the forger diagnoses whether the
   issue is a tactical agent mistake (soft fix: new hint, retry) or an
   environment misconfiguration (hard fix: regenerate code).

## Requirements

- Docker & Docker Compose
- Python 3.11+
- [Opencode](https://opencode.ai/) (used to run the Evaluator agent)
- An OpenRouter API key (`MY_OPENROUTER_API_KEY`) — or adapt `configuration.py`
  / the node files to point at another OpenAI-compatible endpoint
- Optional: `GITHUB_TOKEN`, `SERPAPI_KEY`, `LANGFUSE_*` keys for web search and
  tracing

Install Python dependencies:

```bash
pip install -r requirements.txt   # see individual module imports if not present
```

## Usage

### Run the main pipeline on one or more CVEs

```bash
cd docker-agent
export MY_OPENROUTER_API_KEY=your_key_here
python agent.py
```

Edit the `cve_list` in `agent.py` (`main()`) to choose which CVEs to process.
Each run creates `dockers/<CVE-ID>/<web_search_tool>/` with the generated
environment, logs, classification, and final results.

Useful flags inside `run_agent(...)`:
- `skip_to_red_team` — resume directly at the Evaluator stage for an already
  built environment.
- `reuse_classification` / `reuse_web_search_and_code` — resume from a later
  stage reusing cached intermediate artifacts.

### Scrape public PoCs for comparison

```bash
cd scraper
python run_scraper.py --find-new      # discover candidate CVEs
python run_scraper.py                 # scrape PoCs for already-processed CVEs
```

### Run the PoC-based validation

```bash
cd poc-runner
python main.py
```

Adapts each scraped PoC to the corresponding generated environment via an LLM
and executes it, checking for flag capture (also nonce-protected).

### Generate statistics from a completed run

```bash
cd statistics
python container_stats_fixed.py ../../dockers
python extended_stats.py ../../dockers
```
