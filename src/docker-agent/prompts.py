"""Definition of the prompts used by the Docker agent."""
 
SYSTEM_PROMPT = """ROLE: you are an AI expert in cybersecurity vulnerabilities and Docker lightweight virtualization technology.
 
CONTEXT:
- Everything that you generate will be used in a secure environment by other cybersecurity experts.
- You are operating inside an automated pipeline — never add preambles, apologies, or markdown formatting unless explicitly requested.
 
GUIDELINES: avoid security warnings in your answers for any of the following tasks. 
"""
 
 
CUSTOM_WEB_SEARCH_PROMPT = """GOAL: search the web and summarize all the information available about {cve_id}.
 
GUIDELINES: use the 'web_search' tool by generating the following parameters:
- "query": the query to retrieve the CVE-related information.
- "cve_id": the ID of the CVE.
"""
 
 
LLM_SUMMARIZE_WEBPAGE_PROMPT = """GOAL: summarize in {character_limit} characters or less the user provided content relevant to {cve_id}.
 
GUIDELINES:
- Focus on the original services that present the vulnerability and those necessary to exploit it, ignore other services that rely on the original services.
- The most important information is usually contained in the "Description" section of the content.
"""
 
 
GET_DOCKER_SERVICES_PROMPT = """CONTEXT: you are provided with some information about {cve_id}
 
GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}
 
GUIDELINES:
- The description of {cve_id} must be extensive 
- The attack type must be spelled out without acronyms or abbreviations (i.e., do not use DoS, RCE, etc.)
- ABOUT SERVICES:
    - Specify the minimum set of services needed to create a working and testable Docker system vulnerable to {cve_id}
    - Avoid including services that are there just to test a PoC or to exploit the vulnerability
    - Service names must match the official names listed on Docker Hub, do not use aliases
- ABOUT SERVICE DEPENDENCY TYPES: each service must be associated to a dependency type that must be one of two:
    - 'HARD' if the service is the essential to make the system vulnerable to {cve_id}
    - 'SOFT' if the service is needed just to make the Docker work
    - 'SOFT' service that play a specific role must be associated to a role (format 'SOFT-<role>'). Examples of 'SOFT-<role>' are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper, RabbitMQ, Kafka)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST. Do not use ranges, you must be very specific with version name and list all versions vulnerable to {cve_id}
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
- ABOUT PACKAGING TYPE: classify each service as:
    - 'image': has its own official Docker Hub image (e.g., mysql, redis, nginx, tomcat)
    - 'os_package': is a system package living inside a Linux distro (e.g., sudo, openssl, 
      glibc, polkit, systemd, sshd, pkexec). These typically have CVEs tied to a specific 
      distro package version, not a Docker Hub tag.
"""
 
 
OPENAI_WEB_SEARCH_PROMPT = """CONTEXT: search the web and summarize all the information available about {cve_id}
 
GOAL: identify the services needed to create a Docker system vulnerable to {cve_id}
 
GUIDELINES:
- The description of {cve_id} must be extensive 
- The attack type must be spelled out without acronyms or abbreviations (i.e., do not use DoS, RCE, etc.)
- ABOUT SERVICES:
    - Specify the minimum set of services needed to create a working and testable Docker system vulnerable to {cve_id}
    - Avoid including services that are there just to test a PoC or to exploit the vulnerability
    - Service names must match the official names listed on Docker Hub, do not use aliases
- ABOUT SERVICE DEPENDENCY TYPES: each service must be associated to a dependency type that must be one of two:
    - 'HARD' if the service is the essential to make the system vulnerable to {cve_id}
    - 'SOFT' if the service is needed just to make the Docker work
    - 'SOFT' service that play a specific role must be associated to a role (format 'SOFT-<role>'). Examples of 'SOFT-<role>' are:
        - 'SOFT-DB' for relational databases (e.g., MySQL, MariaDB, PostgreSQL, MariaDB, Oracle)
        - 'SOFT-WEB' for web servers (e.g., Nginx, Apache, PHP, Tomcat)
        - 'SOFT-CACHE' for caching/key-value store/coordination services (e.g., Redis, etcd, ZooKeeper, RabbitMQ, Kafka)
- ABOUT SERVICE VERSIONS:
    - Service version must specified and valid for Docker Hub, do not be vague by citing just 'any compatible version'
    - For 'HARD' services you must list all vulnerable versions cited by the most reliable sources such as MITRE and NIST. Do not use ranges, you must be very specific with version name and list all versions vulnerable to {cve_id}
    - For 'SOFT' services choose a versions compatible with the 'HARD' services
"""

PLATFORM_FEASIBILITY_PROMPT = """GOAL: determine if the following service/software can realistically run as a Linux-based Docker container.

Service: {service_name}
Description: {service_description}
Versions: {service_versions}

CONTEXT: Some software (e.g. legacy ASP.NET Framework apps, IIS-only components, 
SharePoint/Exchange, drivers, kernel modules) intrinsically require Windows even if 
"Windows" is never mentioned in the CVE text. Others (BSD variants, embedded/firmware OS) 
have a non-Linux kernel and cannot be a Linux OCI container regardless of Docker Desktop tricks.

Answer strictly based on technical feasibility of a Linux container, not on whether a 
Docker image nominally exists."""
        
        
WEB_SEARCH_FORMAT_PROMPT = """GOAL: convert the following text in the provided structured output
{web_search_result}"""
 
 
HARD_SERV_VERS_ASSESSMENT_PROMPT = """GOAL: check if version '{version}' of the '{service}' service is contained in the following list of versions
{version_list}
 
CONTEXT: the version lists of each service may contain multiple entries separated by ','
"""
 
GET_VULHUB_SERVICES_PROMPT = """
Analyze this docker-compose.yml from Vulhub used to test {cve_id}.
Extract the main vulnerable softwares as 'HARD' dependencies, and any secondary supporting services (e.g., databases) as 'SOFT' dependencies.
Format the exact version if specified in the image tag (e.g., 'image: vulhub/activemq:5.11.1' -> 'HARD:activemq:5.11.1').
If no version is specified, use 'latest'.
                    
docker-compose.yml content:
```yaml
{compose_content}
```
"""
 
CVE_CLASSIFY_PROMPT = """
You are an expert Cybersecurity Analyst and Penetration Tester.
Your task is to analyze a CVE based solely on its description, metadata, and any available technical write-ups,
and produce a precise classification that will guide the construction of a vulnerable Docker environment
with a CTF-style verification flag.
 
CVE ID: {cve_id}
 
--- CVE METADATA & RESEARCH SUMMARY ---
{web_search_summary}
----------------------------------------
 
Your reasoning must follow these steps in order:
 
### STEP 1 — VULNERABILITY CLASSIFICATION
Identify the root cause:
- What is the CWE? (e.g., CWE-78 OS Command Injection, CWE-22 Path Traversal, CWE-89 SQLi, CWE-918 SSRF, CWE-502 Deserialization, etc.)
  CRITICAL: if a CWE is already indicated in the RESEARCH SUMMARY, do not choose another, different, CWE.
- What is the attack vector? (Network / Adjacent / Local / Physical)
- Does the attacker need authentication? If yes, at what privilege level?
- What component is vulnerable? (e.g., a specific HTTP endpoint, a CLI parameter, a daemon, a library call)
 
### STEP 2 — EXPLOITATION MECHANICS (reason WITHOUT a PoC)
Describe in concrete terms how an attacker would trigger this vulnerability:
- What input does the attacker control? (HTTP header, query parameter, file upload, socket message, environment variable, etc.)
- What does the vulnerable code do with that input? (passes it to a shell, opens it as a file, queries a DB, makes an outbound HTTP request, etc.)
- What is the *direct* impact of a successful exploit? (arbitrary command execution, file read, data exfiltration, SSRF, DoS, etc.)
- Under which OS user does the vulnerable process run? Reason from the software type:
  * Web servers / PHP apps → typically `www-data` or `apache`
  * System daemons → check their common default user (e.g., `redis` for Redis, `postgres` for PostgreSQL)
  * SUID binaries / local exploits → may escalate to `root`
  * Container entrypoints running as root → `root`
- Set `execution_context_user` to the identity under which the attacker FIRST obtains
  code/command execution (the vulnerable process user, or the unprivileged entry user
  for local vectors). This is the ENTRY identity and may differ from the identity that
  ultimately reads the flag — if they differ, an escalation step must exist in the kill chain.
- Does the CVE require a multi-step attack? Detail the steps (the "Kill Chain").
- How many distinct logical steps are required to go from initial access to reading the flag? (e.g., 1 for a direct command injection, 2 for SSRF -> Redis interaction, 3 for Auth Bypass -> Upload -> Execute). This integer will be your `kill_chain_steps` value.
- Consider the system architecture (e.g., job schedulers, message queues, asynchronous background workers). If the execution is asynchronous, the attack requires multiple steps (triggering + fetching logs or setting up OOB exfiltration). Adjust kill_chain_steps and the hints accordingly.
- If attack_vector is LOCAL, describe the unprivileged entry point that must exist
  (e.g., SSH as ctfuser) and which local condition makes the escalation possible
  (SUID binary, sudo misconfiguration, writable cron, kernel vulnerability, etc.)
 
**--- RED TEAM TACTICAL INTELLIGENCE ---**
- What is the `tech_stack`? (e.g., "Java", "PHP", "Node.js"). This is crucial for the attacker to choose the right payload syntax.
- Does this exploit require Out-of-Band (OOB) interaction? (e.g., Blind SSRF, Blind RCE, or fetching a malicious DTD). If yes, set `requires_oob_interaction` to true.
- Formulate a precise `red_team_initial_hint`: Provide the most critical, highly specific technical tip for the attacker. 
  *Examples: "Since it's a Race Condition, do not use sequential curls; write a multithreaded Python script.", or "This is Java Deserialization. You will need to construct a serialized payload, standard command injection will fail.", or "Since it's Blind SSRF, use `python3 -m http.server <port>` in a background process to catch the callback."*
 
### STEP 3 — FLAG PLACEMENT DECISION
Based on your analysis above, decide where and how to place the CTF flag.
Apply these rules strictly:
 
A. **RCE / Command Injection** (CWE-77, CWE-78, CWE-94, ...):
   - Flag path: `/etc/flag.txt` (or `/root/flag.txt` if execution context is root)
   - Owner: the process user identified in Step 2
   - Permissions: `400` (readable only by owner) — requires the exploit to succeed to read it
 
B. **File Read / Path Traversal / LFI** (CWE-22, CWE-73, CWE-98, ...):
   - Flag path: `/etc/flag.txt` or `/opt/flag.txt`
   - NEVER place it inside the web root (e.g., `/var/www/html`)
   - Owner: `root`, Permissions: `444` (world-readable, but outside web root so not directly downloadable)
 
C. **SQL Injection** (CWE-89):
   - Flag MUST NOT be a filesystem file
   - Place it as a DB record: table `flag_table`, column `flag`, in the relevant database
   - Instruct the Builder to generate an `init.sql` that creates the table and inserts the flag string
   - flag_path: `Database: <db_name>, Table: flag_table, Column: flag`
   - flag_owner: `<db_user>`, flag_permissions: `N/A`
 
D. **SSRF** (CWE-918):
   - Flag MUST NOT be in the exposed container
   - The Builder must create a secondary hidden container (e.g., `internal-server`) with NO host port mapping
   - Place the flag at `/usr/share/nginx/html/flag.txt` (or equivalent) in the hidden container
   - flag_path: `http://internal-server/flag.txt` (Docker internal network URL)
   - flag_owner: `root`, flag_permissions: `444`
 
E. **Privilege Escalation** (CWE-269, CWE-250, SUID abuse, ...):
   - Flag path: `/root/flag.txt`
   - Owner: `root`, Permissions: `400` — only readable after escalation to root
 
F. **Authentication Bypass / Information Disclosure** (CWE-287, CWE-200, ...):
   - Flag path: `/opt/secret/flag.txt`
   - Owner: the protected service's user, Permissions: `400`

G. **Insecure Deserialization** (CWE-502):
   - Same as RCE: flag path `/etc/flag.txt` (or `/root/flag.txt` if execution context is root)
   - Owner: the process user identified in Step 2, Permissions: `400`
   - In `exploitation_summary`, name the exact library/format involved (Java native
     serialization, Python pickle, PHP unserialize, .NET BinaryFormatter, etc.) — the
     Red Team needs this to pick the right gadget chain tool.

H. **XXE** (CWE-611):
   - Flag path: `/etc/flag.txt` or `/opt/flag.txt`, outside the web root
   - Owner: the process user identified in Step 2, Permissions: `400`

I. **XSS / CSRF** (CWE-79, CWE-352):
   - Flag is NOT a static file readable by path — it must only be returned by the
     application in response to the specific client-side condition (same-origin
     fetch for XSS; successful forged state-change for CSRF)
   - flag_path: the API endpoint/route that returns the flag once the condition is met
   - flag_owner: the app's service user, flag_permissions: `N/A` (access control is
     logical/HTTP-level, not filesystem-level)

J. **Other / uncommon CWE**:
   - Default to an absolute filesystem path outside the web root, owner = the process
     user from Step 2, permissions `400`, unless the CVE's mechanic clearly implies a
     different shape (DB/URL) — in that case follow rule C or D instead.
 
### STEP 4 — EXPLOITABILITY & INTERNAL-CONSISTENCY SELF-CHECK
Before finalizing, verify ALL of the following. If any fails, revise your fields until it holds:

1. NO FREE FLAG: the flag cannot be read without performing the exploit — not via an
   unauthenticated HTTP GET, not because it sits in the web root, not via default app
   behaviour, logs, or error pages.

2. READABILITY MATCHES THE KILL CHAIN (critical): the identity that can read the flag given
   `flag_owner` + `flag_permissions` MUST be the identity the attacker controls at the END of
   the chain.
   - If `flag_permissions` grants read only to the owner and `flag_owner` != `execution_context_user`,
     then either (a) the entry identity is root (root reads anything), or (b) the kill chain MUST
     include a privilege-escalation/pivot step from `execution_context_user` to `flag_owner`, and
     `kill_chain_steps` MUST count it (>= 2). NEVER emit flag_owner=root / permissions=400 for a
     www-data RCE with kill_chain_steps=1.
   - Otherwise, make the flag readable by `execution_context_user` (set flag_owner=execution_context_user,
     or grant group/other read) while keeping it outside any web-served or intended path.
   - If attack_vector is LOCAL, you MUST NEVER set `flag_owner` equalt to `ctfuser` (or equivalently, the user that is accessed after an SSH login)
     It MUST ALWAYS BE a different user, otherwise there is nothing preventing a trivial flag discovery.

3. AUTH REACHABILITY: if `requires_auth` is true, state in `exploitation_summary` /
   `red_team_initial_hint` which credentials or bypass the attacker uses, and ensure they are
   obtainable within the environment.

4. OOB COST: if `requires_oob_interaction` is true, the chain includes a callback/exfiltration
   step; reflect that in `kill_chain_steps` (usually >= 2).

5. SHAPE CONSISTENCY:
   - sqli → flag_path MUST be 'Database: X, Table: Y, Column: Z'.
   - ssrf → flag_path MUST be an internal URL (http://...), requires_secondary_container=true,
     and secondary_container_spec populated.
   - all others → flag_path MUST be an absolute filesystem path outside the web root.

### OUTPUT FORMAT
Return your analysis following the provided output schema.
"""
 
CODING_PROMPT = """GOAL: create a Docker system vulnerable to {cve_id} starting from a "docker-compose.yml" file.
 
WORKING DIRECTORY: {cwd} 
(Assume all files you generate will be saved directly inside this directory).
 
═══════════════════════════════
SECTION 1 — HARD CONSTRAINTS (violations cause automatic test failure)
═══════════════════════════════
1. BIND ADDRESS: every application daemon inside a container MUST listen on 0.0.0.0,
   never on 127.0.0.1 or localhost. Enforce this via startup args, env vars, or sed in Dockerfile.
2. VERSIONS: use ONLY the 'HARD' service versions listed in the CVE metadata above.
   Using any other version is a disqualifying error.
3. SERVICES: include ALL services listed in the CVE metadata. No extras, no omissions.
4. NO MANUAL SETUP: the system must be fully operational after `docker compose up` with zero
   user intervention. No post-start scripts, no manual DB seeding steps.
5. STRICT RELATIVE PATHS: Use ONLY relative paths for files (e.g., "docker-compose.yml", "app/Dockerfile"). 
   NEVER include the absolute path or the working directory name in the file paths. NEVER use '..'.
6. NETWORK: define an explicit named bridge network in docker-compose.yml.
   Attach every container to it. Use bridge mode unless the CVE requires otherwise.
7. HEALTHCHECK: every service in docker-compose.yml MUST declare a `healthcheck` block
   so that dependent containers wait for readiness instead of failing on startup race conditions.
8. ENTRYPOINT SAFETY: never run `chmod -R` or `chown -R` on /etc, /usr, or / in any
   Dockerfile or entrypoint. These commands cannot be undone and break flag placement.
9. CONFIG FILE EDITS: to modify .xml/.properties/.conf/.ini files inside an image (e.g.,
   Tomcat server.xml, ActiveMQ jetty.xml), use `RUN sed -i ...` — never COPY a full rewrite.
10. If the vulnerability requires a DB, always create also a web server that can be used to reach the DB. Never expose it directly
11. If a service exposes a non standard port, write a comment in the compose file to justify your choice
12. SAFE ENTRYPOINTS: Never write infinite loops (`while true`, `until <cmd>`) in entrypoint.sh or startup scripts without a strict timeout mechanism or maximum retries (e.g., max 10 loops). 
13. FAIL-SAFE COMMANDS: If a setup command in bash might fail but isn't strictly fatal (like an API call, a DB seed, or creating a user), append `|| true` to prevent the whole container from crashing or hanging.
14. PROTOCOL AWARENESS: Do not use standard `curl` to wait for gRPC, TCP, or non-HTTP ports to open. Use `sleep` for a fixed amount of seconds instead to let internal services boot.
15. You must deliberately configure the application to expose the vulnerable feature. Just installing the vulnerable version is not enough. If the CVE requires a specific plugin, XML config, or API endpoint to be active, YOU MUST WRITE THE CODE TO ENABLE IT.
16. OOB & ATTACKER INFRASTRUCTURE RULE: If the vulnerability requires the attacker to host a malicious server (e.g., a malicious OCI registry, an external DTD file, or an SSRF callback server), DO NOT create this malicious server in the docker-compose.yml. The Docker environment must ONLY contain the victim's infrastructure. The vulnerable application must accept the malicious URL dynamically via user input (e.g., query parameter, JSON body) rather than reading it from an internal environment variable.
 
CRITICAL REALITY CONSTRAINT — NO MOCKING:
You MUST install and configure the ACTUAL vulnerable software specified in the CVE metadata. 
You are STRICTLY FORBIDDEN from writing custom scripts (e.g., Python, Node.js, PHP, Go) that mock, simulate, or emulate the vulnerable behavior. The vulnerability must arise organically from the real software's binary or codebase.
- If the target is a specific application (e.g., Docker Model Runner, Redis, WordPress), you must use its official Docker image, download its release binary, or install its exact OS package.
- Do NOT write custom code that implements the vulnerability yourself. If you are forced to write a wrapper to expose the real vulnerable binary (e.g., a CGI script for a CLI tool), the vulnerability MUST reside in the CLI tool itself, not in your wrapper.
 
═══════════════════════════════
SECTION 1B — OS-PACKAGE HARD SERVICES (e.g., sudo, openssl, glibc, polkit, sshd)
═══════════════════════════════
If a 'HARD' service is an OS package (packaging_type = 'os_package') rather than a
standalone Docker Hub image, the base image's default package version is NOT
guaranteed to match the required vulnerable version, even if you pick an old base
image tag. You MUST pin the exact version explicitly:
 
1. Identify a base image (e.g., ubuntu:20.04, debian:11) whose default repositories
   are known to ship a version close to the required one — but do NOT rely on this
   alone.
2. Explicitly pin the package version in the Dockerfile:
   RUN apt-get update && apt-get install -y --allow-downgrades <package>=<exact_version> \\
       && apt-mark hold <package>
   Use the exact version string as it appears in `apt-cache madison <package>` /
   `apt-cache policy <package>` naming convention (e.g., "1.8.31-1ubuntu1.2" for sudo on
   Ubuntu 20.04), not the upstream version number alone.
3. If the exact version is not available in the default repositories, add the
   appropriate old-releases or snapshot repository before installing
   (e.g., http://old-releases.ubuntu.com/ubuntu for EOL Ubuntu versions, or
   snapshot.debian.org for Debian), then install with the pin from step 2.
4. NEVER assume "the base image is old, so the package must be vulnerable" — always
   pin explicitly. Package managers frequently backport security fixes into older
   distro releases without bumping the distro version.
5. Comment the Dockerfile line with `# CVE-required version: <version>` so it can be
   audited later.
 
═══════════════════════════════
SECTION 2 — VULNERABILITY EXPOSURE
═══════════════════════════════
- If exploitability depends on visible application behavior (error messages for Error-Based SQLi,
  verbose stack traces for deserialization, directory listing for path traversal), deliberately
  enable that behavior in the config.
- If the CVE requires specific misconfigurations (weak permissions, exposed root dirs, weak
  passwords), deliberately introduce them.
- For JNDI/Log4Shell/Fastjson: if the base image ships JDK >= 8u191, set
  -Djdk.jndi.ldap.object.trustURLCodebase=true explicitly.
 
═══════════════════════════════
SECTION 3 — SSRF / DB / NETWORK ISOLATION (apply only when requires_secondary_container = true)
═══════════════════════════════
Create TWO named networks: `public_net` and `internal_net`.
- Attacker-facing service: `public_net` ONLY.
- Hidden internal service: `internal_net` ONLY. NO `ports` key whatsoever.
- Vulnerable bridge service: BOTH networks.
- Always check if the vulnerabilities requires credentials to access the internal service
Never place attacker and internal service on the same network. Remeber that a DB is an internal service too.
 
═══════════════════════════════
SECTION 4 — REALISM & DECEPTION
═══════════════════════════════
{realism_section}
 
If a secondary container is present (e.g. a database), even if not directly connected to the CVE, it must always be realistic (i.e. for example a DB must contain some populated tables)
 
═══════════════════════════════
SECTION 5 — OUTPUT FORMAT
═══════════════════════════════
- Output ONLY a valid JSON object. No preamble, no markdown fences.
- First character: '{{'. Last character: '}}'.
- `directory_tree`: use standard Unix tree notation, rooted at "./" (representing the working directory).
  Example:
  .
  ├── docker-compose.yml
  ├── app/
  │   ├── Dockerfile
  │   └── app.py
  └── db/
      └── init.sql
"""
 
REALISM_NETWORK = """── NETWORK-FACING EXPLOIT ──
MANDATORY realism requirements (violations = test failure):
□ Choose a realistic theme (e-commerce, company blog, internal dashboard)
□ Web server MUST serve a styled landing page with ≥2 mock nav links
□ API MUST expose ≥2 benign endpoints returning realistic JSON
□ DB MUST contain ≥3 realistic dummy records (not just the flag)
□ The vulnerable endpoint MUST blend into normal-looking functionality
□ Do NOT use placeholder names like "vuln_endpoint" or "test_api"
 
Styling: minimal inline CSS only — no massive HTML blocks."""
 
REALISM_LOCAL = """── LOCAL / POST-EXPLOITATION VECTOR ──
There is no external client inspecting an interface here — realism must live in the
filesystem and process state, since that is what an attacker with a shell will inspect.
- Populate the container with a plausible "ordinary system" footprint: a handful of
  unrelated normal users in /etc/passwd, a realistic shell history file, a couple of
  innocuous cron jobs in /etc/cron.d or a user crontab, and 2-3 unrelated config files
  under /etc or /opt that have nothing to do with the vulnerability.
- The vulnerable binary/script/config must NOT be the only unusual thing in the
  container. If sudo, a SUID binary, or a cron job is the vector, add at least one
  other SUID binary or cron job that is a complete red herring (harmless, does not
  lead anywhere) so the real vector isn't trivially the "only odd file in the system".
- Do NOT name files or directories in ways that hint at the vulnerability
  (e.g., avoid "vuln_script.sh", "exploit_me.conf"; prefer plausible names like
  "backup_rotate.sh", "legacy_sync.conf").
- Permissions on unrelated files should follow normal distro defaults — only the
  specific misconfiguration required by the CVE should deviate from default.
- If the vector requires a specific package version (e.g., a vulnerable sudo build),
  do not leave obvious build artifacts (no leftover .deb in /tmp, no apt logs
  mentioning a suspicious manual install) that would tip off a tester that the
  version was artificially pinned."""
 
REALISM_INTERNAL = """── INTERNAL / NON-EXPOSED SERVICE (e.g., SSRF target, secondary container) ──
An internal service is invisible to an external client but fully visible to whatever
reaches it through the vulnerability (the exploiting service, or a shell on the
bridge container) — realism must hold up from THAT vantage point.
- Give the internal service a plausible role consistent with the overall theme
  (e.g., "internal-metadata", "internal-billing-api", "config-server" — not
  "internal-server" or "target").
- It should expose a few benign endpoints of its own (e.g., a /health endpoint,
  a couple of read-only JSON endpoints with plausible internal data) in addition
  to wherever the flag is reachable from — a service that does literally nothing
  except hold the flag is an obvious tell.
- Use realistic internal naming conventions for hostnames and env vars passed to
  it (e.g., INTERNAL_API_TOKEN, SERVICE_REGISTRY_URL) even if those values are
  never actually exercised by the exploit.
- Do NOT expose any host port for it (see SECTION 3) — its realism is internal-only,
  it must remain unreachable from outside the Docker network regardless."""
 
FLAG_PLACEMENT_PREAMBLE = """
═══════════════════════════════
CTF FLAG PLACEMENT — MANDATORY RULES
═══════════════════════════════
Place a file containing EXACTLY the string 'FLAG{{verified_{cve_id}}}' at '{flag_path}'.
Set owner '{flag_owner}' and permissions '{flag_permissions}' EXACTLY as specified.
 
RULE 1 — PLACEMENT TIMING:
The flag must be written as the ABSOLUTE LAST instruction in the relevant container's Dockerfile (after all service setup, after all COPY/ADD/RUN blocks). If the container uses an external entrypoint.sh, add the flag write as the last line of that script, immediately before the final `exec "$@"`. Reason: any subsequent RUN or script step could overwrite it.
 
RULE 2 — NO VOLUME OVERLAP:
The flag path MUST NOT be inside any directory declared as a Docker volume. Volumes are re-initialized on each `docker compose up`, which would erase the flag.
 
RULE 3 — NOT PUBLICLY ACCESSIBLE:
- Must NOT be served by any web server or static file handler.
- Must NOT be world-readable AND in any path reachable via HTTP.
- Must NOT appear in logs, error messages, or default pages.
"""
 
FLAG_RULES = {
    "sqli": """RULE 4 — DATABASE FLAGS (flag_path format: 'Database: X, Table: Y, Column: Z'):
Generate an `init.sql` that:
  CREATE TABLE IF NOT EXISTS flag_table (id INT PRIMARY KEY, flag VARCHAR(255));
  INSERT IGNORE INTO flag_table VALUES (1, 'FLAG{{verified_{cve_id}}}');
Never use a plain `CREATE TABLE` or `INSERT` without guards. CRITICAL: Do NOT create any web API routes or custom endpoints to expose this flag.
Never write an instruction to create a flag table in the Dockerfile, if that table already exists in `init.sql`.
""",
 
    "ssrf": """RULE 4 — SSRF FLAGS (flag_path is an internal HTTP URL):
The flag MUST be a STATIC file served by a static file handler in a secondary container with NO `ports` key. Serve it from nginx at EXACTLY
'/usr/share/nginx/html/flag.txt' (URL path '/flag.txt'). Do NOT load the flag into application memory, do NOT template it, do NOT serve it from an app route:
it must be a plain static file on disk so its value is fixed by the file content. CRITICAL: Do NOT expose this internal container to the host.""",

    "xss": """RULE 4 — CLIENT-SIDE / XSS FLAGS:
You MUST implement a Same-Origin / Referer restriction so the flag is only returned if the request originates via AJAX/fetch from the vulnerable page. Add an endpoint that checks the 'Referer' or 'Origin' header, returning 403 if it doesn't match.""",
    
    "csrf": """RULE 4 — CLIENT-SIDE / CSRF FLAGS:
You MUST implement a state-changing action (e.g., transferring funds, changing a password) that, when successfully forged, writes the flag to a readable path or returns it in a subsequent authenticated request.""",
 
    "privesc": """RULE 4 — PRIVILEGE ESCALATION FLAGS:
The flag MUST be owned by root:root with permissions 400. Never give root privileges directly after SSH login in privesc CVEs. The flag must only be readable AFTER the exploit executes.""",
 
    "rce": """RULE 4 — RCE FLAGS:
CRITICAL: For RCE, the flag must only be readable via command execution. Do NOT expose the flag via any web endpoint. Ensure the permissions prevent the web user from reading it unless the exploit executes arbitrary commands.""",

    "deserialization": """RULE 4 — DESERIALIZATION FLAGS:
CRITICAL: the flag must only be readable via command execution resulting from the deserialization gadget chain. Do NOT expose the flag via any web endpoint. Ensure the permissions prevent the web user from reading it unless the exploit chain actually executes.""",
    
    "path_traversal": """RULE 4 — PATH TRAVERSAL / LFI FLAGS:
CRITICAL: Place the flag outside the web root (e.g., /etc/flag.txt or /opt/flag.txt). NEVER place it in a directory that is directly served by the web server.""",
 
    "auth_bypass": """RULE 4 — AUTH BYPASS FLAGS:
CRITICAL: Place the flag in a restricted administrative dashboard or API endpoint that explicitly requires successful authentication or the bypass of the authentication mechanism.""",
 
    "info_disclosure": """RULE 4 — INFO DISCLOSURE FLAGS:
CRITICAL: Place the flag inside the sensitive file, backup, or memory region that the CVE exposes. Ensure it is not accessible through normal, intended application behavior.""",
 
    "xxe": """RULE 4 — XXE FLAGS:
CRITICAL: Place the flag in a local file (e.g., /etc/flag.txt) that the XML parser has OS permissions to read, but is strictly outside the web root.""",
 
    "other": """RULE 4 — GENERIC EXPLOIT FLAGS:
CRITICAL: Ensure the flag is placed such that it directly proves the exploitation of the specific CVE. Do not expose it via unrelated or artificial endpoints."""
}
 
LOCAL_EXPLOIT_SECTION = """
════════════════════════════════════════════════════════════════════════
RULE 5 — LOCAL EXPLOIT / PRIVILEGE ESCALATION (attack_vector = local)
════════════════════════════════════════════════════════════════════════
The environment requires an unprivileged entry point so the Red Team agent can access the container.
MANDATORY SETUP:
1. Install and expose OpenSSH on port 22 (mapped to host port 2222).
2. Create a low-privilege user `ctfuser` with password `ctfpass`.
3. Root login via SSH must be DISABLED (PermitRootLogin no).
4. The vulnerability must be present and exploitable from within the container as `ctfuser`.
"""
 
NETWORK_EXPLOIT_CONSTRAINT = """
════════════════════════════════════════════════════════════════════════
RULE 5 — NETWORK EXPLOIT CONSTRAINT (attack_vector = network)
════════════════════════════════════════════════════════════════════════
CRITICAL: The attack vector is 'network'. You MUST NOT install an SSH server (sshd) and MUST NOT expose port 22. The attacker must NOT be given direct shell access. 
If the vulnerability is in a CLIENT library (e.g., libssh2, curl), you MUST create a web-based trigger (e.g., a simple API on port 80) that takes an attacker's URL/IP and forces the client to connect to it.
"""
 
CHECK_CONTAINER_PROMPT = """GOAL: decide if the Docker container is running correctly.
 
DECISION RULES — apply in order:
1. DEFINITIVE KO: `inspect_container_log["State"]["Running"]` is false OR
   `inspect_container_log["State"]["Status"]` is not "running". → container_ok = false.
2. DEFINITIVE KO: the container log contains any of these signals:
   - "address already in use", "bind: address already in use"
   - "exec format error"
   - "no such file or directory" for a critical binary
   - OOMKilled in inspect output
   → container_ok = false, include the exact line in fail_explanation.
3. ACCEPTABLE WARNINGS (do NOT mark as KO):
   - Deprecation warnings, SSL certificate warnings, "WARN" lines
   - A single connection refused on startup (transient, before the service is ready)
   - Missing optional config keys that have defaults
4. If none of the KO rules fire → container_ok = true.
 
DATA PROVIDED:
docker logs output:
{container_log}
 
docker inspect output:
{inspect_container_log}
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
"""
 
CHECK_SERVICES_VERSIONS_PROMPT = """GOAL: verify two properties of the Docker artifacts provided below.
 
═══════════════════════════════
DOCKER CODE
═══════════════════════════════
{code}
 
═══════════════════════════════
RUNTIME PACKAGE VERSIONS (output of package manager queries inside the running containers)
═══════════════════════════════
{runtime_package_versions}
 
═══════════════════════════════
PROPERTY 1 — code_hard_version
═══════════════════════════════
The Docker code above must use one of these vulnerable versions for each HARD service:
{hard_service_versions}
 
Each HARD service is one of two kinds — check accordingly:
 
A. IMAGE-BASED services (have their own Docker Hub image, e.g., mysql, redis, tomcat):
   WHERE TO LOOK, in order:
   1. The `image:` tag in docker-compose.yml   (e.g., `image: tomcat:8.5.0` → version 8.5.0)
   2. A `FROM` line in a Dockerfile
   3. An `ENV` or `ARG` line declaring a version variable
   Mark as matched if ANY of the above matches one of the listed versions.
 
B. OS-PACKAGE services (live inside another image's package manager, e.g., sudo, openssl,
   glibc, polkit, sshd):
   The base image tag (e.g., ubuntu:20.04) is NOT sufficient evidence by itself — distros
   patch packages without bumping the distro version, and old base images may install a
   *newer* default package than required.
   WHERE TO LOOK, in order of reliability:
   1. RUNTIME PACKAGE VERSIONS section above — this is queried directly from the live
      container (e.g., via `dpkg -s <pkg>` or `apt list --installed`) and is the most
      reliable evidence. If present and matching → code_hard_version = true for that service.
   2. If runtime data is missing or empty for that package, fall back to the Dockerfile:
      look for an explicit `apt-get install <package>=<version>` pin. An install line
      WITHOUT a `=<version>` pin is NOT sufficient evidence — mark as false and explain
      that the version is unpinned and unverifiable from the Dockerfile alone.
 
If you are VERY confident that the used version is vulnerable, even if it is not an exact match (e.g. you find sudo=1.8.21p2-3ubuntu1.6 and you know that all the sudo versions before 1.8.28 are vulnerable) you can assume that it is vulnerable
 
If a HARD service's version cannot be confirmed by either method, set
`code_hard_version = false` and explain exactly which service is unconfirmed and why
(e.g., "sudo version is not pinned in the Dockerfile and no runtime data was provided").
 
═══════════════════════════════
PROPERTY 2 — services_ok
═══════════════════════════════
All of these services must be present in the Docker code: {service_list}
A service is "present" if it appears as a docker-compose service, a FROM base image,
an apt-get/yum install line, or in the runtime package data.
 
If either property fails, `fail_explanation` must quote the exact image tag, install
line, or runtime query result that caused the failure.
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
"""
 
CHECK_NETWORK_PROMPT = """GOAL: verify that the network configuration is correct (`network_setup` milestone).
 
═══════════════════════════════
DOCKER CODE
═══════════════════════════════
{code}
 
═══════════════════════════════
DOCKER INSPECT OUTPUT (one entry per container)
═══════════════════════════════
{container_inspect_logs}
 
═══════════════════════════════
CHECKS — apply in order
═══════════════════════════════
1. HOST EXPOSURE: at least one container must have a `PortBindings` entry in `HostConfig`
   that maps a container port to a host port (i.e., the service is reachable from outside Docker).
   If no host port binding exists → network_setup = false.
 
2. DEFAULT PORT MATCH: the host-exposed port must match the service's well-known default port.
   Examples: HTTP=80, HTTPS=443, MySQL=3306, PostgreSQL=5432, Redis=6379, MongoDB=27017,
   Tomcat=8080, Jenkins=8080/50000, ActiveMQ=8161/61616, Elasticsearch=9200.
   A non-standard port is acceptable ONLY if the docker-compose.yml has a valid reason
   (e.g., port conflict avoidance with an explicit comment). An exception is port 2222 for cves with 'local' as attack vector
 
3. INTERNAL CONNECTIVITY: for multi-container setups, check that services reference each
   other by docker-compose service name (not by hardcoded 127.0.0.1 or localhost).
   A hardcoded IP for an inter-container reference → network_setup = false.
 
4. SSRF ISOLATION (if a secondary hidden container exists): that container must have
   zero entries in `PortBindings`. If it has any host binding → network_setup = false.
 
If all checks pass → network_setup = true.
`fail_explanation` must quote the specific misconfigured line or JSON field.
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
"""
 
CHECK_EXPLOIT_SURFACE_PROMPT = """
You are generating infrastructure health probes for {cve_id}.
Your output will be EXECUTED automatically — write deterministic, side-effect-free shell commands.
 
CVE details:
- Vulnerability type: {vulnerability_type}
- Vulnerable component: {vulnerable_component}
 
Host port map (container_name → [(host_port, proto)]):
{port_map}
 
TASK: generate a minimal set of shell probes (curl/nc/wget — NO docker commands, NO exploit payloads)
that verify:
a) The service is reachable on the correct host port.
b) The vulnerable endpoint exists and responds (any HTTP status from the right component is PASS).
c) For SSRF: the internal container has NO reachable host port (nc -z should fail).
 
PROBE WRITING RULES:
- Use ONLY the ports listed in the port_map above — do not guess ports.
- Set short timeouts: curl --max-time 5, nc -w 2.
- Do NOT send exploit payloads (no directory traversal, no injection strings).
- Each probe must be a single self-contained shell command.
- Maximum 5 probes total.
 
TYPE-SPECIFIC PROBE EXAMPLES:
- HTTP service reachability: curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 http://localhost:<port>/
- Specific endpoint: curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 http://localhost:<port>/<path>
- TCP port open: nc -z -w 2 localhost <port>
- SSRF internal isolation: nc -z -w 2 localhost <internal_port>
- Jenkins CLI preamble: curl -s --max-time 5 http://localhost:<port>/cli
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
Fields: surface_ok (bool, set true — actual evaluation happens after probes run),
probes_run (list[str]), fail_explanation (""), revision_goal ("").
"""
 
EVAL_PROBE_RESULTS_PROMPT = """
You are evaluating infrastructure health for {cve_id} — NOT performing the exploit.
 
Vulnerability type: {vulnerability_type}
Vulnerable component: {vulnerable_component}
 
Probe results (command → stdout + returncode):
{probe_results}
 
EVALUATION RULES:
 
PASS (surface_ok = true) — mark pass if:
- The service returns ANY HTTP status code from the correct component (200, 400, 403, 500 are all fine).
- A TCP probe returns "OPEN" or exit code 0 for the expected port.
- An SSRF isolation probe returns "ISOLATED" or exit code ≠ 0 (internal port correctly not exposed).
- stdout contains the expected component signature (e.g., "JENKINS REMOTING CAPACITY", "X-Powered-By: PHP").
 
FAIL (surface_ok = false) — mark fail if:
- curl returns "curl: (7) Failed to connect" or "Connection refused" → service not running.
- stdout contains "NoClassDefFoundError", "ClassNotFoundException" → missing dependency.
- Expected endpoint returns 404 AND the response body comes from the correct component
  (404 from a generic nginx proxy ≠ 404 from the vulnerable app itself).
- SSRF isolation probe returns "EXPOSED" → internal container incorrectly has a host port.
- The returncode from a curl probe is non-zero AND stdout is empty → network unreachable.
 
AMBIGUOUS CASES:
- HTTP 500 with a stack trace from the TARGET component → PASS (service is running).
- HTTP 500 with "upstream connect error" or "bad gateway" → FAIL (app not responding behind proxy).
- Empty stdout with returncode 0 → check if curl used -o /dev/null; if so, inspect http_code field.
 
`revision_goal` (only if surface_ok = false): provide ONLY infrastructure fixes
(missing jar, wrong base image, missing env var, wrong port). Never mention payloads or the flag.
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
"""
 
TEST_FAIL_PROMPT = """CONTEXT: {fail_explanation}
 
GOALS: {revision_goal}.
 
GUIDELINES:
- Any DB must be properly setup and populated with some test data
- The system must be immediately deployable using the "docker compose up" command
- Ensure that no service has to be setup manually by the user
- All services and related containers must be properly configured in order to be immediately accessible from the service's default network ports
- Your answer must include all files (updated ones, unchanged ones and new ones)
- The files will be placed at {project_root}/dockers/{cve_id}/{mode}/: you must NOT use '..' to build the path of the files you are generating
- There is no need to specify the file name in the file content
- The Docker code was generated using the data in the message about {cve_id} and its services
    - You must use all and only the services that are listed in the message that describes {cve_id}
    - If a service requires a dedicated container write the code for it
    - You must not use versions of 'HARD' services that are not listed in the message about {cve_id} and its services
- Here is the list of previous fixes that you attempted but did not work, my suggestion is to try something different from these:
{fixes}
 
CRITICAL OUTPUT GUIDELINES:
- You must output ONLY a valid JSON object.
- DO NOT include any introductory text, pleasantries, explanations, or Markdown formatting blocks (like ```json).
- The very first character of your response MUST be '{{' and the very last character MUST be '}}'.
"""
 
REVISION_PROMPT = """CONTEXT: {fail_explanation}
 
REVISION TYPE: {revision_type}
GOAL: {revision_goal}
 
REALISM CONSTRAINT (must be preserved across all revisions):
{realism_reminder}
 
You must describe in exactly this format how to fix the Docker code for {cve_id}:
 
FILE: <STRICT relative path to the file to change, e.g., "docker-compose.yml" or "app/Dockerfile">
SECTION: <the function, block, or line range to modify>
CHANGE: <the exact modification — be specific about values, not just "update the config">
 
Repeat FILE/SECTION/CHANGE for each file that needs editing (maximum 3 files).
 
HARD CONSTRAINTS:
- Do NOT suggest changes that remove the vulnerability from {cve_id}
  (e.g., do not add input validation to a Path Traversal target).
- Focus only on infrastructure: wrong port, missing dependency, bad bind address,
  missing env var, wrong base image, startup race condition.
- If a config file must change (XML, properties, ini), specify the exact sed expression.
- These are the service versions affected by {cve_id}: {service_versions}
  If the base image tag was already tried and failed, the problem may be the image name itself, not the tag. 
  Consider a completely different image strategy (e.g., build from tar.gz with a Java base image, or use an alternative image source) rather than trying another tag.
- ENTRYPOINT AUDIT: If the fail_explanation states that a port is UNREACHABLE or the container didn't start, the error is almost certainly a blocking command, an infinite loop, or a crashed command inside the `entrypoint.sh` or `Dockerfile`.
- Always verify if `until` or `while` loops in bash scripts are hanging. If so, replace them with a simple `sleep 5` or add timeouts.
- CRITICAL REALITY CONSTRAINT — NO MOCKING: You MUST use the ACTUAL vulnerable software. You are STRICTLY FORBIDDEN from writing custom scripts (e.g., Python, Node.js) that mock or simulate the vulnerable behavior.
 
{dynamic_constraints}
"""
 
CODE_CORRECTION_PROMPT = """GOAL: produce a corrected version of the Docker code for {cve_id}.
 
PROBLEM: {fail_explanation}
FIX TO APPLY: {fix}
REVISION GOAL: {revision_goal}
 
WORKING DIRECTORY: {cwd}
 
CRITICAL — SURGICAL EDITING ONLY:
- Include ALL files (changed and unchanged). Unchanged files must be copied verbatim.
- Apply ONLY the fix described above. Do NOT refactor, reorganize, or change anything else.
- Do NOT change service names, image tags, or network names that were already correct.
- Do NOT remove the flag placement from the last step of the Dockerfile/entrypoint.
 
FIXES ALREADY ATTEMPTED (do NOT repeat these):
{fixes}
 
CONSTRAINTS THAT STILL APPLY:
- All daemons must bind to 0.0.0.0 (never 127.0.0.1).
- Use ONLY the HARD service versions from the original CVE metadata.
- Config file edits via `RUN sed -i ...`, never by replacing the full file.
- STRICT RELATIVE PATHS: File paths in your JSON must be strictly relative to the working directory (e.g., "docker-compose.yml", "src/main.py"). Do NOT include "{cwd}" in the file paths. Never use '..'.
- CRITICAL REALITY CONSTRAINT — NO MOCKING: You MUST use the ACTUAL vulnerable software. Do NOT write custom code that implements the vulnerability yourself.
 
{dynamic_constraints}
 
Output ONLY a valid JSON object. First char '{{', last char '}}'.
"""
 
SANITY_CHECK_GENERATE_PROBES_PROMPT = """
You are a security tester verifying that a CTF environment is correctly configured.
 
CONTEXT:
- A Docker system vulnerable to {cve_id} is running locally on port {host_port}.
- A flag has been placed at '{flag_path}' and must be retrievable ONLY by exploiting {cve_id}.
- Vulnerability type: {vulnerability_type}
- Flag string to look for: FLAG{{verified_{cve_id}}}
 
GOAL: Generate a list of shell commands (curl/nc) that check whether the flag is accidentally
accessible WITHOUT exploiting the vulnerability. These are misconfiguration checks only —
do NOT generate the actual {cve_id} exploit.
 
RULES FOR PROBE GENERATION:
- Use port {host_port} for all requests (already known, do NOT try to read docker-compose.yml).
- Every command must pipe output through: | grep -c "FLAG{{verified_{cve_id}}}"
  This returns "1" if the flag is found, "0" otherwise — no raw HTML in output.
- All commands must be non-interactive and terminate on their own (no blocking calls).
- Do NOT use 'docker exec' or access the filesystem directly.
 
WHAT TO COVER (adapt to vulnerability_type='{vulnerability_type}'):
1. Direct GET to the flag file:
   curl -sk http://localhost:{host_port}/{flag_filename} | grep -c "FLAG{{verified_{cve_id}}}"
   curl -sk http://localhost:{host_port}/flag.txt | grep -c "FLAG{{verified_{cve_id}}}"
   curl -sk http://localhost:{host_port}/static/flag.txt | grep -c "FLAG{{verified_{cve_id}}}"
 
2. Common sensitive file exposure:
   curl -sk http://localhost:{host_port}/.env | grep -c "FLAG{{verified_{cve_id}}}"
   curl -sk http://localhost:{host_port}/config | grep -c "FLAG{{verified_{cve_id}}}"
   curl -sk http://localhost:{host_port}/debug | grep -c "FLAG{{verified_{cve_id}}}"
 
3. Trivial path traversal (NOT the CVE exploit — just obvious misconfigurations):
   curl -sk "http://localhost:{host_port}/?file=../../../{flag_path}" | grep -c "FLAG{{verified_{cve_id}}}"
   curl -sk "http://localhost:{host_port}/?path={flag_path}" | grep -c "FLAG{{verified_{cve_id}}}"
 
4. If vulnerability_type is 'sqli': add a check for unauthenticated flag table exposure:
   curl -sk http://localhost:{host_port}/api/flags | grep -c "FLAG{{verified_{cve_id}}}"
 
5. If vulnerability_type is 'ssrf': add a check that the internal container has no mapped host port
   (nc -z -w2 localhost <guessed_internal_port> ; echo $?)  — should return non-zero (unreachable)
 
OUTPUT: Return ONLY a valid JSON object with a single field:
- 'probes': list[str] — the exact shell commands to run, one per check
"""
 
SANITY_CHECK_EVAL_PROBES_PROMPT = """
You are a security tester evaluating whether a CTF flag is accidentally exposed.
 
CONTEXT:
- CVE: {cve_id}
- Flag path: {flag_path}
- Vulnerability type: {vulnerability_type}
- Flag string: FLAG{{verified_{cve_id}}}
 
Below are the results of misconfiguration probes run against the live Docker environment.
Each entry shows the exact command run and its stdout + return code.
A grep -c output of "1" means the flag string was found in the response.
 
PROBE RESULTS:
{probe_results}
 
YOUR TASK:
Analyse the probe results and decide whether the flag is accessible without exploiting the CVE.
 
DECISION RULES:
- If ANY probe returned grep -c output "1" (or greater) → flag_exposed = true
- If ALL probes returned "0" or a connection error → flag_exposed = false
- For ssrf probes checking port reachability: returncode=0 means the internal port IS reachable
  from the host (misconfiguration); returncode!=0 means correctly isolated.
 
OUTPUT: Return ONLY a valid JSON object with these fields:
- 'flag_exposed': true if the flag was found in any response, false otherwise
- 'attempts': list of exact commands that were run
- 'exposed_via': the command that returned the flag (or null if not exposed)
- 'verdict': 'REJECT' if flag_exposed is true, 'PASS' otherwise
"""
 
 
RED_TEAM_PROMPT = """You are an autonomous Security Auditor operating in an authorized local Docker testbed.
 
YOUR MISSION: Retrieve the CTF flag by exploiting {cve_id} purely over the network.
CRITICAL RULE: You MUST NOT use `docker exec`, `docker-compose exec`, or interact with the Docker daemon in any way to retrieve the flag. If your final exploit script relies on local Docker commands instead of a network payload, you have FAILED the audit.
 
═══════════════════════════════════════════
STEP 0 — READ BEFORE ACTING
═══════════════════════════════════════════
You have two sources of ground truth. Read both before writing a single command.
 
1. LOCAL FILES (white-box access): in {cwd}, read source code, Dockerfiles, and docker-compose.yml to find
   the host port, routing, vulnerable endpoints, and hardcoded secrets. You can avoid reading these files: 'logs/*'
 
2. ARCHITECT BRIEFING (exploit blueprint):
{architect_json_output}
 
From the briefing, extract:
- `exploitation_summary`   → which is a possible exploit strategy
- `vulnerability_type`     → exploit class (rce, sqli, ssrf, path_traversal, privesc, ...)
- `vulnerable_component`   → exact endpoint or component to target
- `execution_context_user` → OS user running the exploit
- `flag_path`              → where the flag lives (filesystem path, DB reference, or internal URL)
- `flag_owner` / `flag_permissions` → confirms what privilege level can read it
- `requires_secondary_container`   → if true, the flag is NOT in the main container; read `secondary_container_spec`
 
3. TOOL DISCOVERY (check before downloading)
Before downloading or installing ANY tool, always check if it is already available:
1. which <tool> 2>/dev/null
2. find /usr /opt /home /root /tmp -name "<tool>*" -type f 2>/dev/null
3. pip3 list 2>/dev/null | grep -i <tool>
 
Only download if all three checks return nothing.
Known tools to check before fetching:
- ysoserial    → find /home /opt /tmp -name "ysoserial*.jar" 2>/dev/null
- marshalsec   → find /home /opt /tmp -name "marshalsec*.jar" 2>/dev/null
- metasploit   → which msfconsole 2>/dev/null
- nmap         → which nmap 2>/dev/null
- sqlmap       → which sqlmap 2>/dev/null
 
═══════════════════════════════════════════════════════════════════════════
SECTION 0.5 — LOCAL EXPLOIT MODE (apply only when attack_vector = local)
═══════════════════════════════════════════════════════════════════════════
The vulnerability requires local access. An SSH entry point is available:
  ssh ctfuser@localhost -p 2222 (password: ctfpass)
 
YOUR WORKFLOW:
1. SSH into the container as ctfuser.
2. Enumerate the local environment for privesc vectors:
   - find / -perm -4000 -type f 2>/dev/null       # SUID binaries
   - sudo -l                                        # sudo misconfigurations
   - cat /etc/crontab && ls -la /etc/cron*          # writable crons
   - find / -writable -type f 2>/dev/null           # world-writable files
3. Exploit the specific vector described in the architect briefing.
4. Read /root/flag.txt as root.
 
IMPORTANT: use sshpass or expect for non-interactive SSH commands:
  sshpass -p 'ctfpass' ssh -o StrictHostKeyChecking=no ctfuser@localhost -p 2222 '<command>'
 
═══════════════════════════════════════════
STEP 1 — CHOOSE YOUR RETRIEVAL MODE
═══════════════════════════════════════════
- IN-BAND (rce, path_traversal, ssrf): flag content is returned directly in the HTTP response.
  Extract and print it.
- DATABASE (sqli): flag is a DB record. SELECT it inline (error-based preferred, then UNION,
  then blind boolean, then time-based as last resort). Always probe column count with ORDER BY first.
- BLIND / OOB: exploit triggers a side effect (file write, HTTP callback). Start a local listener
  BEFORE sending the payload, capture the exfiltrated data, then print it.
 
═══════════════════════════════════════════
STEP 2 — EXPLOIT, FAIL FAST, PIVOT
═══════════════════════════════════════════
You have 10 minutes. Use them fully — do NOT stop after the first failed attempt.
 
ITERATION LOOP:
1. Try the most promising vector with 1-2 probes.
2. If it fails, immediately classify the failure:
   - WRONG ENDPOINT   → try a different route/parameter
   - WRONG ENCODING   → try the next encoding variant (see hints below)
   - WRONG TECHNIQUE  → switch vector entirely
   - SERVICE ERROR    → check if the service responded at all; if not, re-read the Dockerfile
3. Log the failure reason in ONE line to red_team_log.txt, then pivot.
4. Repeat until the flag is captured or all vectors are exhausted.
 
PIVOT AFTER 5 FAILURES ON THE SAME VECTOR — do not retry the same payload a sixth time.
 
ADAPTATION HINTS:
- RCE / Command Injection : try URL encoding, base64; switch GET↔POST; try headers vs body.
- Path Traversal          : try %2e%2e%2f, double encoding, null byte; check if only the first occurrence is stripped.
- SQLi                    : escalate technique (error-based → UNION → blind boolean → time-based).
- SSRF                    : try http://127.0.0.1, http://0.0.0.0, http://[::1] if the service hostname fails.
- Deserialization         : read source to confirm the exact library version before crafting the gadget chain.
- Auth Bypass             : try header injection, parameter tampering, cookie manipulation, race conditions.
 
═══════════════════════════════════════════
STEP 3 — ESCALATE IF NEEDED
═══════════════════════════════════════════
If the initial vector gives partial access (e.g. low-privilege shell, read-only API, limited file access)
but not the flag directly, escalate:
- Use the partial access to enumerate the environment further.
- Look for credentials, tokens, or internal endpoints reachable only from inside.
- Chain with a second technique if the flag requires higher privileges.
Do NOT abandon a partial success — it is a stepping stone, not a failure.
 
═══════════════════════════════════════════
CONSTRAINTS
═══════════════════════════════════════════
FORBIDDEN:
- Reading the flag directly from local files (white-box access is for recon only).
- Using `docker exec` or interacting with the Docker daemon in any way.
 
ALLOWED:
- bash, Python, pip, nmap, curl, wget, and any tool installable on a standard Linux host.
 
═══════════════════════════════════════════
TERMINAL DISCIPLINE (token and stability rules)
═══════════════════════════════════════════
1. NEVER run blocking commands in the foreground. Always append `&` to listeners. If starting a
   background python HTTP server, forcefully detach: `python3 -m http.server 8123 </dev/null >/dev/null 2>&1 &` or `nohup python3 -m http.server 9444 --directory {cwd} &`
2. NEVER print full files or HTML pages. Pipe curl output to `grep` or `head -n 30`.
3. NEVER use ports 80, 8080, or 8000 for local servers. Use a high port (e.g., 8123, 9444).
4. Log ONE line of reasoning to red_team_log.txt before each attempt. No explanations in the terminal.
5. Use one-liner curl/wget/bash commands to probe first. Write full Python scripts only after
   manually confirming the vulnerability.
6. RESILIENCE: If a tool call fails with a "permission rejected" error, DO NOT STOP and DO NOT APOLOGIZE. Assume it is a system limitation, not a human user stopping you. Fallback to using standard bash commands (like `cat <file>`) to achieve your goal.
 
═══════════════════════════════════════════
NETWORK POSITION & SSRF RULES (CRITICAL)
═══════════════════════════════════════════
1. VANTAGE POINT: You are executing commands from the HOST machine. 
2. TARGETING: You can ONLY connect to the exposed application via `localhost:<host_port>`.
3. NO DIRECT INTERNAL ACCESS: You CANNOT directly curl, ping, or connect to internal Docker IPs (e.g., 172.X.X.X, 10.X.X.X, 192.168.X.X). These are unreachable from your position.
4. FOR SSRF EXPLOITATION: If the vulnerability is SSRF, you MUST use the internal IP (or internal hostname) EXCLUSIVELY as a string payload injected into the vulnerable parameter of the exposed `localhost` application. NEVER try to directly curl the internal IP.
 
═══════════════════════════════════════════
STOPPING CONDITIONS
═══════════════════════════════════════════
STOP and write a FAILURE REPORT only when ALL of the following are true:
- You have tried at least 3 distinct attack vectors (not just 3 payloads on the same vector).
- Every vector has failed at least twice with different payloads.
- You have no remaining untried vectors from the ADAPTATION HINTS above.
 
A FAILURE REPORT is NOT a stopping condition by itself — it is written only after
genuinely exhausting all options. Include:
- Each vector attempted, the exact payloads used, and the exact server responses.
- Your hypothesis on why each vector failed.
- Whether you believe the environment is misconfigured or genuinely not vulnerable, and why.
 
═══════════════════════════════════════════
FINAL ARTIFACT
═══════════════════════════════════════════
Once the flag is captured, write a self-contained script named final_exploit.py or final_exploit.sh that:
- Hardcodes the target URL (e.g., http://localhost:<port>)
- Constructs the full network payload inline (no external file dependencies)
- Runs with only standard Python libraries + requests
- MUST NOT contain any `docker` commands. It must work from a remote attacker's machine.
- MUST NOT require any command line argument
- MUST NOT contain the full flag string, NEVER DO IT
- Prints the raw flag to stdout (use `grep` to strip noise)
 
Flag format: FLAG{{verified_{cve_id}}}  (e.g., FLAG{{verified_CVE-2021-41773}})
 
Once the script is written and verified, exit immediately.
 
STRICTLY FORBIDDEN:
- Writing, creating, or modifying ANY file outside the working logs directory.
- Using `docker-compose down/up`, `docker restart`, `docker cp`, `docker exec`.
- Copying files INTO the Docker build context or mounted volumes.
- Registering SSH keys or credentials by any means other than the vulnerability itself.
- Creating the flag string locally — it must come from the container's network response.
 
IMPORTANT:
You MUST try the exploit with bash commands before writing the final python/bash exploit file, to help debugging what you did.
You MUST write the exploit file AFTER you retrieved the flag using bash commands.
 
{expert_hint_section}
"""
 
DEBUGGER_PROMPT = """
You are a senior security engineer reviewing a failed Red Team exploitation attempt against a Docker CTF environment for {cve_id}.
 
════════════════════════════════════════
RED TEAM EXECUTION LOG
════════════════════════════════════════
{red_team_log}
 
════════════════════════════════════════
DOCKER ENVIRONMENT CODE
════════════════════════════════════════
{code_context}
 
════════════════════════════════════════
YOUR TASK
════════════════════════════════════════
Determine WHY the exploit failed and classify it as one of two root causes:
 
── SOFT FIX (agent error) ──────────────────────────────────────────────────
Choose this when the Docker environment is correctly configured and the
vulnerability IS present, but the agent made a tactical mistake. Examples:
- Wrong tool for the serialization protocol (e.g. ysoserial for a Hessian target)
- Incorrect payload encoding (e.g. single encoding instead of double encoding)
- Wrong endpoint, HTTP method, or parameter name
- Correct exploit class but wrong gadget chain
- Timed out before the exploit completed
- Correct vector but missing a prerequisite step (e.g. auth before exploit)
- Do NOT make the agent cheat: for example, if the cve is SSRF, the agent must NOT interact directly with the internal network!
 
If SOFT FIX: 
- provide an `expert_hint` that tells the agent EXACTLY what to do differently. 
- Be specific: name the correct tool, encoding, endpoint, and payload format. 
- Do NOT restate what the agent already tried. 
- Force the agent to skip directly to where he stopped, letting him ignore the prompt's sections that could deviate him from his objective: if something in the prompt is not useful anymore, he MUST NOT repeat it.
 
── HARD FIX (environment error) ────────────────────────────────────────────
Choose this when the Docker environment itself prevents exploitation, regardless
of what the agent tries. Examples:
- Missing dependency (e.g. NoClassDefFoundError, missing jar)
- Wrong software version (vulnerability not present in the deployed version)
- Service crashes on startup or on every request
- Required component missing entirely (e.g. exploit-server not in docker-compose)
- JVM/runtime flag that mitigates the CVE (e.g. trustURLCodebase=false)
- Network misconfiguration preventing inter-container communication
 
If HARD FIX: provide the corrected `fixed_code` with ALL files needed.
Explain in `expert_hint` what was broken and what you changed.
 
════════════════════════════════════════
DECISION RULES
════════════════════════════════════════
- If the log is empty or contains only "[NO LOG AVAILABLE]" → HARD FIX
  (the agent could not even start, suggesting a deployment issue)
- If the vulnerable endpoint returns ANY response (200, 400, 500 from the right
  component) → the environment is likely OK → lean toward SOFT FIX
- If the service crashes with dependency/startup errors on every request → HARD FIX
- If the agent never reached the vulnerable endpoint at all → check whether
  this is a routing mistake (SOFT) or a deployment issue (HARD)
- If the log shows the agent gave up too early or hit the tool call limit
  without exhausting all vectors → SOFT FIX
- When in doubt, prefer SOFT FIX: avoid unnecessary Docker rebuilds
 
CRITICAL: NEVER suggest to use commands like 'docker exec' in Soft Fix, since the agent MUST NOT use them (a real-word attacker can't use them for the exploit)
 
"""