import os
from typing import Optional
from langfuse import Langfuse, get_client # type: ignore
from langfuse.langchain import CallbackHandler # type: ignore
from pydantic import BaseModel, Field # type: ignore
from typing import Literal, List
from enum import Enum
 
# Initialize Langfuse client with constructor arguments
Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST"),
)
 
# Get the configured client instance
langfuse = get_client()
# Initialize Langfuse CallbackHandler for LangGraph/Langchain (tracing)
langfuse_handler = CallbackHandler()


class Service(BaseModel):
    name: str = Field(description="Name of the service")
    version: list[str] = Field(description="List of versions of the service")
    dependency_type: str = Field(description="Type of the dependency of the service, either 'HARD' or 'SOFT'")
    description: str = Field(description="Brief description of why the service is necessary in the Docker")
    packaging_type: str = Field(
        default="image",
        description=(
            "How this service is delivered: 'image' if it has its own Docker Hub image "
            "(e.g., mysql, redis, nginx), 'os_package' if it is a system package installed "
            "via apt/yum inside another image (e.g., sudo, openssl, glibc, polkit, sshd)"
        )
    )

class WebSearch(BaseModel):
    desc: str = Field(description="Description of the CVE")
    cwe: str = Field(description="The CWE associated to the CVE")
    attack_type: str = Field(description="Type of attack (e.g. DoS, RCE, etc.)")
    services: list[Service] = Field(description="List of services to be used in the Docker system vulnerable to the CVE")
    

class HARDServiceVersionAssessment(BaseModel):
    hard_version: bool = Field("Does the 'HARD' service version range contain the expected version?")

    
class VulhubGroundTruth(BaseModel):
    services: List[str] = Field(
        description='List of services in format "TYPE:service_name:version". TYPE is "HARD" for the main vulnerable app, "SOFT" for secondary databases/services.'
    )

class PlatformFeasibility(BaseModel):
    linux_container_feasible: bool = Field(description="False if the vulnerable service cannot be repreesented using Linux and Docker")
    reason: str = Field(description="Brief explaination")

class File(BaseModel):
    location: str = Field(description="Location of the file")
    content: str = Field(description="Content of the file")
    

class Code(BaseModel):
    files: list[File] = Field(description="Name and code of the various files needed to reproduce the CVE")
    directory_tree: str = Field(description="Directory tree where the files will be stored, rooted in the CVE-ID folder")
    target_hostname: str = Field(description="A realistic internal hostname for the target node (e.g., 'srv-app-01')")

class ContainerLogsAssessment(BaseModel):
    container_ok: bool = Field(description="Is the Docker container running correctly?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of the error presented by the logs")
    
    
class ServiceAssessment(BaseModel):
    code_hard_version: bool = Field(description="Does the generated code use vulnerable version of the 'HARD' services?")
    services_ok: bool = Field(description="Does the generated code contain the services provided by the web search?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of why one or more milestones have failed")


class NetworkAssessment(BaseModel):
    network_setup: bool = Field(description="Are all services/containers setup to be accessible from the right network ports?")
    fail_explanation: Optional[str] = Field(description="Detailed explanation of why one or more milestones have failed")

    
class CodeRevision(BaseModel):
    error: str = Field(description="Detailed description of the error presented by the logs")
    fix: str = Field(description="Detailed description of fix applied to the code to solve the error")
    fixed_code: Code = Field(description="File location, content and associated directory tree")

class ExploitSurfaceAssessment(BaseModel):
    surface_ok: bool
    probes_run: list[str]
    fail_explanation: str = ""
    revision_goal: str = ""

class Stats(BaseModel):
    num_containers: int = Field(default=0, description="Number of containers created while testing the Docker")
    test_iteration: int = Field(default=0, description="Number of iterations of the test loop")
    total_iterations: int = Field(default=0, description="Number of iterations considering possible resets after an Hard Fix by the debugger node")
    debug_retries: int = Field(default=0, description="Number of times the debugger node is reached")
    starting_image_builds: bool = Field(default=True, description="Checks if the LLM is able to generate a buildable Docker image in the first test iteration")
    image_build_failures: int = Field(default=0, description="Number of times the Docker image fails to build")
    starting_container_runs: bool = Field(default=True, description="Checks if the LLM is able to generate working Docker container in the first test iteration")
    container_run_failures: int = Field(default=0, description="Number of times the Docker container fails to run")
    not_vuln_version_fail: int = Field(default=0, description="Number of times the Docker builds and runs correctly but uses a not vulnerable version of the 'HARD' service")
    docker_misconfigured: int = Field(default=0, description="Number of times the Docker builds and runs correctly but uses a wrong network setup")
    docker_scout_vulnerable: bool = Field(default=False, description="Is the Docker environment vulnerable to the specified CVE?")
    exploitable: bool = Field(default=False, description="Does the exploit return the expected result?")
    services_ok: bool = Field(default=False, description="Does the Docker use all the services provided by the web search?")
    requires_manual_setup: bool = Field(default=False, description="Does this service require the user to perform some sort of manual operation to make it work or does it work just by launching the Docker?")
    
    
class Milestones(BaseModel):
    cve_id_ok: bool = Field(default=False, description="Does the provided CVE-ID exist in the MITRE CVE database?")
    docker_builds: bool = Field(default=False, description="Do all Docker images get built correctly?")
    docker_runs: bool = Field(default=False, description="Do all Docker containers run correctly?")
    code_hard_version: bool = Field(default=False, description="Does the generated code use vulnerable version of the 'HARD' services?")
    network_setup: bool = Field(default=False, description="Are all services/containers setup to be accessible from the right network ports?")
    exploit_surface_ok: bool = Field(default=False, description="Are the services correctly responding to the probes?")
    flag_placed: bool = Field(default=False, description="Is the flag placed at the intended location?")
    flag_protected: bool = Field(default=False, description="Is the flag correctly protected from trivial attempts to reach it (e.g. 'curl http://localhost/flag.txt')?")
    exploit_success: bool = Field(default=False, description="Was the flag captured during the exploit?")

class VulnerabilityType(str, Enum):
    rce = "rce"
    deserialization = "deserialization"
    path_traversal = "path_traversal"
    sqli = "sqli"
    ssrf = "ssrf"
    privesc = "privesc"
    auth_bypass = "auth_bypass"
    info_disclosure = "info_disclosure"
    xxe = "xxe"
    xss = "xss"
    csrf = "csrf"
    other = "other"

class AttackVector(str, Enum):
    network = "network"
    adjacent = "adjacent"
    local = "local"
    physical = "physical"

class CVEClassification(BaseModel):
    cve_id: str = Field(description="The CVE-ID provided as input")
    cwe_id: str = Field(description="e.g. CWE-78")
    cwe_name: str = Field(description="The name commonly associated to a CWE-ID")
    vulnerability_type: VulnerabilityType = Field(description="The type of vulnerability (according to the class defined) in which this CVE can be mapped")
    attack_vector: AttackVector = Field(description="The required attack vector (e.g. local, network)")
    requires_auth: bool = Field(description="Does this CVE require to be authenticated to be exploited?")
    vulnerable_component: str = Field(description="Brief description of the vulnerable component or endpoint")
    execution_context_user: str = Field(description="OS user under which the exploit runs, e.g. www-data, root, redis")
    exploitation_summary: str = Field(description="2-3 sentence plain-English description of how the exploit works mechanically")
    kill_chain_steps: int = Field(description="Number of distinct logical steps required to exploit the vulnerability and read the flag (e.g., 1 for direct RCE, 3 for Auth Bypass -> Token Extract -> RCE).")
    flag_path: str = Field(description="Absolute path, DB reference (Database: X, Table: Y, Column: Z), or internal URL")
    flag_owner: str = Field(description="The user in the system that should own the flag file")
    flag_permissions: str = Field(description="Octal string e.g. '400', or 'N/A' for DB flags")
    placement_rationale: str = Field(description="An explanation to justofy the flag placement decision")
    requires_secondary_container: bool = Field(description="Does this CVE require more than one container?")
    secondary_container_spec: str | None = Field(default=None, description="Description of the hidden container if needed")
    tech_stack: str = Field(description="The primary language or framework of the vulnerable component (e.g., Java/Spring, PHP, Node.js, Python/Flask, C/Binary).")
    requires_oob_interaction: bool = Field(description="True if the exploit typically requires setting up a reverse shell, DNS interaction, or a local HTTP server to catch callbacks.")
    red_team_initial_hint: str = Field(description="A highly specific, 2-sentence actionable technical advice for the Red Team on how to approach this specific CVE.")

class SanityCheckResult(BaseModel):
    flag_exposed: bool = Field(description="True if the flag was found without exploiting the vulnerability")
    attempts: list[str] = Field(description="List of commands or requests attempted")
    exposed_via: str = Field(description="The command that returned the flag, or null if not exposed")
    verdict: str = Field(description="'REJECT' if flag_exposed is true, 'PASS' otherwise")

class SanityCheckResult(BaseModel):
    flag_exposed: bool
    attempts: list[str]
    exposed_via: str | None
    verdict: Literal["PASS", "REJECT"]

class SanityProbes(BaseModel):
    """Structured output for the probe-generation phase of sanity_check."""
    probes: list[str] = Field(description="List of shell commands to run as misconfiguration probes")

class RedTeamResult(BaseModel):
    exploit_success: bool = Field(description="True if the flag was successfully retrieved by exploiting the vulnerability")
    poc_steps: list[str] = Field(description="Ordered list of commands or HTTP requests used in the exploit")
    poc_script: str = Field(description="Self-contained shell or Python script reproducing the exploit")
    flag_value: str = Field(description="The flag string retrieved, or empty if exploit failed")
    failure_reason: str = Field(description="If exploit failed, explanation of why")

class DebuggerDecision(BaseModel):
    action_type: Literal["Soft Fix", "Hard Fix"] = Field(
        description="'Soft Fix' if the agent made a tactical mistake, 'Hard Fix' if the Docker environment is broken"
    )
    analysis: str = Field(
        description="One-sentence explanation of why the exploit failed"
    )
    expert_hint: str = Field(
        description="For soft fix: exact instructions for the agent. For hard fix: explanation of what was broken"
    )
    fixed_code: Optional[Code] = Field(
        default=None,
        description="Corrected Docker code — required if fix_type is 'hard', null otherwise"
    )