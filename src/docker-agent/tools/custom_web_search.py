"""Custom web search function."""

import os
import re
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_openai import ChatOpenAI

# My modules
from prompts import (
    LLM_SUMMARIZE_WEBPAGE_PROMPT, 
    GET_DOCKER_SERVICES_PROMPT,
)
from configuration import langfuse_handler, WebSearch


class ContextGenerator:
    def __init__(self, n_documents, verbose, model):
        self.verbose = verbose
        self.n_documents = n_documents
        self.text_len_threshold = 50
        self.model = model

        # Retrieve the Google CSE key and ID from environment variables
        # self.google_api_key = os.getenv("GOOGLE_API_KEY")
        # self.google_cse_id = os.getenv("GOOGLE_CSE_ID")
        self.serpapi_key = os.getenv("SERPAPI_KEY")
        self.or_api_key = os.getenv("MY_OPENROUTER_API_KEY")
        self.local_key = os.getenv("LOCAL_KEY", "")

        if not self.serpapi_key:
            raise ValueError("SERPAPI_KEY must be set as environment variable.")

    def is_text_clean(self, text):
        """Check if the given text is valid UTF-8 encoded content by trying to encode and decode it."""
        try:
            text.encode("utf-8").decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    def extract_and_clean_content(self, url):
        """For each URL that has been found by the Google API:
        - Check if the content is HTML
        - Remove script and style tags from the page
        - Extract the text from the page
        - Evaluate if enough data has been extracted"""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                if self.verbose:
                    print(f"\t[SKIP] {url} - Response code: {response.status_code}")
                return None
            
            content_type = response.headers.get("Content-Type", "")
            if not content_type.startswith("text/html"):
                if self.verbose:
                    print(f"\t[SKIP] {url} - Content-Type not valid: {content_type}")
                return None

            # Parses the HTML using Python's built-in "html.parser" engine
            # & transform the raw HTML (i.e. response.content) into a tree-like object (soup) that represents the structure of the web page
            soup = BeautifulSoup(response.content, "html.parser")

            # Remove <script> and <style> elements, as these do not contribute to the main textual content
            for script_or_style in soup(["script", "style"]):
                script_or_style.decompose()

            # Extract the text from the soup object (ignoring tags)
            text = soup.get_text()
            # Removes excessive whitespaces
            text = re.sub(r"\s+", " ", text).strip()

            # If not enough text (e.g. 50) has been extracted, or if the text is not clean, skip this URL
            if len(text) < self.text_len_threshold or not self.is_text_clean(text):
                return None

            return text

        except Exception as e:
            if self.verbose:
                print(f"\t[ERROR] Failed to fetch {url}: {e}")
            return None

    def get_web_search_results(self, cve_id):
        """Use the Google Custom Search JSON API to retrieve data from the web."""
        print("\tSearching with Google API...")
        documents = []
        query = f"{cve_id} -github"

        # Gather data from 'n_documents'
        params = {
            "engine": "google",
            "q": query,
            "api_key": self.serpapi_key,
            "num": 10
        }

        try:
            response = requests.get("https://serpapi.com/search", params=params, timeout=10)
            # Raise an exception if the GET request was unsuccessful
            response.raise_for_status()
            results = response.json()

        # Catch the exception
        except Exception as e:
            if self.verbose:
                print(f"\t[GOOGLE SEARCH ERROR] {e}")
            return []

        items = results.get("organic_results", [])
        for item in tqdm(items, disable=not self.verbose, leave=False):
            # Get the URL of the web page to extract its content
            url = item.get("link")
            if not url:
                continue

            # Extracting data from the URL
            doc = self.extract_and_clean_content(url)
            if doc:
                print(f"\tContent processed from {url}")
                documents.append((url, doc))

            # If enough data has been collected, break the loop
            if len(documents) >= self.n_documents:
                break

        return documents

    def summarize_web_page(self, doc, cve_id, character_limit: int = 1000, max_chars: int = 450000) -> str:
        # Log when the content is too long, to evaluate how many times it happens and what you are losing
        if len(doc) > max_chars:
            try:
                with open("long_web_pages.log", "a", encoding="utf-8") as logf:
                    logf.write("\n\n========== [URL EXCEEDED LIMIT] ==========\n")
                    logf.write(f"CVE ID: {cve_id}\n")
                    logf.write(f"Document length: {len(doc)} characters\n")
                    logf.write(f"Document content:\n{doc}\n")

            except Exception as log_error:
                if self.verbose:
                    print(f"\t[LOGGING ERROR] {log_error}")

        try:
            # Create message history for the LLM
            messages = [
                # Passing the system prompt to the LLM
                SystemMessage(content=LLM_SUMMARIZE_WEBPAGE_PROMPT.format(cve_id=cve_id, character_limit=character_limit)),
                # Passing the content of the web page as a user message
                HumanMessage(content=f"Here is the content you have to summarise: {doc[:max_chars]}"),
            ]
            
            llm_model = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1", #"https://llm.polito.it", #
                api_key=self.or_api_key, #self.local_key, 
                model="deepseek/deepseek-v4-flash", #"gemma-4-31b", #
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
            
            # Invoke the LLM to summarize the web page content
            response = llm_model.invoke(messages, config={"callbacks": [langfuse_handler]})
            if self.verbose:
                print(f"\tSummary: {response.content.strip()}")
                
            # Count input and output tokens
            input_token_count = response.response_metadata.get("token_usage", {}).get("prompt_tokens", 0)
            output_token_count = response.response_metadata.get("token_usage", {}).get("completion_tokens", 0)
            return (response.content.strip(), input_token_count, output_token_count)

        except Exception as e:
            if self.verbose:
                print(f"\t[LLM WEB PAGE SUMMARY ERROR] {e}")
            return (None, 0, 0)

    def summarize_web_search(self, urls, summaries, cve_id, max_chars: int = 450000):
        try:
            # Concatenate the summaries
            conc_sum = ""
            for url, summary in zip(urls, summaries):
                conc_sum += f"Source: {url}\n{summary}\n\n"
                
            if self.verbose:
                print(f"\n\n\tSUMMARY CONCATENATION\n\t{conc_sum}")
                
            # Create message history for the LLM
            messages = [
                # Passing the system prompt to the LLM
                SystemMessage(content=GET_DOCKER_SERVICES_PROMPT.format(cve_id=cve_id)),
                # Passing the content of the web search as a user message
                HumanMessage(content=f"Use the following knowledge to achieve your task: {conc_sum[:max_chars]}"),
            ]
            
            llm_model = ChatOpenAI(
                base_url="https://openrouter.ai/api/v1", #"https://llm.polito.it", #
                api_key=self.or_api_key, #self.local_key, 
                model="deepseek/deepseek-v4-flash", #"gemma-4-31b", #
                temperature=0.0, 
                max_retries=2, 
                max_completion_tokens=10000
            )
            
            parser = PydanticOutputParser(pydantic_object=WebSearch)
            messages = [
                SystemMessage(content=GET_DOCKER_SERVICES_PROMPT.format(cve_id=cve_id) + f"\n\n{parser.get_format_instructions()}"),
                HumanMessage(content=f"Use the following knowledge to achieve your task: {conc_sum[:max_chars]}"),
            ]
            response = llm_model.invoke(messages, config={"callbacks": [langfuse_handler]})
            formatted_response = parser.parse(response.content)
            
            if self.verbose:
                print(f"\n\n\tFORMATTED WEB SEARCH RESPONSE\n\t{formatted_response}")
            
            return formatted_response

        except Exception as e:
            if self.verbose:
                print(f"\t[LLM WEB SEARCH SUMMARY ERROR] {e}")
    
    def get_cve_from_nist_api(self, cve_id):
        """Retrieve CVE data from NIST's NVD API, extracting all technically
        useful fields instead of just the description."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            vuln = data.get("vulnerabilities", [])[0]["cve"]

            # --- Description ---
            description = next(
                (d["value"] for d in vuln.get("descriptions", []) if d["lang"] == "en"),
                "No description available."
            )

            # --- CWE ---
            cwes = []
            for weakness in vuln.get("weaknesses", []):
                for wd in weakness.get("description", []):
                    if wd["lang"] == "en" and wd["value"] not in cwes:
                        cwes.append(wd["value"])
            cwe_str = ", ".join(cwes) if cwes else "N/A"

            # --- CVSS ---
            cvss_str = "N/A"
            metrics = vuln.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_str = (
                        f"Score: {m['cvssData'].get('baseScore', 'N/A')} "
                        f"({m['cvssData'].get('baseSeverity', m.get('baseSeverity', 'N/A'))}), "
                        f"Vector: {m['cvssData'].get('vectorString', 'N/A')}"
                    )
                    break

            # --- Affected versions from CPE ---
            affected_versions = []
            for config in vuln.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if not cpe_match.get("vulnerable", False):
                            continue
                        entry = cpe_match.get("criteria", "")
                        version_info = []
                        if cpe_match.get("versionStartIncluding"):
                            version_info.append(f">= {cpe_match['versionStartIncluding']}")
                        if cpe_match.get("versionEndExcluding"):
                            version_info.append(f"< {cpe_match['versionEndExcluding']}")
                        if cpe_match.get("versionEndIncluding"):
                            version_info.append(f"<= {cpe_match['versionEndIncluding']}")
                        if version_info:
                            affected_versions.append(f"{entry} ({', '.join(version_info)})")
                        elif entry:
                            affected_versions.append(entry)
            versions_str = "\n".join(affected_versions[:10]) if affected_versions else "N/A"

            # --- Reference URLs (returned separately for fetching) ---
            reference_urls = [
                ref["url"] for ref in vuln.get("references", [])
                if ref.get("url", "").startswith("http")
            ]

            # Build a structured summary to inject into the pipeline
            summary = (
                f"[NVD STRUCTURED DATA FOR {cve_id}]\n"
                f"Description: {description}\n"
                f"CWE: {cwe_str}\n"
                f"CVSS: {cvss_str}\n"
                f"Affected versions (CPE):\n{versions_str}\n"
                f"Reference URLs: {', '.join(reference_urls[:5])}"
            )

            return (url, summary, reference_urls)

        except Exception as e:
            return f"Failed to retrieve CVE data from NIST: {str(e)}"


    def fetch_ghsa(self, cve_id: str) -> list[tuple[str, str]]:
        """Fetch the GitHub Security Advisory (GHSA) for the given CVE.
        GHSA advisories are usually richer than NVD for recent CVEs — they
        include patch diffs, affected version ranges, and PoC references
        within days of disclosure."""
        url = f"https://api.github.com/repos/advisories?cve_id={cve_id}"
        # Use the public search endpoint instead
        search_url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=3"
        results = []
        
        try:
            headers = {"Accept": "application/vnd.github+json"}
            github_token = os.getenv("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"Bearer {github_token}"

            resp = requests.get(search_url, headers=headers, timeout=10)
            if resp.status_code != 200:
                if self.verbose:
                    print(f"\t[GHSA] No advisory found for {cve_id} (status {resp.status_code})")
                return []

            advisories = resp.json()
            for adv in advisories[:2]:  # max 2 advisories
                ghsa_id = adv.get("ghsa_id", "")
                html_url = adv.get("html_url", f"https://github.com/advisories/{ghsa_id}")
                
                # Build a structured text from the advisory fields
                summary_parts = []
                if adv.get("summary"):
                    summary_parts.append(f"Summary: {adv['summary']}")
                if adv.get("description"):
                    summary_parts.append(f"Details: {adv['description'][:2000]}")
                if adv.get("severity"):
                    summary_parts.append(f"Severity: {adv['severity']}")
                if adv.get("cwes"):
                    summary_parts.append(f"CWEs: {', '.join(c['cwe_id'] for c in adv['cwes'])}")
                
                # Affected packages and versions
                for pkg in adv.get("vulnerabilities", [])[:5]:
                    p = pkg.get("package", {})
                    name = p.get("name", "")
                    ecosystem = p.get("ecosystem", "")
                    vuln_range = pkg.get("vulnerable_version_range", "")
                    first_patch = pkg.get("first_patched_version", "")
                    summary_parts.append(
                        f"Affected: {ecosystem}/{name} {vuln_range} "
                        f"(patched in: {first_patch})"
                    )

                if summary_parts:
                    text = f"[GITHUB ADVISORY {ghsa_id} for {cve_id}]\n" + "\n".join(summary_parts)
                    results.append((html_url, text))
                    if self.verbose:
                        print(f"\t[GHSA] Found advisory {ghsa_id} for {cve_id}")

        except Exception as e:
            if self.verbose:
                print(f"\t[GHSA ERROR] {e}")

        return results


    def invoke(self, cve_id):
        # Documents are split into two groups:
        #   - web_documents:        free-form HTML pages -> lossy per-page summarization
        #   - structured_documents: NVD + GHSA authoritative data -> kept VERBATIM,
        #                           never summarized, so exact affected versions /
        #                           CPE ranges / CWEs are preserved for the extractor.

        # --- Free-form HTML from SerpAPI (Google) ---
        web_documents = self.get_web_search_results(cve_id)

        structured_documents = []

        # --- NVD (structured, verbatim) ---
        nist_data = self.get_cve_from_nist_api(cve_id)
        reference_urls = []
        nvd_ok = False
        if isinstance(nist_data, tuple):
            url, summary, reference_urls = nist_data
            structured_documents.append((url, summary))
            nvd_ok = True
            if self.verbose:
                print(f"\t[NVD] Structured data fetched. References: {reference_urls}")
        elif self.verbose:
            print(f"\t[NIST API ERROR] {nist_data}")

        # --- GHSA (structured, verbatim) ---
        ghsa_results = self.fetch_ghsa(cve_id)
        structured_documents.extend(ghsa_results)

        # --- NVD reference URLs (advisories, vendor patches): these are free-form
        # HTML pages, so they go through summarization like any other web page. ---
        # Skip domains that are paywalled, noisy, or already covered above.
        skip_domains = {"cve.org", "nvd.nist.gov", "twitter.com", "x.com", "youtube.com"}
        fetched_refs = 0
        for ref_url in reference_urls[:8]:  # scan at most 8 reference URLs
            if fetched_refs >= 3:  # but fetch at most 3 extra pages
                break
            domain = ref_url.split("/")[2] if "//" in ref_url else ""
            if any(skip in domain for skip in skip_domains):
                continue
            doc = self.extract_and_clean_content(ref_url)
            if doc:
                web_documents.append((ref_url, doc))
                fetched_refs += 1
                if self.verbose:
                    print(f"\t[NVD REF] Fetched: {ref_url}")

        total_docs = len(web_documents) + len(structured_documents)
        print(f"\tFetched {total_docs} documents total "
            f"(web={len(web_documents)}, "
            f"nvd={1 if nvd_ok else 0}, ghsa={len(ghsa_results)}, nvd_refs={fetched_refs})")

        if not web_documents and not structured_documents:
            return ("No documents retrieved from web search.", 0, 0)

        # Summarize ONLY the free-form HTML documents.
        input_token_count = 0
        output_token_count = 0
        summarized_web = {}
        for url, doc in tqdm(web_documents, desc="Summarizing", disable=not self.verbose, leave=False):
            result = self.summarize_web_page(doc=doc, cve_id=cve_id)
            if not isinstance(result, tuple) or len(result) != 3:
                continue
            summary, inputCount, outputCount = result
            input_token_count += inputCount
            output_token_count += outputCount
            if summary:
                summarized_web[url] = summary

        # Assemble the final context: structured docs FIRST and verbatim (so they
        # survive any tail truncation in summarize_web_search), then the summaries.
        urls = [u for u, _ in structured_documents] + list(summarized_web.keys())
        docs = [d for _, d in structured_documents] + list(summarized_web.values())

        if not urls:
            return ("No relevant content could be extracted.", 0, 0)

        formatted_response = self.summarize_web_search(urls, docs, cve_id)
        if formatted_response is None:
            return ("Web search summarization failed.", 0, 0)

        return (formatted_response, input_token_count, output_token_count)

def web_search_func(cve_id: str, model: str, n_documents: int = 10, verbose: bool = True):
    inCount = 0
    outCount = 0
    
    try:
        rag_model = ContextGenerator(n_documents=n_documents, verbose=verbose, model=model)
        (formatted_response, inCount, outCount) = rag_model.invoke(cve_id)
    except Exception as e:
        formatted_response = f"An error occurred during the web search: {str(e)}"
    print(formatted_response)
    return (formatted_response, inCount, outCount)