
import os
import argparse
import tempfile
import subprocess
import json
import shutil
from collections import Counter
from datetime import datetime
from typing import Dict, List, Tuple, Any

# Import updated handlers
from git_handler import clone_repository_from_env, get_scan_branches_from_env

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def ensure_osv_scanner():
    """
    Checks if osv-scanner is installed. If not, attempts to install it via 'go install'.
    Returns True on success, False on failure.
    """
    if shutil.which("osv-scanner"):
        print("✅ OSV-Scanner is already installed.")
        return True

    print("⚠️ OSV-Scanner not found. Attempting to install via 'go install'...")
    print("(This requires the Go programming language to be installed and configured correctly.)")
    try:
        install_command = [
            "go", "install", "github.com/google/osv-scanner/cmd/osv-scanner@latest"
        ]
        subprocess.run(install_command, check=True, capture_output=True, text=True)
        if shutil.which("osv-scanner"):
            print("✅ OSV-Scanner installed successfully.")
            return True
        else:
            print("❌ Installation seemed to succeed, but 'osv-scanner' is still not in the PATH.")
            print("   Please ensure your Go bin directory (e.g., $GOPATH/bin) is in your system's PATH.")
            return False
    except FileNotFoundError:
        print("❌ ERROR: The 'go' command was not found.")
        print("   Please install the Go programming language first: https://go.dev/doc/install")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Failed to install OSV-Scanner. Return code: {e.returncode}")
        print(f"   Stderr: {e.stderr}")
        return False


def get_llm():
    """
    Checks environment variables and returns the Gemini LLM instance.
    """
    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key:
        print("🔑 Google API key found. Using Google Gemini model (gemini-2.5-flash).")
        return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.2)
    else:
        raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


def analyze_code(llm, file_content, file_name):
    """
    Uses the provided LLM and LangChain to analyze a file's content.
    Produces a robust vulnerability report with enhanced output while preserving the original keys.
    """
    prompt = PromptTemplate(
        input_variables=["file_name", "code"],
        template_format="jinja2",
        template="""\
Act as a senior application security engineer. Analyze the following code from '{{ file_name }}'.
Perform a comprehensive and methodical analysis for common and less-common vulnerabilities.

**Focus Areas (apply as relevant to the language/framework):**
- **Injection:** SQL/NoSQL/Command/Shell injection, template injection, LDAP injection.
- **Validation & Sanitization:** Improper input validation, insufficient output encoding (XSS, HTML/Markdown injection).
- **Configuration & Secrets:** Hardcoded secrets (API keys, passwords, tokens), insecure storage, logging secrets, weak crypto.
- **Access Control:** IDOR, missing authorization checks, privilege escalation, CSRF (where applicable).
- **Deserialization & File Handling:** Insecure deserialization, unsafe file writes/reads, path traversal, SSRF.
- **Remote Code Execution & OS Interactions:** Unsafely building commands, unsanitized `sh`/`exec`.
- **Dependencies:** Use of vulnerable libraries or unpinned versions (flag only when evidence is clear).
- **Cloud & CI/CD specifics:** For Jenkinsfiles/Groovy pipelines, check:
  - Unsafe `sh` steps with interpolated variables.
  - Missing `withCredentials` or misuse (secrets leaked via `echo` or environment exposure).
  - Unpinned images/actions, overbroad permissions.
  - Storing secrets in environment variables or SCM.
- **Error Handling & Logging:** Sensitive data in logs; exception swallowing.
- **Concurrency & Resource Management:** Race conditions; file handle/socket misuse.

**Output Requirements:**
Return a **valid JSON array**. Each item MUST include these keys:
- "line_number": 1-based line integer of the primary problematic location.
- "vulnerability_type": short name (e.g., "SQL Injection", "XSS", "Hardcoded Secret").
- "risk_explanation": concise explanation of why it’s insecure.
- "suggested_fix": actionable guidance a developer can implement.

You MAY also include these optional keys for enhanced reporting:
- "severity": "High" | "Medium" | "Low"
- "cwe": e.g., "CWE-89 (SQL Injection)"
- "evidence": short code snippet or fragment
- "references": array of relevant docs/links (e.g., OWASP pages)

If you find no vulnerabilities, return an empty list: [].

**Important Guidance:**
1) Be certain—avoid false positives.
2) Be detailed—explain why it’s vulnerable.
3) Be actionable—provide clear fixes (e.g., parameterized queries, escaping/encoding, least privilege).
4) Consider usage context (function, class, pipeline stage).
5) Infer language/framework from '{{ file_name }}' and code content (e.g., Jenkinsfile → Groovy + shell).
6) If the issue spans multiple lines, report the first line where the risky construct starts.

**Code to Review**
```{{ code }}```
""",
    )
    chain = prompt | llm | StrOutputParser()
    result = chain.invoke({"file_name": file_name, "code": file_content})
    return result


def run_osv_scanner(repo_path):
    """Executes the OSV-Scanner tool on the repository path."""
    print("\nRunning OSV-Scanner for dependencies...")
    try:
        result = subprocess.run(
            ['osv-scanner', '--recursive', '--json', repo_path],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode not in (0, 1):
            print(f"❌ OSV-Scanner encountered an error:\n{result.stderr}")
            return None
        if result.stderr.strip():
            print(result.stderr)
        if not result.stdout.strip():
            print("✅ OSV-Scanner ran successfully and found no vulnerabilities.")
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("❌ ERROR: 'osv-scanner' command not found. Please install it or add to PATH.")
        return None
    except json.JSONDecodeError:
        print("❌ ERROR: Could not parse OSV-Scanner JSON output.")
        return None


def normalize_osv_json(obj: dict | None) -> List[dict]:
    """
    Normalize OSV-Scanner output to a common shape:
    Returns list[ { 'source': { 'path': <str> }, 'packages': [ { 'package': {'name': ...}, 'version': 'x.y', 'vulnerabilities': [ {'id': ...} ] } ] } ]
    """
    if not obj:
        return []
    if isinstance(obj, dict) and 'results' in obj:
        return obj['results']
    # Fallback if structure differs
    return obj.get('results', []) if isinstance(obj, dict) else []


def index_osv_packages(results: Any) -> Dict[Tuple[str, str, str], Dict[str, set]]:
    """
    Build index: { (ecosystem, name, version) : { 'vuln_ids': set([...]), 'sources': set([...]) } }
    """
    idx: Dict[Tuple[str, str, str], Dict[str, set]] = {}
    for res in normalize_osv_json(results):
        src = res.get('source', {}).get('path') or res.get('path') or '<unknown>'
        for pkg in res.get('packages', []):
            name = (pkg.get('package') or {}).get('name') or pkg.get('name')
            eco = (pkg.get('package') or {}).get('ecosystem') or pkg.get('ecosystem') or 'unknown'
            ver = pkg.get('version') or (pkg.get('package') or {}).get('version') or 'unknown'
            key = (eco, name, ver)
            vuln_ids = {v.get('id') for v in pkg.get('vulnerabilities', []) if v.get('id')}
            if key not in idx:
                idx[key] = {'vuln_ids': set(), 'sources': set()}
            idx[key]['vuln_ids'] |= vuln_ids
            idx[key]['sources'].add(src)
    return idx


def diff_dependency_indexes(idx_a: Dict[Tuple[str, str, str], Dict[str, set]],
                            idx_b: Dict[Tuple[str, str, str], Dict[str, set]]):
    """
    Compare two dependency indices and produce:
      - added: packages present only in B
      - removed: packages present only in A
      - changed_vulns: list of { package:(eco,name,ver), introduced:[ids], fixed:[ids] } for common packages with different vuln sets
    """
    set_a = set(idx_a.keys())
    set_b = set(idx_b.keys())
    added = sorted(set_b - set_a)
    removed = sorted(set_a - set_b)
    common = sorted(set_a & set_b)

    changed_vulns = []
    for key in common:
        a_v = idx_a[key]['vuln_ids']
        b_v = idx_b[key]['vuln_ids']
        if a_v != b_v:
            changed_vulns.append({
                'package': key,
                'introduced': sorted(b_v - a_v),
                'fixed': sorted(a_v - b_v)
            })
    return added, removed, changed_vulns


def get_severity(vuln_type):
    """Assigns a severity level to a vulnerability type."""
    vuln_type = (vuln_type or "").lower()
    if "injection" in vuln_type:
        return "🔴 Critical"
    elif "secret" in vuln_type or "privileged" in vuln_type:
        return "🟠 High"
    else:
        return "🟡 Medium"


def main():
    if not ensure_osv_scanner():
        print("\nHalting script because OSV-Scanner is not available.")
        return

    parser = argparse.ArgumentParser(description="Hybrid AI & Dependency Security Scanner (multi-branch)")
    parser.add_argument("--repo_url", required=True, help="URL of the Git repository to scan")
    args = parser.parse_args()

    try:
        llm = get_llm()
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Read branch list from .env (minimized configuration)
    branches = get_scan_branches_from_env()
    if not branches:
        # Empty means: scan default branch (HEAD after clone)
        branches = [None]  # None → default branch

    single_branch_opt = os.getenv("SINGLE_BRANCH", "false").strip().lower() == "true"

    # Collect results per branch
    per_branch_ai: Dict[str, List[dict]] = {}
    per_branch_osv: Dict[str, dict] = {}

    for br in branches:
        label = br or "<default>"
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"\n=== Cloning branch: {label} ===")
            cloned = clone_repository_from_env(args.repo_url, temp_dir, branch=br, single_branch=single_branch_opt)
            if not cloned:
                print("Scan aborted due to cloning failure.")
                return

            osv_results = run_osv_scanner(temp_dir)

            # AI source code scan
            ai_findings = []
            print("\nStarting AI source code scan...")
            for subdir, _, files in os.walk(temp_dir):
                if ".git" in subdir:
                    continue
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.go', '.rb', '.ts', '.tf', '.sh', '.yml', '.yaml', 'Dockerfile', 'Jenkinsfile')):
                        file_path = os.path.join(subdir, file)
                        relative_path = os.path.relpath(file_path, temp_dir)
                        try:
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                            if len(content.strip()) == 0 or len(content) > 50000:
                                continue
                            analysis_result = analyze_code(llm, content, relative_path)
                            cleaned_json_str = analysis_result.strip()
                            if cleaned_json_str.startswith("```json"):
                                cleaned_json_str = cleaned_json_str[7:]
                            if cleaned_json_str.endswith("```"):
                                cleaned_json_str = cleaned_json_str[:-3]
                            cleaned_json_str = cleaned_json_str.strip()

                            if cleaned_json_str:
                                vulnerabilities = json.loads(cleaned_json_str)
                                if isinstance(vulnerabilities, list) and vulnerabilities:
                                    for vuln in vulnerabilities:
                                        vuln['file_path'] = relative_path
                                        ai_findings.append(vuln)
                        except json.JSONDecodeError:
                            print(f" └─ ⚠️ WARNING: AI returned non-JSON output for this file. Skipping ({relative_path}).")
                        except Exception as e:
                            print(f" └─ ❌ ERROR: Could not process file {relative_path}: {e}")

            per_branch_ai[label] = ai_findings
            per_branch_osv[label] = osv_results

    # --- Report Generation ---
    report_lines: List[str] = []
    scan_date = datetime.now().strftime("%B %d, %Y")
    report_lines.append("# 🛡️ Security Scan Report")
    report_lines.append(f"\n**Repository:** `{args.repo_url}`")
    report_lines.append(f"**Scan Date:** {scan_date}")
    report_lines.append("\n---")
    report_lines.append("## 📊 Executive Summary")

    # Overall counts
    total_ai = sum(len(v) for v in per_branch_ai.values())
    total_dep = 0
    for osv in per_branch_osv.values():
        for res in normalize_osv_json(osv):
            for pkg in res.get('packages', []):
                total_dep += len(pkg.get('vulnerabilities', []))
    total_all = total_ai + total_dep

    if total_all == 0:
        report_lines.append("\n✅ **Excellent!** No security vulnerabilities were found in the source code or dependencies across scanned branches.")
    else:
        report_lines.append(f"\nThe scan identified a total of **{total_all} vulnerabilities** across code and dependencies.")
        report_lines.append(f"- Source code findings (AI): **{total_ai}**")
        report_lines.append(f"- Dependency vulnerabilities (OSV): **{total_dep}**")

    # Per-branch sections
    for br_label in per_branch_ai.keys():
        report_lines.append(f"\n---\n## 🧠 AI Code Scan — Branch: `{br_label}`")
        ai_findings = per_branch_ai[br_label]
        if not ai_findings:
            report_lines.append("\n✅ **Status:** No source code vulnerabilities found.")
        else:
            report_lines.append("\n### Vulnerability Overview")
            report_lines.append("\nSeverity | Vulnerability Type | File Location")
            report_lines.append("\n:--- | :--- | :---")
            for vuln in sorted(ai_findings, key=lambda x: get_severity(x.get('vulnerability_type', '')), reverse=True):
                severity = get_severity(vuln.get('vulnerability_type', ''))
                vtype = vuln.get('vulnerability_type', 'Unknown')
                location = f"`{vuln['file_path']}`"
                report_lines.append(f"{severity} | {vtype} | {location}")

            # Distribution chart (Mermaid)
            report_lines.append("\n### Vulnerability Distribution Chart")
            report_lines.append("\n```mermaid")
            report_lines.append("pie title Source Code Vulnerability Distribution")
            vuln_counts = Counter(v.get('vulnerability_type', 'Unknown') for v in ai_findings)
            for vtype, count in vuln_counts.items():
                report_lines.append(f'  "{vtype}" : {count}')
            report_lines.append("```")

            # Detailed breakdown
            report_lines.append("\n## 📝 Detailed Source Code Findings")
            findings_by_file = {}
            for finding in ai_findings:
                findings_by_file.setdefault(finding['file_path'], []).append(finding)
            for file_path, vulns in findings_by_file.items():
                report_lines.append(f"\n### 📄 File: `{file_path}`")
                for v in vulns:
                    severity = get_severity(v.get('vulnerability_type', ''))
                    report_lines.append(f"\n#### **{v.get('vulnerability_type', 'Unknown')}**")
                    report_lines.append(f"- **Severity:** {severity}")
                    report_lines.append(f"- **Line:** {v.get('line_number', 'N/A')}")
                    report_lines.append("\n**🚨 Risk:**")
                    report_lines.append(v.get('risk_explanation', 'No details provided.'))
                    report_lines.append("\n**✅ Recommendation:**")
                    report_lines.append(v.get('suggested_fix', 'No fix suggested.'))
                    report_lines.append("<br>")

        # Dependencies for this branch
        report_lines.append(f"\n## 📦 Dependency Vulnerabilities — Branch: `{br_label}`")
        osv_results = per_branch_osv.get(br_label)
        normalized = normalize_osv_json(osv_results)
        if normalized:
            for result in normalized:
                source = result.get('source', {}).get('path') or result.get('path') or '<unknown>'
                report_lines.append(f"\n### File: `{source}`")
                for pkg in result.get('packages', []):
                    name = (pkg.get('package') or {}).get('name') or pkg.get('name')
                    ver = pkg.get('version') or (pkg.get('package') or {}).get('version') or 'unknown'
                    vuln_ids = [v.get('id') for v in pkg.get('vulnerabilities', []) if v.get('id')]
                    if vuln_ids:
                        report_lines.append(f"- **{name} @ {ver}** → {', '.join(vuln_ids)}")
        else:
            report_lines.append("\n✅ **Status:** No dependency vulnerabilities were found.")

    # Dependency diff when we have 2+ branches
    if len(branches) >= 2:
        a_label = (branches[0] or "<default>")
        b_label = (branches[1] or "<default>")
        idx_a = index_osv_packages(per_branch_osv.get(a_label))
        idx_b = index_osv_packages(per_branch_osv.get(b_label))
        added, removed, changed = diff_dependency_indexes(idx_a, idx_b)

        report_lines.append(f"\n---\n## 🔀 Branch Dependency Diff ({a_label} ➜ {b_label})")
        report_lines.append("\n### ➕ Added (present only in target)")
        if added:
            for eco, name, ver in added:
                report_lines.append(f"- `{eco}` / **{name}** @ {ver}")
        else:
            report_lines.append("- None")

        report_lines.append("\n### ➖ Removed (present only in source)")
        if removed:
            for eco, name, ver in removed:
                report_lines.append(f"- `{eco}` / **{name}** @ {ver}")
        else:
            report_lines.append("- None")

        report_lines.append("\n### ⚠️ Vulnerability Changes (same package/version)")
        if changed:
            for row in changed:
                eco, name, ver = row['package']
                intro = ", ".join(row['introduced']) or "—"
                fixed = ", ".join(row['fixed']) or "—"
                report_lines.append(f"- `{eco}` / **{name}** @ {ver}  → introduced: {intro} | fixed: {fixed}")
        else:
            report_lines.append("- None")

    # Write report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"ai_repoguard_{timestamp}.md"
    with open(report_filename, "w") as report_file:
        report_file.write("\n".join(report_lines))
    print(f"\n✅ Scan complete! Unified report saved to {report_filename}")


if __name__ == "__main__":
    main()



# # 
# import os
# import argparse
# import tempfile
# import subprocess
# import json
# import shutil
# from collections import Counter
# from datetime import datetime

# # Local import from the new handler file
# from git_handler import clone_repository_from_env

# from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain_core.prompts import PromptTemplate
# from langchain_core.output_parsers import StrOutputParser
# from dotenv import load_dotenv



# # Load environment variables from .env file
# load_dotenv()


# def ensure_osv_scanner():
#     """
#     Checks if osv-scanner is installed. If not, attempts to install it via 'go install'.
#     Returns True on success, False on failure.
#     """
#     if shutil.which("osv-scanner"):
#         print("✅ OSV-Scanner is already installed.")
#         return True

#     print("⚠️ OSV-Scanner not found. Attempting to install via 'go install'...")
#     print("(This requires the Go programming language to be installed and configured correctly.)")
#     try:
#         install_command = [
#             "go", "install", "github.com/google/osv-scanner/cmd/osv-scanner@latest"
#         ]
#         subprocess.run(install_command, check=True, capture_output=True, text=True)
#         if shutil.which("osv-scanner"):
#             print("✅ OSV-Scanner installed successfully.")
#             return True
#         else:
#             print("❌ Installation seemed to succeed, but 'osv-scanner' is still not in the PATH.")
#             print("   Please ensure your Go bin directory (e.g., $GOPATH/bin) is in your system's PATH.")
#             return False
#     except FileNotFoundError:
#         print("❌ ERROR: The 'go' command was not found.")
#         print("   Please install the Go programming language first: https://go.dev/doc/install")
#         return False
#     except subprocess.CalledProcessError as e:
#         print(f"❌ ERROR: Failed to install OSV-Scanner. Return code: {e.returncode}")
#         print(f"   Stderr: {e.stderr}")
#         return False


# def get_llm():
#     """
#     Checks environment variables and returns the Gemini LLM instance.
#     """
#     google_key = os.getenv("GOOGLE_API_KEY")
#     if google_key:
#         print("🔑 Google API key found. Using Google Gemini model (gemini-2.5-flash).")
#         return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.2)
#     else:
#         raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


# def analyze_code(llm, file_content, file_name):
#     """
#     Uses the provided LLM and LangChain to analyze all file's content.
#     Produces a robust vulnerability report with enhanced output while preserving the original keys.
#     """
#     prompt = PromptTemplate(
#         input_variables=["file_name", "code"],
#         template_format="jinja2",
#         template="""
# Act as a senior application security engineer. Analyze the following code from '{{ file_name }}'.
# Perform a comprehensive and methodical analysis for common and less-common vulnerabilities.

# **Focus Areas (apply as relevant to the language/framework):**
# - **Injection:** SQL/NoSQL/Command/Shell injection, template injection, LDAP injection.
# - **Validation & Sanitization:** Improper input validation, insufficient output encoding (XSS, HTML/Markdown injection).
# - **Configuration & Secrets:** Hardcoded secrets (API keys, passwords, tokens), insecure storage, logging secrets, weak crypto.
# - **Access Control:** IDOR, missing authorization checks, privilege escalation, CSRF (where applicable).
# - **Deserialization & File Handling:** Insecure deserialization, unsafe file writes/reads, path traversal, SSRF.
# - **Remote Code Execution & OS Interactions:** Unsafely building commands, unsanitized `sh`/`exec`.
# - **Dependencies:** Use of vulnerable libraries or unpinned versions (flag only when evidence is clear).
# - **Cloud & CI/CD specifics:** For Jenkinsfiles/Groovy pipelines, check:
#   - Unsafe `sh` steps with interpolated variables.
#   - Missing `withCredentials` or misuse (secrets leaked via `echo` or environment exposure).
#   - Unpinned images/actions, overbroad permissions.
#   - Storing secrets in environment variables or SCM.
# - **Error Handling & Logging:** Sensitive data in logs; exception swallowing.
# - **Concurrency & Resource Management:** Race conditions; file handle/socket misuse.

# **Output Requirements:**
# Return a **valid JSON array**. Each item MUST include these keys (original requirement):
# - "line_number": 1-based line integer of the primary problematic location.
# - "vulnerability_type": short name (e.g., "SQL Injection", "XSS", "Hardcoded Secret").
# - "risk_explanation": concise explanation of why it’s insecure.
# - "suggested_fix": actionable guidance a developer can implement.

# You MAY also include these optional keys for enhanced reporting (recommended):
# - "severity": "High" | "Medium" | "Low"
# - "cwe": e.g., "CWE-89 (SQL Injection)"
# - "evidence": short code snippet or fragment
# - "references": array of relevant docs/links (e.g., OWASP pages)

# If you find no vulnerabilities, return an empty list: [].

# **Important Guidance:**
# 1) Be certain—avoid false positives.
# 2) Be detailed—explain why it’s vulnerable.
# 3) Be actionable—provide clear fixes (e.g., parameterized queries, escaping/encoding, least privilege).
# 4) Consider usage context (function, class, pipeline stage).
# 5) Infer language/framework from '{{ file_name }}' and code content (e.g., Jenkinsfile → Groovy + shell).
# 6) If the issue spans multiple lines, report the first line where the risky construct starts.

# **Code to Review**
# ```{{ code }}```
# """
#     )

#     chain = prompt | llm | StrOutputParser()
#     result = chain.invoke({"file_name": file_name, "code": file_content})
#     return result

# def run_osv_scanner(repo_path):
#     """Executes the OSV-Scanner tool on the repository path."""
#     print("\nRunning OSV-Scanner for dependencies...")
#     try:
#         result = subprocess.run(
#             ['osv-scanner', '--recursive', '--json', repo_path],
#             cwd=repo_path,
#             capture_output=True,
#             text=True,
#             check=False
#         )

#         if result.returncode not in (0, 1):
#             print(f"❌ OSV-Scanner encountered an error:\n{result.stderr}")
#             return None

#         if result.stderr.strip():
#             print(result.stderr)

#         if not result.stdout.strip():
#             print("✅ OSV-Scanner ran successfully and found no vulnerabilities.")
#             return None

#         return json.loads(result.stdout)

#     except FileNotFoundError:
#         print("❌ ERROR: 'osv-scanner' command not found. Please install it or add to PATH.")
#         return None
#     except json.JSONDecodeError:
#         print("❌ ERROR: Could not parse OSV-Scanner JSON output.")
#         return None

# def get_severity(vuln_type):
#     """Assigns a severity level to a vulnerability type."""
#     vuln_type = vuln_type.lower()
#     if "injection" in vuln_type:
#         return "🔴 Critical"
#     elif "secret" in vuln_type or "privileged" in vuln_type:
#         return "🟠 High"
#     else:
#         return "🟡 Medium"


# def main():
#     if not ensure_osv_scanner():
#         print("\nHalting script because OSV-Scanner is not available.")
#         return

#     parser = argparse.ArgumentParser(description="Hybrid AI & Dependency Security Scanner")
#     parser.add_argument("--repo_url", required=True, help="URL of the Git repository to scan")
#     args = parser.parse_args()

#     try:
#         llm = get_llm()
#     except ValueError as e:
#         print(f"Error: {e}")
#         return

#     ai_findings = []

#     with tempfile.TemporaryDirectory() as temp_dir:
#         # --- MODIFIED: Use the new cloning handler ---
#         clone_successful = clone_repository_from_env(args.repo_url, temp_dir)
        
#         # If cloning failed, stop the script.
#         if not clone_successful:
#             print("\nScan aborted due to cloning failure.")
#             return

#         osv_results = run_osv_scanner(temp_dir)

#         print("\nStarting AI source code scan...")
#         for subdir, _, files in os.walk(temp_dir):
#             if ".git" in subdir:
#                 continue
#             for file in files:
#                 if file.endswith(('.py', '.js', '.java', '.go', '.rb', 'ts', '.tf', '.sh', '.yml', '.yaml', 'Dockerfile', 'Jenkinsfile')):
#                     file_path = os.path.join(subdir, file)
#                     relative_path = os.path.relpath(file_path, temp_dir)

#                     print(f"Scanning file: {relative_path}")
#                     try:
#                         with open(file_path, 'r', errors='ignore') as f:
#                             content = f.read()
#                             if len(content.strip()) == 0 or len(content) > 50000:
#                                 continue
                            
#                             analysis_result = analyze_code(llm, content, relative_path)
                            
#                             cleaned_json_str = analysis_result.strip()
#                             if cleaned_json_str.startswith("```json"):
#                                 cleaned_json_str = cleaned_json_str[7:]
#                             if cleaned_json_str.endswith("```"):
#                                 cleaned_json_str = cleaned_json_str[:-3]
#                             cleaned_json_str = cleaned_json_str.strip()

#                             try:
#                                 if cleaned_json_str:
#                                     vulnerabilities = json.loads(cleaned_json_str)
#                                     if isinstance(vulnerabilities, list) and vulnerabilities:
#                                         for vuln in vulnerabilities:
#                                             vuln['file_path'] = relative_path
#                                             ai_findings.append(vuln)
#                             except json.JSONDecodeError:
#                                 print(f"  └─ ⚠️ WARNING: AI returned non-JSON output for this file. Skipping.")
                    
#                     except Exception as e:
#                         print(f"  └─ ❌ ERROR: Could not process file {relative_path}: {e}")

#     # --- Full Report Generation Logic ---
#     report_lines = []
#     scan_date = datetime.now().strftime("%B %d, %Y")

#     report_lines.append("# 🛡️ Security Scan Report")
#     report_lines.append(f"\n**Repository:** `{args.repo_url}`")
#     report_lines.append(f"**Scan Date:** {scan_date}")
#     report_lines.append("\n---")
#     report_lines.append("## 📊 Executive Summary")
    
#     total_vulns = len(ai_findings)
#     dep_vulns = 0
#     if osv_results and osv_results.get('results'):
#         for result in osv_results['results']:
#             for package in result.get('packages', []):
#                 dep_vulns += len(package.get('vulnerabilities', []))
#     total_vulns += dep_vulns

#     if total_vulns == 0:
#         report_lines.append("\n✅ **Excellent!** No security vulnerabilities were found in the source code or dependencies.")
#     else:
#         report_lines.append(f"\nThe scan identified a total of **{total_vulns} vulnerabilities.**")

#     if ai_findings:
#         report_lines.append("\n### Vulnerability Overview")
#         report_lines.append("\n| Severity | Vulnerability Type | File Location |")
#         report_lines.append("| :--- | :--- | :--- |")
#         for vuln in sorted(ai_findings, key=lambda x: get_severity(x.get('vulnerability_type', '')), reverse=True):
#             severity = get_severity(vuln.get('vulnerability_type', ''))
#             vuln_type = vuln.get('vulnerability_type', 'Unknown')
#             location = f"`{vuln['file_path']}`"
#             report_lines.append(f"| {severity} | {vuln_type} | {location} |")
#         report_lines.append("\n### Vulnerability Distribution Chart")
#         report_lines.append("\n```mermaid")
#         report_lines.append("pie title Source Code Vulnerability Distribution")
#         vuln_counts = Counter(v.get('vulnerability_type', 'Unknown') for v in ai_findings)
#         for vuln_type, count in vuln_counts.items():
#             report_lines.append(f'    "{vuln_type}" : {count}')
#         report_lines.append("```")
    
#     report_lines.append("\n---")
#     report_lines.append("\n## 📦 Dependency Vulnerabilities (from OSV-Scanner)")
#     if osv_results and osv_results.get('results'):
#         for result in osv_results['results']:
#             source = result['source']['path']
#             report_lines.append(f"\n### File: `{source}`")
#             for package in result['packages']:
#                 for vuln in package['vulnerabilities']:
#                     report_lines.append(f"- **ID:** {vuln['id']}")
#                     report_lines.append(f"  - **Package:** {package['package']['name']}")
#                     report_lines.append(f"  - **Summary:** {vuln.get('summary', 'No summary provided.')}")
#     else:
#         report_lines.append("\n✅ **Status:** No dependency vulnerabilities were found.")
    
#     report_lines.append("\n\n---\n")
#     report_lines.append("## 📝 Source Code Vulnerabilities (from AI Scan)")
#     if not ai_findings:
#         report_lines.append("\n✅ **Status:** The AI scan found no source code vulnerabilities.")
#     else:
#         report_lines.append("\nBelow is a detailed breakdown of each vulnerability found in the source code.")
#         findings_by_file = {}
#         for finding in ai_findings:
#             if finding['file_path'] not in findings_by_file:
#                 findings_by_file[finding['file_path']] = []
#             findings_by_file[finding['file_path']].append(finding)
#         for file_path, vulnerabilities in findings_by_file.items():
#             report_lines.append(f"\n### 📄 File: `{file_path}`")
#             for vuln in vulnerabilities:
#                 severity = get_severity(vuln.get('vulnerability_type', ''))
#                 report_lines.append(f"\n#### **Vulnerability: {vuln.get('vulnerability_type', 'Unknown')}**")
#                 report_lines.append(f"- **Severity:** {severity}")
#                 report_lines.append(f"- **Line:** {vuln.get('line_number', 'N/A')}")
#                 report_lines.append("\n**🚨 Risk:**")
#                 report_lines.append(vuln.get('risk_explanation', 'No details provided.'))
#                 report_lines.append("\n**✅ Recommendation:**")
#                 suggested_fix = vuln.get('suggested_fix', 'No fix suggested.')
#                 if "```" in suggested_fix:
#                     report_lines.append("Example Fix:")
#                     report_lines.append(f"{suggested_fix}")
#                 else:
#                     report_lines.append(suggested_fix)
#                 report_lines.append("<br>")
    
#     timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#     report_filename = f"ai_repoguard_{timestamp}.md"
    
#     with open(report_filename, "w") as report_file:
#         report_file.write("\n".join(report_lines))
    
#     print(f"\n✅ Scan complete! Unified report saved to {report_filename}")


# if __name__ == "__main__":
#     main()
