import os
import argparse
import tempfile
import subprocess
import json
import shutil
from collections import Counter
from datetime import datetime

# Local import from the new handler file
from git_handler import clone_repository_from_env #clone_repository  

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
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
        return ChatGoogleGenerativeAI(model="gemini-2.5-flash-preview-05-20", temperature=0.1)
    else:
        raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


def analyze_code(llm, file_content, file_name):
    """Uses the provided LLM and LangChain to analyze a single file's content."""
    prompt = PromptTemplate(
        input_variables=["file_name", "code"],
        template="""
        Act as an expert security code reviewer.
        Analyze the following code from the file '{file_name}'.
        Identify potential security vulnerabilities such as SQL injection, XSS, hardcoded secrets,
        insecure deserialization, or command injection.

        For each vulnerability you find, provide a JSON object with the keys:
        "line_number", "vulnerability_type", "risk_explanation", and "suggested_fix".

        If you find no vulnerabilities, return an empty list [].

        CODE:
        ```
        {code}
        ```

        YOUR JSON RESPONSE (must be a valid JSON list inside a json markdown block):
        """
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

def get_severity(vuln_type):
    """Assigns a severity level to a vulnerability type."""
    vuln_type = vuln_type.lower()
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

    parser = argparse.ArgumentParser(description="Hybrid AI & Dependency Security Scanner")
    parser.add_argument("--repo_url", required=True, help="URL of the Git repository to scan")
    args = parser.parse_args()

    try:
        llm = get_llm()
    except ValueError as e:
        print(f"Error: {e}")
        return

    ai_findings = []

    with tempfile.TemporaryDirectory() as temp_dir:
        # --- MODIFIED: Use the new cloning handler ---
        clone_successful = clone_repository_from_env(args.repo_url, temp_dir)
        
        # If cloning failed, stop the script.
        if not clone_successful:
            print("\nScan aborted due to cloning failure.")
            return

        osv_results = run_osv_scanner(temp_dir)

        print("\nStarting AI source code scan...")
        for subdir, _, files in os.walk(temp_dir):
            if ".git" in subdir:
                continue
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.go', '.rb', 'ts', '.tf', '.sh', '.yml', '.yaml', 'Dockerfile', 'Jenkinsfile')):
                    file_path = os.path.join(subdir, file)
                    relative_path = os.path.relpath(file_path, temp_dir)

                    print(f"Scanning file: {relative_path}")
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

                            try:
                                if cleaned_json_str:
                                    vulnerabilities = json.loads(cleaned_json_str)
                                    if isinstance(vulnerabilities, list) and vulnerabilities:
                                        for vuln in vulnerabilities:
                                            vuln['file_path'] = relative_path
                                            ai_findings.append(vuln)
                            except json.JSONDecodeError:
                                print(f"  └─ ⚠️ WARNING: AI returned non-JSON output for this file. Skipping.")
                    
                    except Exception as e:
                        print(f"  └─ ❌ ERROR: Could not process file {relative_path}: {e}")

    # --- Full Report Generation Logic ---
    report_lines = []
    scan_date = datetime.now().strftime("%B %d, %Y")

    report_lines.append("# 🛡️ Security Scan Report")
    report_lines.append(f"\n**Repository:** `{args.repo_url}`")
    report_lines.append(f"**Scan Date:** {scan_date}")
    report_lines.append("\n---")
    report_lines.append("## 📊 Executive Summary")
    
    total_vulns = len(ai_findings)
    dep_vulns = 0
    if osv_results and osv_results.get('results'):
        for result in osv_results['results']:
            for package in result.get('packages', []):
                dep_vulns += len(package.get('vulnerabilities', []))
    total_vulns += dep_vulns

    if total_vulns == 0:
        report_lines.append("\n✅ **Excellent!** No security vulnerabilities were found in the source code or dependencies.")
    else:
        report_lines.append(f"\nThe scan identified a total of **{total_vulns} vulnerabilities.**")

    if ai_findings:
        report_lines.append("\n### Vulnerability Overview")
        report_lines.append("\n| Severity | Vulnerability Type | File Location |")
        report_lines.append("| :--- | :--- | :--- |")
        for vuln in sorted(ai_findings, key=lambda x: get_severity(x.get('vulnerability_type', '')), reverse=True):
            severity = get_severity(vuln.get('vulnerability_type', ''))
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            location = f"`{vuln['file_path']}`"
            report_lines.append(f"| {severity} | {vuln_type} | {location} |")
        report_lines.append("\n### Vulnerability Distribution Chart")
        report_lines.append("\n```mermaid")
        report_lines.append("pie title Source Code Vulnerability Distribution")
        vuln_counts = Counter(v.get('vulnerability_type', 'Unknown') for v in ai_findings)
        for vuln_type, count in vuln_counts.items():
            report_lines.append(f'    "{vuln_type}" : {count}')
        report_lines.append("```")
    
    report_lines.append("\n---")
    report_lines.append("\n## 📦 Dependency Vulnerabilities (from OSV-Scanner)")
    if osv_results and osv_results.get('results'):
        for result in osv_results['results']:
            source = result['source']['path']
            report_lines.append(f"\n### File: `{source}`")
            for package in result['packages']:
                for vuln in package['vulnerabilities']:
                    report_lines.append(f"- **ID:** {vuln['id']}")
                    report_lines.append(f"  - **Package:** {package['package']['name']}")
                    report_lines.append(f"  - **Summary:** {vuln.get('summary', 'No summary provided.')}")
    else:
        report_lines.append("\n✅ **Status:** No dependency vulnerabilities were found.")
    
    report_lines.append("\n\n---\n")
    report_lines.append("## 📝 Source Code Vulnerabilities (from AI Scan)")
    if not ai_findings:
        report_lines.append("\n✅ **Status:** The AI scan found no source code vulnerabilities.")
    else:
        report_lines.append("\nBelow is a detailed breakdown of each vulnerability found in the source code.")
        findings_by_file = {}
        for finding in ai_findings:
            if finding['file_path'] not in findings_by_file:
                findings_by_file[finding['file_path']] = []
            findings_by_file[finding['file_path']].append(finding)
        for file_path, vulnerabilities in findings_by_file.items():
            report_lines.append(f"\n### 📄 File: `{file_path}`")
            for vuln in vulnerabilities:
                severity = get_severity(vuln.get('vulnerability_type', ''))
                report_lines.append(f"\n#### **Vulnerability: {vuln.get('vulnerability_type', 'Unknown')}**")
                report_lines.append(f"- **Severity:** {severity}")
                report_lines.append(f"- **Line:** {vuln.get('line_number', 'N/A')}")
                report_lines.append("\n**🚨 Risk:**")
                report_lines.append(vuln.get('risk_explanation', 'No details provided.'))
                report_lines.append("\n**✅ Recommendation:**")
                suggested_fix = vuln.get('suggested_fix', 'No fix suggested.')
                if "```" in suggested_fix:
                    report_lines.append("Example Fix:")
                    report_lines.append(f"{suggested_fix}")
                else:
                    report_lines.append(suggested_fix)
                report_lines.append("<br>")
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"ai_repoguard_{timestamp}.md"
    
    with open(report_filename, "w") as report_file:
        report_file.write("\n".join(report_lines))
    
    print(f"\n✅ Scan complete! Unified report saved to {report_filename}")


if __name__ == "__main__":
    main()

# import os
# import argparse
# import tempfile
# import subprocess
# import json
# import shutil
# from git import Repo
# from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain.prompts import PromptTemplate
# from langchain_core.output_parsers import StrOutputParser
# from dotenv import load_dotenv
# from collections import Counter
# from datetime import datetime

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
#         return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)
#     else:
#         raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


# def analyze_code(llm, file_content, file_name):
#     """Uses the provided LLM and LangChain to analyze a single file's content."""
#     prompt = PromptTemplate(
#         input_variables=["file_name", "code"],
#         template="""
#         Act as an expert security code reviewer.
#         Analyze the following code from the file '{file_name}'.
#         Identify potential security vulnerabilities such as SQL injection, XSS, hardcoded secrets,
#         insecure deserialization, or command injection.

#         For each vulnerability you find, provide a JSON object with the keys:
#         "line_number", "vulnerability_type", "risk_explanation", and "suggested_fix".

#         If you find no vulnerabilities, return an empty list [].

#         CODE:
#         ```
#         {code}
#         ```

#         YOUR JSON RESPONSE (must be a valid JSON list inside a json markdown block):
#         """
#     )
    
#     # Use the newer LangChain Expression Language (LCEL) syntax
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

#         # OSV-Scanner exit codes: 0 → no vulns, 1 → vulns found, >1 → actual error
#         if result.returncode not in (0, 1):
#             print(f"❌ OSV-Scanner encountered an error:\n{result.stderr}")
#             return None

#         # Optional: print log for info/debugging
#         if result.stderr.strip():
#             print(result.stderr)

#         # Parse and return JSON output after the scan
#         if not result.stdout.strip():
#             print("⚠️ No JSON output from OSV-Scanner — possibly no supported manifests.")
#             return None

#         print("✅ OSV-Scanner completed successfully.\n")  # Log after completion
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
#         print(f"Cloning {args.repo_url} into {temp_dir}...")
#         Repo.clone_from(args.repo_url, temp_dir)
#         print("Clone complete.")

#         osv_results = run_osv_scanner(temp_dir)

#         print("\nStarting AI source code scan...")
#         for subdir, _, files in os.walk(temp_dir):
#             # Ignore .git directory and other common non-source files
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
                            
#                             # ROBUST JSON CLEANING AND PARSING BLOCK
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

#     # --- Generate the Formatted Report ---
#     report_lines = []
#     scan_date = datetime.now().strftime("%B %d, %Y")
#     report_lines.append("# 🛡️ Security Scan Report")
#     report_lines.append(f"\n**Repository:** `{args.repo_url}`")
#     report_lines.append(f"**Scan Date:** {scan_date}")
#     report_lines.append("\n---")
#     report_lines.append("## 📊 Executive Summary")
#     if not ai_findings:
#         report_lines.append("\n✅ The scan identified **0 vulnerabilities** within the source code.")
#     else:
#         report_lines.append(f"\nThe scan identified a total of **{len(ai_findings)} vulnerabilities** within the source code.")
    
#     if not (osv_results and osv_results.get('results')):
#         report_lines.append("No vulnerabilities were found in the project's third-party dependencies.")

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
#         report_lines.append("pie title Vulnerability Distribution")
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
#                     report_lines.append(f"  - **Summary:** {vuln['summary']}")
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
    
#     # DYNAMIC FILENAME GENERATION
#     timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#     report_filename = f"ai_repoguard_{timestamp}.md"
    
#     with open(report_filename, "w") as report_file:
#         report_file.write("\n".join(report_lines))
    
#     print(f"\n✅ Scan complete! Unified report saved to {report_filename}")

# if __name__ == "__main__":
#     main()


