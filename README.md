# 🛡️ AI-Repoguard: Hybrid Security Scanner
```
##⚠️ Disclaimer

This tool utilizes a Large Language Model (LLM) to identify potential security risks. While it is highly capable, AI can produce false positives
or miss complex, multi-file vulnerabilities. This tool is meant to assist developers and security researchers, not to replace professional
security audits or dedicated SAST/DAST enterprise software.
```
# 1. Overview

AI-Repoguard is a powerful, command-line security auditing tool that provides a comprehensive analysis of Git repositories. It combines two critical security methodologies:

AI-Powered SAST (Static Application Security Testing): Utilizes Google's Gemini Large Language Model to perform an intelligent scan of your source code, identifying potential vulnerabilities, logical flaws, and security misconfigurations.

SCA (Software Composition Analysis): Integrates Google's OSV-Scanner to analyze your project's third-party dependencies for known, published vulnerabilities.

The tool is designed for developers and DevOps teams to automate security checks, either on-demand or as part of a CI/CD pipeline. It produces a single, easy-to-read Markdown report detailing all findings.

# 2. Features

Hybrid Analysis: Combines AI source code scanning with dependency vulnerability checking for holistic security coverage.

Automated & Non-Interactive: Clones repositories and runs scans without requiring user input, making it ideal for automation.

Multi-Provider Git Support: Securely clones both public and private repositories from GitHub, GitLab, and Bitbucket using environment variables.

Auto-Installation: Automatically checks for and installs the osv-scanner dependency if it's not found (requires Go to be installed).

Detailed Markdown Reports: Generates a timestamped, well-formatted report for each scan, complete with an executive summary, vulnerability distribution charts, and actionable recommendations.

Extensible: Easily configured to scan a wide variety of source code files and configuration formats.

# 3. Installation & Setup

Step 1: Clone the Project
git clone <your-project-repo-url>
cd ai_repoguard

Step 2: Install Python Dependencies
Ensure you have Python 3.8+ installed.

pip install -r requirements.txt

Step 3: Install Go (Prerequisite for OSV-Scanner)
The script requires the Go programming language to be installed to automatically manage osv-scanner. If you don't have it, install it from the official site: https://go.dev/doc/install

After installation, ensure your Go bin directory is in your system's PATH.

# 4. Configuration (.env file)
The entire tool is configured via a .env file in the root of the project. Create this file before running a scan.

---

Example 1: Scanning a Public Repository
Set IS_PUBLIC_REPO to true.

.env for a public repository

GOOGLE_API_KEY="your-google-api-key-goes-here"
IS_PUBLIC_REPO=true

---

Example 2: Scanning a Private GitHub Repository
Set IS_PUBLIC_REPO to false and provide your GitHub credentials.

.env for a private GitHub repository

GOOGLE_API_KEY="your-google-api-key-goes-here"

IS_PUBLIC_REPO=false

GIT_PROVIDER=github

GIT_USERNAME=your-github-username

GITHUB_TOKEN=ghp_YourPersonalAccessTokenGoesHere

# 5. How to Run a Scan
Execute the main script from your terminal, providing the URL of the repository you wish to scan.

python repoguard_v2.py --repo_url [https://github.com/some-user/some-repo.git](https://github.com/some-user/some-repo.git)

The script will begin the cloning and scanning process, and you will see the progress logged to your console.

# 6. Output
Upon completion, a new Markdown file will be generated in your project directory with a timestamped filename, for example: ai_repoguard_2025-10-14_16-45-00.md.

This report will contain a full summary and a detailed breakdown of all vulnerabilities found.

# 7. Git Handler Module (git_handler.py)
The project includes a dedicated module, git_handler.py, for all repository cloning operations. It is designed to be non-interactive and is controlled entirely by the environment variables detailed in the configuration section above.
