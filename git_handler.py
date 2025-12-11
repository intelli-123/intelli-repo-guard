# git_handler.py


import os
import urllib.parse
from typing import Optional, Tuple, List
from git import Repo, exc


def get_scan_branches_from_env() -> List[str]:
    """
    Read SCAN_BRANCHES from .env as a comma-separated list.
    Returns [] if not set.

    Example:
      SCAN_BRANCHES=main,develop,release
    """
    raw = os.getenv("SCAN_BRANCHES", "").strip()
    if not raw:
        return []
    return [b.strip() for b in raw.split(",") if b.strip()]


def _detect_provider_from_url(repo_url: str) -> Optional[str]:
    """
    Infer provider from the repo URL hostname if GIT_PROVIDER is not set.
    """
    try:
        host = urllib.parse.urlparse(repo_url).netloc.lower()
    except Exception:
        return None

    if "github.com" in host:
        return "github"
    if "gitlab.com" in host:
        return "gitlab"
    if "bitbucket.org" in host:
        return "bitbucket"
    return None


def _get_auth_credentials(provider_env: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (provider, username, token) from env. If provider is None, try to detect later.
    """
    provider = provider_env or os.getenv("GIT_PROVIDER")
    username = os.getenv("GIT_USERNAME")
    token = None

    if provider == "github":
        token = os.getenv("GITHUB_TOKEN")
    elif provider == "gitlab":
        token = os.getenv("GITLAB_TOKEN")
    elif provider == "bitbucket":
        token = os.getenv("BITBUCKET_APP_PASSWORD")

    return provider, username, token


def _build_authenticated_url(repo_url: str, username: str, token: str) -> str:
    """
    Build https://<user>:<token>@host/path URL with proper URL-encoding.
    """
    parsed = urllib.parse.urlparse(repo_url)
    safe_user = urllib.parse.quote(username or "")
    safe_token = urllib.parse.quote(token or "")
    return f"{parsed.scheme}://{safe_user}:{safe_token}@{parsed.netloc}{parsed.path}"


def _clone_internal(
    url: str,
    temp_dir: str,
    branch: Optional[str] = None,
    single_branch: bool = False
) -> Optional[Repo]:
    """
    Try to clone using GitPython. Returns Repo on success, None on failure.
    - Uses branch=... to checkout during clone when available.
    - Optionally uses --single-branch optimization.
    """
    try:
        kwargs = {}
        if branch:
            kwargs["branch"] = branch  # maps to: git clone -b <branch>  # [1](https://stackoverflow.com/questions/43520843/how-to-clone-from-specific-branch-from-git-using-gitpython)
        if single_branch:
            # GitPython forwards 'single_branch=True' to 'git clone --single-branch'
            kwargs["single_branch"] = True

        print(f"→ git clone {url} into {temp_dir}" + (f" [branch={branch}]" if branch else ""))
        repo = Repo.clone_from(url, temp_dir, **kwargs)
        # Safety: Some GitPython setups may not checkout the branch as expected. Ensure checkout post-clone.
        if branch:
            try:
                repo.git.checkout(branch)  # explicit checkout if needed  # [2](https://stackoverflow.com/questions/47872070/how-to-check-out-a-branch-with-gitpython)
            except exc.GitCommandError:
                # If checkout fails (branch not found), we keep the current HEAD and warn.
                print(f"⚠️ WARN: Could not checkout branch '{branch}' after clone. Proceeding on default HEAD.")
        print("✅ Clone complete.")
        return repo
    except exc.GitCommandError as e:
        print(f"❌ ERROR: git clone failed.\n   Git Error: {e}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Unexpected failure during clone: {e}")
        return None


def clone_repository_from_env(
    repo_url: str,
    temp_dir: str,
    branch: Optional[str] = None,
    single_branch: bool = False
) -> bool:
    """
    Clone a Git repository with smart handling of public/private/branch scenarios.

    Logic:
      1) If IS_PUBLIC_REPO=true → try unauthenticated clone first; on failure, fallback to authenticated if credentials exist.
      2) If IS_PUBLIC_REPO=false → try authenticated clone first; on failure, fallback to unauthenticated (repo might be public).
      3) If GIT_PROVIDER or credentials are missing but required, print helpful diagnostics.

    Args:
        repo_url: Remote repository URL (https://host/org/repo.git)
        temp_dir: Local directory to clone into
        branch: Optional branch to checkout at/after clone
        single_branch: If True, pass --single-branch for performance

    Returns:
        True if cloned successfully; False otherwise.
    """

    # Normalize env inputs
    is_public_env = os.getenv("IS_PUBLIC_REPO", "true").strip().lower() == "true"
    provider_env = os.getenv("GIT_PROVIDER")

    # Derive provider from URL if not in env (best-effort)
    provider_detected = _detect_provider_from_url(repo_url)
    provider, username, token = _get_auth_credentials(provider_env or provider_detected)

    # Prepare sanitized username (avoid spaces, trim)
    if username:
        username = username.strip()
    # For tokens, just ensure presence; we will URL-encode in builder.

    # Decide strategy order
    try_auth_first = not is_public_env  # if marked private → prefer auth first

    # CASE A: Try unauthenticated first (marked public)
    if not try_auth_first:
        print("🔓 Public repo mode (IS_PUBLIC_REPO=true): attempting unauthenticated clone...")
        repo = _clone_internal(repo_url, temp_dir, branch=branch, single_branch=single_branch)
        if repo:
            return True

        # Fallback to authenticated if credentials exist
        if provider and username and token:
            print("🔑 Unauth clone failed; attempting authenticated clone with provided credentials...")
            authed_url = _build_authenticated_url(repo_url, username, token)
            repo = _clone_internal(authed_url, temp_dir, branch=branch, single_branch=single_branch)
            if repo:
                print("✅ Authenticated clone succeeded (repo might be private or requires auth).")
                return True
            else:
                print("❌ ERROR: Authenticated clone also failed. Check credentials/permissions/repo URL.")
                return False
        else:
            print("❌ ERROR: No valid credentials in env to fallback (GIT_PROVIDER/GIT_USERNAME/<TOKEN>).")
            return False

    # CASE B: Try authenticated first (marked private)
    print("\n🔐 Private repo mode (IS_PUBLIC_REPO=false): attempting authenticated clone...")
    if not provider or not username or not token:
        print("⚠️ WARN: Missing credentials for private clone.")
        print("   Required: GIT_PROVIDER, GIT_USERNAME, and provider-specific token (GITHUB_TOKEN/GITLAB_TOKEN/BITBUCKET_APP_PASSWORD).")
        print("   Falling back to unauthenticated attempt (repo might be public).")

        repo = _clone_internal(repo_url, temp_dir, branch=branch, single_branch=single_branch)
        if repo:
            print("✅ Unauthenticated clone succeeded. Repo appears to be PUBLIC.")
            print("   Consider setting IS_PUBLIC_REPO=true to skip auth.")
            return True
        else:
            print("❌ ERROR: Unauthenticated clone failed and credentials are missing. Cannot proceed.")
            return False

    # Have credentials → do authenticated attempt
    authed_url = _build_authenticated_url(repo_url, username, token)
    repo = _clone_internal(authed_url, temp_dir, branch=branch, single_branch=single_branch)
    if repo:
        return True

    # Auth failed → try unauthenticated (maybe the repo is public)
    print("⚠️ WARN: Authenticated clone failed. Trying unauthenticated clone in case the repo is PUBLIC...")
    repo = _clone_internal(repo_url, temp_dir, branch=branch, single_branch=single_branch)
    if repo:
        print("✅ Unauthenticated clone succeeded. Repo appears to be PUBLIC.")


# import os
# import urllib.parse
# from git import Repo, exc

# def clone_repository_from_env(repo_url, temp_dir):
#     """
#     Clones a Git repository using configuration from environment variables.

#     Args:
#         repo_url (str): The URL of the repository to clone.
#         temp_dir (str): The local temporary directory to clone into.

#     Returns:
#         bool: True if cloning was successful, False otherwise.
#     """
#     # Default to public if the variable is not set
#     is_public = os.getenv("IS_PUBLIC_REPO", "true").lower() == 'true'

#     if is_public:
#         try:
#             print(f"Cloning public repository {repo_url} into {temp_dir}...")
#             Repo.clone_from(repo_url, temp_dir)
#             print("✅ Clone complete.")
#             return True
#         except exc.GitCommandError as e:
#             print(f"❌ ERROR: Failed to clone public repository. It might be private or the URL is incorrect.")
#             print(f"   Git Error: {e}")
#             return False
#     else: # Private repository logic
#         print("\n--- Private Repository Authentication (from .env) ---")
#         provider = os.getenv("GIT_PROVIDER")
#         username = os.getenv("GIT_USERNAME")
#         token = None

#         if not provider or not username:
#             print("❌ ERROR: For private repos, GIT_PROVIDER and GIT_USERNAME must be set in your .env file.")
#             return False

#         # Get the correct token based on the provider
#         if provider == "github":
#             token = os.getenv("GITHUB_TOKEN")
#         elif provider == "gitlab":
#             token = os.getenv("GITLAB_TOKEN")
#         elif provider == "bitbucket":
#             token = os.getenv("BITBUCKET_APP_PASSWORD")
        
#         if not token:
#             print(f"❌ ERROR: Token for provider '{provider}' not found in .env file.")
#             print("   Please set GITHUB_TOKEN, GITLAB_TOKEN, or BITBUCKET_APP_PASSWORD.")
#             return False

#         # Construct the authenticated clone URL
#         parsed_url = urllib.parse.urlparse(repo_url)
#         clone_url_with_creds = f"{parsed_url.scheme}://{urllib.parse.quote(username)}:{urllib.parse.quote(token)}@{parsed_url.netloc}{parsed_url.path}"

#         try:
#             print(f"Attempting to clone private repository as '{username}'...")
#             Repo.clone_from(clone_url_with_creds, temp_dir)
#             print("✅ Clone complete.")
#             return True
#         except exc.GitCommandError as e:
#             print(f"❌ ERROR: Failed to clone private repository. Please check your credentials, permissions, and repository URL.")
#             print(f"   Git Error: {e}")
#             return False

