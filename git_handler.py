import os
import urllib.parse
from git import Repo, exc

def clone_repository_from_env(repo_url, temp_dir):
    """
    Clones a Git repository using configuration from environment variables.

    Args:
        repo_url (str): The URL of the repository to clone.
        temp_dir (str): The local temporary directory to clone into.

    Returns:
        bool: True if cloning was successful, False otherwise.
    """
    # Default to public if the variable is not set
    is_public = os.getenv("IS_PUBLIC_REPO", "true").lower() == 'true'

    if is_public:
        try:
            print(f"Cloning public repository {repo_url} into {temp_dir}...")
            Repo.clone_from(repo_url, temp_dir)
            print("✅ Clone complete.")
            return True
        except exc.GitCommandError as e:
            print(f"❌ ERROR: Failed to clone public repository. It might be private or the URL is incorrect.")
            print(f"   Git Error: {e}")
            return False
    else: # Private repository logic
        print("\n--- Private Repository Authentication (from .env) ---")
        provider = os.getenv("GIT_PROVIDER")
        username = os.getenv("GIT_USERNAME")
        token = None

        if not provider or not username:
            print("❌ ERROR: For private repos, GIT_PROVIDER and GIT_USERNAME must be set in your .env file.")
            return False

        # Get the correct token based on the provider
        if provider == "github":
            token = os.getenv("GITHUB_TOKEN")
        elif provider == "gitlab":
            token = os.getenv("GITLAB_TOKEN")
        elif provider == "bitbucket":
            token = os.getenv("BITBUCKET_APP_PASSWORD")
        
        if not token:
            print(f"❌ ERROR: Token for provider '{provider}' not found in .env file.")
            print("   Please set GITHUB_TOKEN, GITLAB_TOKEN, or BITBUCKET_APP_PASSWORD.")
            return False

        # Construct the authenticated clone URL
        parsed_url = urllib.parse.urlparse(repo_url)
        clone_url_with_creds = f"{parsed_url.scheme}://{urllib.parse.quote(username)}:{urllib.parse.quote(token)}@{parsed_url.netloc}{parsed_url.path}"

        try:
            print(f"Attempting to clone private repository as '{username}'...")
            Repo.clone_from(clone_url_with_creds, temp_dir)
            print("✅ Clone complete.")
            return True
        except exc.GitCommandError as e:
            print(f"❌ ERROR: Failed to clone private repository. Please check your credentials, permissions, and repository URL.")
            print(f"   Git Error: {e}")
            return False

