"""GitHub API client for code search and retrieval."""

import asyncio
import base64
import fnmatch
import re
import time
from typing import Optional
from urllib.parse import quote

import httpx

from ..utils.errors import GitHubAPIError, RateLimitError
from ..utils.logging import get_logger

logger = get_logger("github_client")


class GitHubClient:
    """Async HTTP client for GitHub REST API v3."""
    
    def __init__(self, token: str, base_url: str = "https://api.github.com"):
        """
        Initialize GitHub client.
        
        Args:
            token: GitHub personal access token
            base_url: GitHub API base URL (default: https://api.github.com)
        """
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=30.0,
        )
        self.last_request_time = 0.0
        self.min_request_interval = 3.0  # Seconds between search requests (more conservative)
        
        # Search API rate limiting (30 requests/minute limit)
        self.search_requests_this_minute = 0
        self.search_minute_start = time.time()
        self.search_cache: dict = {}  # Cache recent search results
    
    async def _wait_for_rate_limit(self):
        """Wait to respect rate limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    async def _wait_for_search_rate_limit(self):
        """Wait to respect Search API rate limits (30 requests/minute)."""
        now = time.time()
        
        # Reset counter if minute has passed
        if now - self.search_minute_start > 60:
            self.search_requests_this_minute = 0
            self.search_minute_start = now
        
        # If approaching limit, wait for the minute to reset
        if self.search_requests_this_minute >= 25:  # Leave 5 request buffer
            wait_time = 60 - (now - self.search_minute_start) + 1
            logger.warning(f"Search API rate limit approaching ({self.search_requests_this_minute}/30), waiting {wait_time:.0f}s")
            await asyncio.sleep(wait_time)
            self.search_requests_this_minute = 0
            self.search_minute_start = time.time()
        
        # Also respect per-request interval
        await self._wait_for_rate_limit()
        
        self.search_requests_this_minute += 1
    
    async def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """
        Make an API request with error handling.
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional arguments for httpx
        
        Returns:
            Response object
        
        Raises:
            RateLimitError: If rate limit is exceeded
            GitHubAPIError: For other API errors
        """
        try:
            response = await self.client.request(method, url, **kwargs)
            
            # Check rate limit headers
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining and int(remaining) < 10:
                logger.warning(f"GitHub API rate limit low: {remaining} remaining")
            
            # Handle rate limit exceeded
            if response.status_code == 403:
                reset_time = response.headers.get("X-RateLimit-Reset")
                if reset_time:
                    wait_time = int(reset_time) - int(time.time())
                    raise RateLimitError(
                        f"GitHub API rate limit exceeded. Resets in {wait_time} seconds."
                    )
            
            # Raise for other errors
            response.raise_for_status()
            
            return response
        
        except httpx.HTTPStatusError as e:
            raise GitHubAPIError(f"GitHub API error: {e.response.status_code} - {e.response.text}")
        except httpx.RequestError as e:
            raise GitHubAPIError(f"GitHub API request failed: {str(e)}")
    
    async def search_code(
        self,
        query: str,
        repo: Optional[str] = None,
        max_results: int = 50,
    ) -> dict:
        """
        Search code using GitHub Search API.
        
        Note: Search API has strict rate limit of 30 requests/minute.
        
        Args:
            query: Search query
            repo: Optional repository filter (owner/name)
            max_results: Maximum number of results to return
        
        Returns:
            Dictionary with search results
        """
        # Build query
        if repo:
            full_query = f"{query} repo:{repo}"
        else:
            full_query = query
        
        # Check cache first
        cache_key = f"code:{full_query}:{max_results}"
        if cache_key in self.search_cache:
            logger.info(f"Search cache hit: {full_query}")
            return self.search_cache[cache_key]
        
        # Respect search-specific rate limits (30/min)
        await self._wait_for_search_rate_limit()
        
        url = f"{self.base_url}/search/code"
        params = {
            "q": full_query,
            "per_page": min(max_results, 100),
        }
        
        logger.info(f"Searching GitHub code ({self.search_requests_this_minute}/30 this min): {full_query}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        results = {
            "total_count": data.get("total_count", 0),
            "items": []
        }
        
        for item in data.get("items", [])[:max_results]:
            results["items"].append({
                "repository": item["repository"]["full_name"],
                "path": item["path"],
                "name": item["name"],
                "url": item["html_url"],
                "sha": item["sha"],
            })
        
        logger.info(f"Found {len(results['items'])} code matches")
        
        # Cache the results
        self.search_cache[cache_key] = results
        
        return results
    
    async def get_file_contents(
        self,
        repo: str,
        path: str,
        ref: str = "main",
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """
        Get file contents from GitHub.
        
        Args:
            repo: Repository (owner/name)
            path: File path
            ref: Branch, tag, or commit (default: main)
            start_line: Optional starting line (1-indexed)
            end_line: Optional ending line (1-indexed)
        
        Returns:
            File contents as string
        """
        url = f"{self.base_url}/repos/{repo}/contents/{quote(path)}"
        params = {"ref": ref}
        
        logger.info(f"Getting file {repo}:{path}@{ref}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        # Decode base64 content
        content_b64 = data.get("content", "")
        if not content_b64:
            return ""
        
        try:
            content = base64.b64decode(content_b64).decode("utf-8")
        except UnicodeDecodeError:
            # Try with latin-1 as fallback
            content = base64.b64decode(content_b64).decode("latin-1")
        
        # Check file size
        size = data.get("size", 0)
        if size > 1_000_000:  # 1MB
            logger.warning(f"Large file ({size} bytes): {repo}:{path}")
        
        # Extract line range if specified
        if start_line is not None or end_line is not None:
            lines = content.split("\n")
            start_idx = (start_line - 1) if start_line else 0
            end_idx = end_line if end_line else len(lines)
            content = "\n".join(lines[start_idx:end_idx])
        
        return content
    
    async def list_directory(
        self,
        repo: str,
        path: str = "",
        ref: str = "main",
        recursive: bool = False,
    ) -> list[dict]:
        """
        List directory contents.
        
        Args:
            repo: Repository (owner/name)
            path: Directory path (empty for root)
            ref: Branch, tag, or commit (default: main)
            recursive: List recursively
        
        Returns:
            List of file/directory entries
        """
        if recursive:
            # Use Git Tree API for recursive listing
            return await self._list_directory_recursive(repo, path, ref)
        
        # Use Contents API for non-recursive listing
        url = f"{self.base_url}/repos/{repo}/contents/{quote(path) if path else ''}"
        params = {"ref": ref}
        
        logger.info(f"Listing directory {repo}:{path}@{ref}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        # Handle single file response
        if isinstance(data, dict):
            return [{
                "name": data["name"],
                "path": data["path"],
                "type": data["type"],
                "size": data.get("size", 0),
            }]
        
        # Handle directory listing
        results = []
        for item in data:
            results.append({
                "name": item["name"],
                "path": item["path"],
                "type": item["type"],
                "size": item.get("size", 0),
            })
        
        logger.info(f"Found {len(results)} items in directory")
        
        return results
    
    async def _list_directory_recursive(
        self,
        repo: str,
        path: str,
        ref: str,
    ) -> list[dict]:
        """List directory recursively using Git Tree API."""
        # Normalize path - treat "." and "./" as root (empty string)
        if path in (".", "./"):
            path = ""
        
        # Get the commit SHA for the ref
        url = f"{self.base_url}/repos/{repo}/git/ref/heads/{ref}"
        try:
            response = await self._make_request("GET", url)
            commit_sha = response.json()["object"]["sha"]
        except GitHubAPIError:
            # Fallback: try getting the commit directly
            url = f"{self.base_url}/repos/{repo}/commits/{ref}"
            response = await self._make_request("GET", url)
            commit_sha = response.json()["sha"]
        
        # Get the tree
        url = f"{self.base_url}/repos/{repo}/git/trees/{commit_sha}"
        params = {"recursive": "1"}
        
        logger.info(f"Getting recursive tree for {repo}@{ref}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        # Debug: log all items in tree for diagnostics
        tree_items = data.get("tree", [])
        if tree_items:
            logger.debug(f"Tree items for {repo}@{ref}: {[item['path'] for item in tree_items[:20]]}"
                        f"{'...' if len(tree_items) > 20 else ''}")
        
        # Filter by path if specified
        results = []
        for item in data.get("tree", []):
            item_path = item["path"]
            if path and not item_path.startswith(path):
                continue
            
            results.append({
                "name": item_path.split("/")[-1],
                "path": item_path,
                "type": item["type"],  # "blob" or "tree"
                "size": item.get("size", 0),
            })
        
        logger.info(f"Found {len(results)} items in recursive tree")
        
        return results
    
    async def glob_files(
        self,
        repo: str,
        pattern: str,
        path: str = "",
        ref: str = "main",
        use_regex: bool = False,
    ) -> list[str]:
        """
        Find files matching pattern.
        
        Args:
            repo: Repository (owner/name)
            pattern: Glob pattern or regex
            path: Starting path (default: root)
            ref: Branch, tag, or commit (default: main)
            use_regex: Treat pattern as regex instead of glob
        
        Returns:
            List of matching file paths
        """
        # Get recursive directory listing
        all_files = await self.list_directory(repo, path, ref, recursive=True)
        
        # Filter files only (not directories)
        files = [f for f in all_files if f["type"] in ("blob", "file")]
        
        # Match pattern
        matches = []
        regex_failed = False
        
        for file in files:
            file_path = file["path"]
            
            if use_regex and not regex_failed:
                try:
                    if re.search(pattern, file_path):
                        matches.append(file_path)
                except re.error as e:
                    # Invalid regex - fall back to glob matching for all files
                    logger.warning(f"Invalid regex '{pattern}': {e}. Falling back to glob match.")
                    regex_failed = True
                    if fnmatch.fnmatch(file_path, pattern):
                        matches.append(file_path)
            else:
                if fnmatch.fnmatch(file_path, pattern):
                    matches.append(file_path)
        
        logger.info(f"Found {len(matches)} files matching pattern: {pattern}")
        
        return matches
    
    async def get_diff(
        self,
        repo: str,
        base: str,
        head: str,
        path: Optional[str] = None,
    ) -> dict:
        """
        Get diff between commits.
        
        Args:
            repo: Repository (owner/name)
            base: Base revision (commit, branch, tag)
            head: Head revision (commit, branch, tag)
            path: Optional path filter
        
        Returns:
            Dictionary with diff information
        """
        url = f"{self.base_url}/repos/{repo}/compare/{base}...{head}"
        
        logger.info(f"Getting diff for {repo}: {base}...{head}")
        
        response = await self._make_request("GET", url)
        data = response.json()
        
        files = []
        for file in data.get("files", []):
            # Filter by path if specified
            if path and not file["filename"].startswith(path):
                continue
            
            files.append({
                "filename": file["filename"],
                "status": file["status"],  # "added", "removed", "modified", etc.
                "additions": file["additions"],
                "deletions": file["deletions"],
                "changes": file["changes"],
                "patch": file.get("patch", ""),
            })
        
        result = {
            "base": base,
            "head": head,
            "ahead_by": data.get("ahead_by", 0),
            "behind_by": data.get("behind_by", 0),
            "total_commits": data.get("total_commits", 0),
            "files": files,
        }
        
        logger.info(f"Diff contains {len(files)} changed files")
        
        return result
    
    async def get_pull_request_diff(
        self,
        owner: str,
        repo: str,
        pull_number: int,
    ) -> dict:
        """
        Get pull request diff and metadata.
        
        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
        
        Returns:
            Dictionary with PR diff and metadata
        """
        # Get PR details
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}"
        
        logger.info(f"Getting PR #{pull_number} from {owner}/{repo}")
        
        response = await self._make_request("GET", url)
        pr_data = response.json()
        
        # Get the files changed in PR
        files_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}/files"
        files_response = await self._make_request("GET", files_url)
        files_data = files_response.json()
        
        # Build result
        files = []
        for file in files_data:
            files.append({
                "filename": file["filename"],
                "status": file["status"],
                "additions": file["additions"],
                "deletions": file["deletions"],
                "changes": file["changes"],
                "patch": file.get("patch", ""),
            })
        
        result = {
            "number": pull_number,
            "title": pr_data.get("title", ""),
            "body": pr_data.get("body", ""),
            "state": pr_data.get("state", ""),
            "base": pr_data.get("base", {}).get("ref", ""),
            "head": pr_data.get("head", {}).get("ref", ""),
            "author": pr_data.get("user", {}).get("login", ""),
            "created_at": pr_data.get("created_at", ""),
            "updated_at": pr_data.get("updated_at", ""),
            "additions": pr_data.get("additions", 0),
            "deletions": pr_data.get("deletions", 0),
            "changed_files": pr_data.get("changed_files", 0),
            "files": files,
        }
        
        logger.info(f"PR #{pull_number} has {len(files)} changed files")
        
        return result
    
    async def search_org_code(
        self,
        org: str,
        query: str,
        language: Optional[str] = None,
        max_results: int = 50,
    ) -> dict:
        """
        Search code across all repositories in an organization.
        
        Note: Search API has strict rate limit of 30 requests/minute.
        
        Args:
            org: Organization name
            query: Search query
            language: Optional language filter
            max_results: Maximum number of results to return
        
        Returns:
            Dictionary with search results grouped by repository
        """
        # Build query with org qualifier
        full_query = f"org:{org} {query}"
        if language:
            full_query += f" language:{language}"
        
        # Check cache first
        cache_key = f"org:{full_query}:{max_results}"
        if cache_key in self.search_cache:
            logger.info(f"Search cache hit: {full_query}")
            return self.search_cache[cache_key]
        
        # Respect search-specific rate limits (30/min)
        await self._wait_for_search_rate_limit()
        
        url = f"{self.base_url}/search/code"
        params = {
            "q": full_query,
            "per_page": min(max_results, 100),
        }
        
        logger.info(f"Searching org code ({self.search_requests_this_minute}/30 this min): {full_query}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        # Group results by repository
        by_repo: dict = {}
        for item in data.get("items", [])[:max_results]:
            repo_name = item["repository"]["full_name"]
            if repo_name not in by_repo:
                by_repo[repo_name] = []
            by_repo[repo_name].append({
                "path": item["path"],
                "name": item["name"],
                "url": item["html_url"],
                "sha": item["sha"],
            })
        
        results = {
            "total_count": data.get("total_count", 0),
            "repos_matched": len(by_repo),
            "by_repository": by_repo,
            "items": [
                {
                    "repository": item["repository"]["full_name"],
                    "path": item["path"],
                    "name": item["name"],
                    "url": item["html_url"],
                }
                for item in data.get("items", [])[:max_results]
            ]
        }
        
        logger.info(f"Found {results['total_count']} matches across {results['repos_matched']} repos")
        
        # Cache the results
        self.search_cache[cache_key] = results
        
        return results
    
    async def list_org_repos(
        self,
        org: str,
        repo_type: str = "all",
        max_results: int = 100,
    ) -> list[dict]:
        """
        List repositories in an organization.
        
        Args:
            org: Organization name
            repo_type: Type filter (all, public, private, forks, sources)
            max_results: Maximum number of repos to return
        
        Returns:
            List of repository information
        """
        url = f"{self.base_url}/orgs/{org}/repos"
        params = {
            "type": repo_type,
            "per_page": min(max_results, 100),
            "sort": "updated",
        }
        
        logger.info(f"Listing repos for org: {org}")
        
        response = await self._make_request("GET", url, params=params)
        data = response.json()
        
        repos = []
        for repo in data[:max_results]:
            repos.append({
                "name": repo["name"],
                "full_name": repo["full_name"],
                "description": repo.get("description", ""),
                "language": repo.get("language", ""),
                "default_branch": repo.get("default_branch", "main"),
                "private": repo.get("private", False),
                "fork": repo.get("fork", False),
                "updated_at": repo.get("updated_at", ""),
            })
        
        logger.info(f"Found {len(repos)} repos in org {org}")
        
        return repos
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
        logger.info("GitHub client closed")

