"""GitHub tools for Claude Agent SDK using @tool decorator."""

from typing import Any, Optional

from claude_agent_sdk import tool, create_sdk_mcp_server

from .github_client import GitHubClient
from ..utils.logging import get_logger

logger = get_logger("github_tools")

# Global GitHub client instance (set at runtime)
_github_client: Optional[GitHubClient] = None


def _to_int(value, default=None):
    """Safely convert value to int (handles string inputs from agent)."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def set_github_client(client: GitHubClient):
    """
    Set the GitHub client instance for tools.
    
    Args:
        client: GitHubClient instance
    """
    global _github_client
    _github_client = client
    logger.info("GitHub client set for tools")


def format_search_results(results: dict) -> str:
    """Format search results for agent consumption."""
    if not results or results.get("total_count", 0) == 0:
        return "No results found"
    
    lines = [f"Found {results['total_count']} total matches (showing first {len(results['items'])}):\n"]
    
    for i, item in enumerate(results["items"], 1):
        lines.append(f"{i}. {item['repository']}/{item['path']}")
        lines.append(f"   URL: {item['url']}\n")
    
    return "\n".join(lines)


def format_file_tree(files: list[dict]) -> str:
    """Format file tree for agent consumption."""
    if not files:
        return "No files found"
    
    lines = []
    for file in files:
        prefix = "📁" if file["type"] in ("tree", "dir") else "📄"
        size_str = f" ({file['size']} bytes)" if file.get("size") else ""
        lines.append(f"{prefix} {file['path']}{size_str}")
    
    return "\n".join(lines)


def format_diff(diff: dict) -> str:
    """Format diff for agent consumption."""
    if not diff or not diff.get("files"):
        return "No changes found"
    
    lines = [
        f"Comparing {diff['base']}...{diff['head']}",
        f"Commits: {diff['total_commits']} | Ahead: {diff['ahead_by']} | Behind: {diff['behind_by']}\n",
        f"Files changed: {len(diff['files'])}\n"
    ]
    
    for file in diff["files"]:
        status_emoji = {
            "added": "➕",
            "removed": "➖",
            "modified": "✏️",
            "renamed": "📝",
        }.get(file["status"], "📄")
        
        lines.append(f"{status_emoji} {file['filename']} ({file['status']})")
        lines.append(f"   +{file['additions']} -{file['deletions']} changes")
        
        if file.get("patch"):
            # Truncate patch if too long
            patch = file["patch"]
            if len(patch) > 500:
                patch = patch[:500] + "\n... (truncated)"
            lines.append(f"   Patch:\n{patch}\n")
    
    return "\n".join(lines)


# Define GitHub tools using @tool decorator

@tool(
    "github_code_search",
    "Search for code patterns, functions, or text in GitHub repositories",
    {
        "query": {"type": "string", "description": "Search query"},
        "repo": {
            "type": "string",
            "description": "Optional: limit to repo (owner/name)",
            "required": False
        },
        "max_results": {
            "type": "integer",
            "description": "Max results to return (default: 50)",
            "default": 50
        }
    }
)
async def github_code_search(args: dict) -> dict:
    """Search code in GitHub repositories."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        results = await _github_client.search_code(
            query=args["query"],
            repo=args.get("repo"),
            max_results=_to_int(args.get("max_results"), 50)
        )
        
        formatted = format_search_results(results)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_code_search failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error searching code: {str(e)}"}
            ]
        }


@tool(
    "github_read_file",
    "Read file contents from a GitHub repository",
    {
        "repo": {"type": "string", "description": "Repository (owner/name)"},
        "path": {"type": "string", "description": "File path"},
        "ref": {
            "type": "string",
            "description": "Branch/tag/commit (default: main)",
            "default": "main"
        },
        "start_line": {
            "type": "integer",
            "description": "Start line (1-indexed, optional)",
            "required": False
        },
        "end_line": {
            "type": "integer",
            "description": "End line (1-indexed, optional)",
            "required": False
        }
    }
)
async def github_read_file(args: dict) -> dict:
    """Read file contents from GitHub."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        start_line = _to_int(args.get("start_line"))
        end_line = _to_int(args.get("end_line"))
        
        content = await _github_client.get_file_contents(
            repo=args["repo"],
            path=args["path"],
            ref=args.get("ref", "main"),
            start_line=start_line,
            end_line=end_line
        )
        
        # Add line numbers if reading a range
        if start_line:
            lines = content.split("\n")
            numbered_lines = [f"{start_line + i:4d} | {line}" for i, line in enumerate(lines)]
            content = "\n".join(numbered_lines)
        
        return {
            "content": [
                {"type": "text", "text": content}
            ]
        }
    except Exception as e:
        logger.error(f"github_read_file failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error reading file: {str(e)}"}
            ]
        }


@tool(
    "github_list_files",
    "List files and directories in a GitHub repository",
    {
        "repo": {"type": "string", "description": "Repository (owner/name)"},
        "path": {
            "type": "string",
            "description": "Directory path (default: root)",
            "default": ""
        },
        "ref": {
            "type": "string",
            "description": "Branch/tag/commit (default: main)",
            "default": "main"
        },
        "recursive": {
            "type": "boolean",
            "description": "List recursively (default: false)",
            "default": False
        }
    }
)
async def github_list_files(args: dict) -> dict:
    """List directory contents in GitHub repository."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        files = await _github_client.list_directory(
            repo=args["repo"],
            path=args.get("path", ""),
            ref=args.get("ref", "main"),
            recursive=args.get("recursive", False)
        )
        
        formatted = format_file_tree(files)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_list_files failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error listing files: {str(e)}"}
            ]
        }


@tool(
    "github_glob_files",
    "Find files matching a glob pattern or regex in a repository",
    {
        "repo": {"type": "string", "description": "Repository (owner/name)"},
        "pattern": {"type": "string", "description": "Glob pattern (*.py) or regex"},
        "path": {
            "type": "string",
            "description": "Starting path (default: root)",
            "default": ""
        },
        "ref": {
            "type": "string",
            "description": "Branch/tag/commit (default: main)",
            "default": "main"
        },
        "use_regex": {
            "type": "boolean",
            "description": "Treat pattern as regex (default: false)",
            "default": False
        }
    }
)
async def github_glob_files(args: dict) -> dict:
    """Find files by pattern in GitHub repository."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        matches = await _github_client.glob_files(
            repo=args["repo"],
            pattern=args["pattern"],
            path=args.get("path", ""),
            ref=args.get("ref", "main"),
            use_regex=args.get("use_regex", False)
        )
        
        if not matches:
            formatted = "No files matched the pattern"
        else:
            formatted = f"Found {len(matches)} matching files:\n" + "\n".join(matches)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_glob_files failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error finding files: {str(e)}"}
            ]
        }


@tool(
    "github_get_diff",
    "Get differences between two commits, branches, or tags",
    {
        "repo": {"type": "string", "description": "Repository (owner/name)"},
        "base": {"type": "string", "description": "Base revision"},
        "head": {"type": "string", "description": "Head revision"},
        "path": {
            "type": "string",
            "description": "Optional: limit to specific path",
            "required": False
        }
    }
)
async def github_get_diff(args: dict) -> dict:
    """Get diff between revisions in GitHub repository."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        diff = await _github_client.get_diff(
            repo=args["repo"],
            base=args["base"],
            head=args["head"],
            path=args.get("path")
        )
        
        formatted = format_diff(diff)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_get_diff failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error getting diff: {str(e)}"}
            ]
        }


@tool(
    "github_get_pr_diff",
    "Get pull request diff and metadata from a GitHub repository",
    {
        "owner": {"type": "string", "description": "Repository owner"},
        "repo": {"type": "string", "description": "Repository name"},
        "pull_number": {"type": "integer", "description": "Pull request number"}
    }
)
async def github_get_pr_diff(args: dict) -> dict:
    """Get pull request diff and metadata."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        pull_number = _to_int(args["pull_number"])
        if pull_number is None:
            return {
                "content": [
                    {"type": "text", "text": f"Error: Invalid pull_number: {args['pull_number']}"}
                ]
            }
        
        pr_data = await _github_client.get_pull_request_diff(
            owner=args["owner"],
            repo=args["repo"],
            pull_number=pull_number
        )
        
        # Format the PR diff for agent consumption
        lines = [
            f"## Pull Request #{pr_data['number']}: {pr_data['title']}",
            f"",
            f"**Author:** {pr_data['author']}",
            f"**State:** {pr_data['state']}",
            f"**Base:** {pr_data['base']} ← **Head:** {pr_data['head']}",
            f"**Files Changed:** {pr_data['changed_files']} (+{pr_data['additions']}/-{pr_data['deletions']})",
            f"",
            f"### Description",
            pr_data['body'] or "(No description)",
            f"",
            f"### Changed Files",
        ]
        
        for file in pr_data['files']:
            status_emoji = {
                "added": "➕",
                "removed": "➖",
                "modified": "✏️",
                "renamed": "📝",
            }.get(file["status"], "📄")
            
            lines.append(f"")
            lines.append(f"{status_emoji} **{file['filename']}** ({file['status']})")
            lines.append(f"   +{file['additions']} -{file['deletions']} changes")
            
            if file.get("patch"):
                patch = file["patch"]
                if len(patch) > 2000:
                    patch = patch[:2000] + "\n... (truncated)"
                lines.append(f"```diff")
                lines.append(patch)
                lines.append(f"```")
        
        formatted = "\n".join(lines)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_get_pr_diff failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error getting PR diff: {str(e)}"}
            ]
        }


def format_org_search_results(results: dict) -> str:
    """Format org-wide search results for agent consumption."""
    if not results or results.get("total_count", 0) == 0:
        return "No results found"
    
    lines = [
        f"Found {results['total_count']} total matches across {results['repos_matched']} repositories:\n"
    ]
    
    # Group by repository
    for repo, items in results.get("by_repository", {}).items():
        lines.append(f"\n### {repo}")
        for item in items[:10]:  # Limit per repo
            lines.append(f"  - {item['path']}")
    
    return "\n".join(lines)


@tool(
    "github_org_code_search",
    "Search code across all repositories in a GitHub organization",
    {
        "org": {"type": "string", "description": "Organization name"},
        "query": {"type": "string", "description": "Search query"},
        "language": {
            "type": "string",
            "description": "Optional: filter by language (python, javascript, etc.)",
            "required": False
        },
        "max_results": {
            "type": "integer",
            "description": "Max results to return (default: 50)",
            "default": 50
        }
    }
)
async def github_org_code_search(args: dict) -> dict:
    """Search code across all repositories in an organization."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        results = await _github_client.search_org_code(
            org=args["org"],
            query=args["query"],
            language=args.get("language"),
            max_results=_to_int(args.get("max_results"), 50)
        )
        
        formatted = format_org_search_results(results)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_org_code_search failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error searching org code: {str(e)}"}
            ]
        }


@tool(
    "github_list_org_repos",
    "List repositories in a GitHub organization",
    {
        "org": {"type": "string", "description": "Organization name"},
        "repo_type": {
            "type": "string",
            "description": "Type filter: all, public, private, forks, sources (default: all)",
            "default": "all"
        },
        "max_results": {
            "type": "integer",
            "description": "Max repos to return (default: 100)",
            "default": 100
        }
    }
)
async def github_list_org_repos(args: dict) -> dict:
    """List repositories in an organization."""
    if _github_client is None:
        return {
            "content": [
                {"type": "text", "text": "Error: GitHub client not initialized"}
            ]
        }
    
    try:
        repos = await _github_client.list_org_repos(
            org=args["org"],
            repo_type=args.get("repo_type", "all"),
            max_results=_to_int(args.get("max_results"), 100)
        )
        
        lines = [f"Found {len(repos)} repositories in {args['org']}:\n"]
        
        for repo in repos:
            visibility = "🔒" if repo["private"] else "🌐"
            fork_indicator = " (fork)" if repo["fork"] else ""
            lang = f" [{repo['language']}]" if repo["language"] else ""
            lines.append(f"{visibility} **{repo['name']}**{lang}{fork_indicator}")
            if repo["description"]:
                lines.append(f"   {repo['description'][:100]}")
        
        formatted = "\n".join(lines)
        
        return {
            "content": [
                {"type": "text", "text": formatted}
            ]
        }
    except Exception as e:
        logger.error(f"github_list_org_repos failed: {e}")
        return {
            "content": [
                {"type": "text", "text": f"Error listing org repos: {str(e)}"}
            ]
        }


def create_github_tools_server() -> Any:
    """
    Create in-process MCP server with GitHub tools.
    
    Returns:
        MCP server object with registered GitHub tools
    """
    logger.info("Creating GitHub tools MCP server")
    
    server = create_sdk_mcp_server(
        name="github",
        version="2.0.0",
        tools=[
            github_code_search,
            github_read_file,
            github_list_files,
            github_glob_files,
            github_get_diff,
            github_get_pr_diff,
            github_org_code_search,
            github_list_org_repos,
        ]
    )
    
    logger.info("GitHub tools MCP server created with 8 tools")
    
    return server

