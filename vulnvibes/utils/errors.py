"""Custom exceptions for vuln-triage-agent."""


class VulnTriageError(Exception):
    """Base exception for vuln-triage-agent."""
    pass


class GitHubAPIError(VulnTriageError):
    """GitHub API request failed."""
    pass


class RateLimitError(GitHubAPIError):
    """GitHub API rate limit exceeded."""
    pass


class AgentExecutionError(VulnTriageError):
    """Agent execution failed."""
    pass


class ExtractionError(VulnTriageError):
    """Failed to extract data from agent response."""
    pass

