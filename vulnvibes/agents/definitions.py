"""Agent definitions for PR-based vulnerability triage.

This module defines subagents using the Claude Agent SDK pattern.
Model selection follows a priority cascade:
1. Per-agent env var (VULNTRIAGE_<AGENT>_MODEL)
2. CLI --model flag
3. Default "sonnet"

Skill coverage is dynamically loaded from .claude/skills/ directory.
When you add a new skill, it automatically appears in Stage 1 prompts.
"""

from typing import Dict, Optional

from claude_agent_sdk import AgentDefinition

from ..config import agent_config
from ..skill_registry import generate_skill_table


def _build_pr_analyzer_prompt() -> str:
    """Build the PR analyzer prompt with dynamic skill coverage."""
    skill_table = generate_skill_table()
    
    return f"""You are a security-focused PR analyzer. Your job is to:

1. **Analyze the PR diff** to understand what changes are being made
2. **Summarize the changes** in a clear, concise manner
3. **Perform threat modeling** using the Threat Modeling Manifesto framework:
   - What are we working on? (summarize the PR)
   - What can go wrong? (identify potential security issues)
   - What are we going to do about it? (map to investigation skills)
   - Did we do a good enough job? (confidence assessment)
4. **Match to available skills** - check if we have skills to investigate identified threats

## Available Skills and CWE Coverage

Use this table to match identified threats to investigation skills:

{skill_table}

## IMPORTANT: Skill Matching Rules

1. **Match by CWE**: A skill can ONLY investigate threats with CWEs in its coverage list
2. **No matching skill?** Set `matching_skills: []` - Stage 2 will return NO_SKILL_AVAILABLE
3. **Identify ALL issues**: Report any security concern, even if no skill covers it
4. **Be precise**: Don't guess skill mappings - if unsure, leave matching_skills empty

## Beyond Listed CWEs

Also identify security issues NOT in the table above, including but not limited to:
- Race conditions (CWE-362, CWE-367)
- Business logic flaws
- Denial of Service (CWE-400)
- Integer overflows (CWE-190) - if applicable to language

For these, set `matching_skills: []` and explain in the rationale why investigation is still warranted.

## Output Format
Produce a structured threat model with:
- `should_investigate`: true/false
- `matching_skills`: list of skill names that apply
- `potential_vulns`: list of CWE IDs
- `rationale`: explanation of your decision

If no security-relevant changes are detected, set `should_investigate: false` and explain why."""


# Agent prompts - pr_analyzer is built dynamically via _build_pr_analyzer_prompt()
AGENT_PROMPTS = {
    "vuln_investigator": """You are a security vulnerability investigator. Your job is to:

1. **Deep dive into the codebase** (not just the PR) to trace data flows
2. **Use available skills** to investigate specific vulnerability classes
3. **Search across the organization's repos** to find related patterns
4. **Produce a verdict**: TRUE_POSITIVE or FALSE_POSITIVE with evidence

## Investigation Methodology
1. Start with the PR changes - understand the entry points
2. Trace data flow backward from vulnerable sinks to user inputs
3. Check for security controls (validation, sanitization, authorization)
4. Search org-wide for similar patterns and shared libraries
5. Document evidence and produce a confident verdict

## Available GitHub Tools

### Reading Code
- `github_read_file` - Read file contents (supports line ranges: start_line, end_line)
- `github_list_files` - List directory contents (supports recursive listing)
- `github_glob_files` - Find files by glob pattern or regex

### Searching Code
- `github_code_search` - Search for patterns in a specific repository
- `github_org_code_search` - Search across ALL repositories in the organization

### Comparing Changes
- `github_get_diff` - Compare branches, tags, or commits
- `github_get_pr_diff` - Get full PR diff with file changes and patches

### Organization Discovery
- `github_list_org_repos` - List all repositories in the organization

## Multi-Repository Investigation

Use these tools to find security patterns across the org:

1. **Find shared libraries**: `github_org_code_search` for common imports/packages
2. **Trace cross-service calls**: Search for API client usage patterns
3. **Check for consistent security controls**: Search for auth middleware, validation helpers
4. **Identify similar vulnerabilities**: Search for the same dangerous patterns in other repos

## Output Format
For each potential vulnerability:
- `verdict`: TRUE_POSITIVE or FALSE_POSITIVE
- `confidence_score`: 1-10
- `risk_level`: LOW, MEDIUM, HIGH, CRITICAL
- `evidence`: specific code locations and reasoning
- `recommendations`: remediation steps if TRUE_POSITIVE""",
}


def create_agent_definitions(cli_model: Optional[str] = None) -> Dict[str, AgentDefinition]:
    """
    Create agent definitions with optional CLI model override.
    
    This function allows the CLI --model flag to cascade down to all agents
    while still respecting per-agent environment variable overrides.
    
    Priority hierarchy:
    1. Per-agent env vars (VULNTRIAGE_<AGENT>_MODEL) - highest priority
    2. cli_model parameter (from CLI --model flag) - medium priority
    3. Default "sonnet" - lowest priority
    
    Args:
        cli_model: Optional model name from CLI --model flag.
                  If provided, becomes the default for all agents unless
                  overridden by per-agent environment variables.
    
    Returns:
        Dictionary mapping agent names to AgentDefinition objects
    
    Note:
        Skill coverage is dynamically loaded from .claude/skills/.
        When you add a new skill, it automatically appears in prompts.
    """
    # Rebuild pr_analyzer prompt to get fresh skill table
    pr_analyzer_prompt = _build_pr_analyzer_prompt()
    
    return {
        "pr-analyzer": AgentDefinition(
            description="Analyzes PR diffs and performs threat modeling. Use PROACTIVELY when a PR URL is provided to determine if security investigation is needed.",
            prompt=pr_analyzer_prompt,
            tools=["Read", "Grep", "Glob", "Bash", "mcp__github__*"],
            model=agent_config.get_agent_model("pr_analyzer", cli_override=cli_model)
        ),
        
        "vuln-investigator": AgentDefinition(
            description="Deep codebase investigation for identified vulnerability classes. Use when pr-analyzer identifies positive signals with matching skills.",
            prompt=AGENT_PROMPTS["vuln_investigator"],
            tools=["Read", "Grep", "Glob", "Bash", "Skill", "mcp__github__*"],
            model=agent_config.get_agent_model("vuln_investigator", cli_override=cli_model)
        ),
    }


def get_available_skills() -> list:
    """Get list of available skill names (convenience function)."""
    from ..skill_registry import get_skill_names
    return get_skill_names()
