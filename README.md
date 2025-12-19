# VulnVibes

An autonomous AI agent for security vulnerability triage of GitHub Pull Requests using the Claude Agent SDK. Automatically performs threat modeling on PR changes and investigates potential vulnerabilities with skill-based analysis.

**Join our Discord** to follow the journey and connect with the community: [discord.gg/9cYqTBdC9h](https://discord.gg/9cYqTBdC9h)

## Features

- 🔍 **PR-Focused Analysis**: Analyzes pull request diffs for security implications
- 🎯 **Two-Stage Workflow**: Threat modeling followed by deep investigation
- 🛠️ **Skill-Based Investigation**: Extensible skills for different vulnerability classes
- 📊 **Structured Output**: Verdicts with confidence scores and detailed reasoning chains
- 🌐 **Multi-Repo Support**: Org-wide code search for cross-repository patterns
- 💻 **CLI + Python API**: Use from command line or programmatically

## Installation

```bash
pip install -e .
```

## Quick Start

### 1. Set Up Credentials

```bash
export GITHUB_TOKEN="ghp_your_token_here"
export ANTHROPIC_API_KEY="sk-ant-your_key_here"
```

### 2. Analyze a Pull Request

```bash
vulnvibes pr analyze https://github.com/org/repo/pull/123
```

### 3. With Context File

Create a `context.md` file with architectural context:

```markdown
---
related_repos:
  - name: infra-ops
    purpose: nginx configs, k8s manifests
ignore_vulns:
  - CWE-916  # Known issue, tracked in JIRA
---

# Architecture Overview
Microservices with nginx reverse proxy. Auth handled by auth-service.
```

Then run:

```bash
vulnvibes pr analyze https://github.com/org/repo/pull/123 --context-file context.md
```

## How It Works

### Stage 1: Threat Modeling

The `pr-analyzer` subagent:
1. Fetches and summarizes the PR diff
2. Performs threat modeling using the Threat Modeling Manifesto framework
3. Identifies potential vulnerabilities with CWE mappings
4. Matches threats to available investigation skills
5. Makes a Go/No-Go decision for Stage 2

### Stage 2: Deep Investigation

If Stage 1 identifies actionable threats, the `vuln-investigator` subagent:
1. Investigates each identified threat using matched skills
2. Traces data flows across the codebase (and related repos)
3. Searches for security controls at all layers
4. Produces verdicts with full reasoning chains

## Project Structure

```
vulnvibes/
├── vulnvibes/                      # Main package
│   ├── __init__.py                 # Package version
│   ├── cli.py                      # CLI (pr analyze command)
│   ├── config.py                   # Model configuration
│   ├── models.py                   # Data models
│   ├── skill_registry.py           # Dynamic skill discovery
│   ├── version.py                  # Version info
│   │
│   ├── agents/                     # Agent definitions
│   │   └── definitions.py          # pr-analyzer, vuln-investigator
│   │
│   ├── orchestrator/               # PR triage orchestration
│   │   ├── __init__.py             # PRTriageOrchestrator
│   │   ├── schemas.py              # JSON schemas
│   │   ├── parsers.py              # Response parsing
│   │   ├── reports.py              # Markdown reports
│   │   └── stages.py               # Stage 1 & 2 execution
│   │
│   ├── providers/                  # External integrations
│   │   ├── github_client.py        # GitHub API client
│   │   └── github_tools.py         # GitHub MCP tools
│   │
│   ├── skills/                     # Bundled investigation skills
│   │   ├── sast-injection-testing/
│   │   ├── sast-authentication-testing/
│   │   ├── sast-authorization-testing/
│   │   └── ... (10 skills total)
│   │
│   └── utils/                      # Utilities
│       ├── logging.py
│       └── errors.py
│
└── tests/                          # Test suite
```

## Available Skills

Skills are bundled with the package and mapped to CWE coverage:

| Skill | CWE Coverage |
|-------|--------------|
| sast-injection-testing | CWE-89, CWE-78, CWE-79, CWE-94 |
| sast-authentication-testing | CWE-287, CWE-306, CWE-384, CWE-613 |
| sast-authorization-testing | CWE-862, CWE-863, CWE-639 |
| sast-cors-testing | CWE-942, CWE-346, CWE-1021 |
| sast-ssrf-testing | CWE-918, CWE-441, CWE-611 |
| sast-file-security-testing | CWE-434, CWE-73, CWE-427 |
| sast-deserialization-testing | CWE-502, CWE-915 |
| sast-security-misconfiguration-testing | CWE-16, CWE-1188, CWE-276 |
| sast-cryptographic-failures-testing | CWE-327, CWE-328, CWE-330 |
| browser-security-testing | CWE-79, CWE-352, CWE-1021 |

## CLI Reference

### `vulnvibes pr analyze`

Analyze a pull request for security vulnerabilities.

```bash
vulnvibes pr analyze <PR_URL> [OPTIONS]
```

**Options:**
- `--github-token`: GitHub token (or env: `GITHUB_TOKEN`)
- `--anthropic-api-key`: Anthropic API key (or env: `ANTHROPIC_API_KEY`)
- `--model`: Model to use (sonnet, opus, haiku, or full model ID)
- `--org`: Organization name for org-wide search
- `--context-file`: Markdown context file with optional YAML frontmatter
- `--output`: Output file for JSON results
- `--output-dir`: Directory for markdown reports
- `--max-tool-calls`: Maximum tool calls per stage (default: 30)

**Examples:**

```bash
# Basic analysis
vulnvibes pr analyze https://github.com/org/repo/pull/123

# With context and markdown reports
vulnvibes pr analyze https://github.com/org/repo/pull/123 \
  --context-file context.md \
  --output-dir ./reports

# Use a specific model
vulnvibes pr analyze https://github.com/org/repo/pull/123 --model opus
```

## Python API

```python
import asyncio
from vulnvibes.orchestrator import PRTriageOrchestrator
from vulnvibes.models import PRTriageInput

async def main():
    orchestrator = PRTriageOrchestrator(
        github_token="ghp_...",
        anthropic_api_key="sk-ant-...",
        model="sonnet",
    )
    
    pr_input = PRTriageInput(pr_url="https://github.com/org/repo/pull/123")
    
    result = await orchestrator.analyze_pr(pr_input)
    
    print(f"Status: {result.status}")
    print(f"Verdict: {result.overall_verdict}")
    if result.threat_model:
        print(f"Threats: {result.threat_model.what_can_go_wrong}")
    
    await orchestrator.close()

asyncio.run(main())
```

## Output Structure

```python
{
    "status": "completed",  # "completed", "no_signal", "no_skills", "failed"
    "overall_verdict": "TRUE_POSITIVE",  # "TRUE_POSITIVE", "FALSE_POSITIVE", "MIXED"
    
    "threat_model": {
        "what_are_we_working_on": "...",  # PR summary
        "what_can_go_wrong": ["..."],     # Identified threats
        "identified_threats": [...]        # Detailed threat objects
    },
    
    "investigation_results": [{
        "verdict": "TRUE_POSITIVE",
        "confidence_score": 8,
        "risk_level": "HIGH",
        "reasoning_chain": [...]
    }],
    
    "skills_used": ["sast-authorization-testing"],
    "total_tool_calls": 45,
    "total_cost": 0.75,
    "total_time": 120.5
}
```

## Configuration

### Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token (required)
- `ANTHROPIC_API_KEY`: Anthropic API key (required)
- `VULNTRIAGE_PR_ANALYZER_MODEL`: Override model for pr-analyzer
- `VULNTRIAGE_VULN_INVESTIGATOR_MODEL`: Override model for vuln-investigator

### Model Selection Priority

1. Per-agent env var (`VULNTRIAGE_<AGENT>_MODEL`)
2. CLI `--model` flag
3. Default: `sonnet`

## Development

### Setup

```bash
git clone https://github.com/anshumanbh/vulnvibes.git
cd vulnvibes
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v
```

### Adding New Skills

1. Create a new directory under `vulnvibes/skills/`
2. Add a `SKILL.md` file with YAML frontmatter containing CWE mappings
3. The skill will be auto-discovered and appear in Stage 1 prompts
