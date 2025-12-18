"""Command-line interface for vuln-triage-agent."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import click
import yaml

from .orchestrator import PRTriageOrchestrator
from .models import PRTriageInput, UserContext
from .utils.logging import setup_logging


def parse_context_file(file_path: str) -> UserContext:
    """Parse markdown context file with optional YAML frontmatter.
    
    Supports format:
    ---
    related_repos:
      - name: infra-ops
        purpose: nginx configs, k8s manifests
    ignore_vulns:
      - CWE-916
    ---
    
    # Architecture Overview
    Free-form markdown content...
    """
    content = Path(file_path).read_text()
    
    structured = {}
    markdown = content
    
    # Check for YAML frontmatter (--- delimited)
    if content.startswith('---'):
        parts = content.split('---', 2)
        if len(parts) >= 3:
            yaml_content = parts[1].strip()
            markdown = parts[2].strip()
            if yaml_content:
                try:
                    structured = yaml.safe_load(yaml_content) or {}
                except yaml.YAMLError as e:
                    click.echo(f"Warning: Failed to parse YAML frontmatter: {e}", err=True)
                    structured = {}
    
    return UserContext(
        related_repos=structured.get('related_repos', []),
        ignore_vulns=structured.get('ignore_vulns', []),
        free_form_context=markdown
    )


@click.group()
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
def cli(verbose: bool):
    """Vulnerability Triage Agent CLI - Analyze PRs for security vulnerabilities."""
    setup_logging("DEBUG" if verbose else "INFO")


@cli.group()
def pr():
    """PR-based vulnerability triage commands."""
    pass


@pr.command()
@click.argument('pr_url')
@click.option('--github-token', envvar='GITHUB_TOKEN', required=True, help='GitHub personal access token')
@click.option('--anthropic-api-key', envvar='ANTHROPIC_API_KEY', required=True, help='Anthropic API key')
@click.option('--model', default=None, help='Model to use (sonnet, opus, haiku, or full model ID)')
@click.option('--org', default=None, help='Organization name for org-wide search (defaults to repo owner)')
@click.option('--context-file', type=click.Path(exists=True), help='Markdown context file with optional YAML frontmatter')
@click.option('--output', type=click.Path(), help='Output file for JSON results (default: stdout)')
@click.option('--output-dir', type=click.Path(), help='Directory for markdown reports (threat_model.md, investigation.md)')
@click.option('--max-tool-calls', type=int, default=30, help='Maximum tool calls per stage')
def analyze(
    pr_url: str,
    github_token: str,
    anthropic_api_key: str,
    model: Optional[str],
    org: Optional[str],
    context_file: Optional[str],
    output: Optional[str],
    output_dir: Optional[str],
    max_tool_calls: int,
):
    """
    Analyze a pull request for security vulnerabilities.
    
    This performs a multi-stage analysis:
    
    Stage 1: PR Analysis & Threat Modeling
      - Fetch and summarize PR diff
      - Identify specific threats from PR changes
      - Generate investigation questions for each threat
    
    Stage 2: Threat Validation (if needed)
      - Validate each identified threat using matched skills
      - Check for security controls at ALL layers (code, middleware, infrastructure)
      - Produce verdicts with full reasoning chain
    
    Context file format (markdown with optional YAML frontmatter):
    
        ---
        related_repos:
          - name: infra-ops
            purpose: nginx configs, k8s manifests
        ignore_vulns:
          - CWE-916  # Known issue, tracked in JIRA
        ---
        
        # Architecture Overview
        Microservices with nginx reverse proxy...
    
    Example:
        vuln-triage pr analyze https://github.com/org/repo/pull/123
        vuln-triage pr analyze https://github.com/org/repo/pull/123 --context-file context.md
    """
    
    # Load user context from markdown file
    user_context = None
    if context_file:
        user_context = parse_context_file(context_file)
        click.echo(f"Loaded user context from {context_file}")
        if user_context.related_repos:
            click.echo(f"   Related repos: {[r.get('name', r) for r in user_context.related_repos]}")
        if user_context.ignore_vulns:
            click.echo(f"   Ignored vulns: {user_context.ignore_vulns}")
        if user_context.free_form_context:
            click.echo(f"   Context: {len(user_context.free_form_context)} chars of markdown")
    
    # Create PR input
    pr_input = PRTriageInput(pr_url=pr_url, org=org)
    
    click.echo(f"\n🔍 Analyzing PR for security vulnerabilities...")
    click.echo(f"   URL: {pr_url}")
    click.echo(f"   Repository: {pr_input.repository}")
    click.echo(f"   PR Number: {pr_input.pull_number}")
    click.echo(f"   Organization: {pr_input.org}")
    if model:
        click.echo(f"   Model: {model}")
    click.echo("")
    
    async def run():
        orchestrator = PRTriageOrchestrator(
            github_token=github_token,
            anthropic_api_key=anthropic_api_key,
            model=model,
            max_tool_calls=max_tool_calls,
            user_context=user_context,
            output_dir=output_dir,
        )
        
        try:
            result = await orchestrator.analyze_pr(pr_input)
            return result
        finally:
            await orchestrator.close()
    
    result = asyncio.run(run())
    
    # Display results based on status
    if result.status == "completed":
        click.echo("✅ Analysis completed!\n")
        
        # Display threat model summary
        if result.threat_model:
            click.echo("📋 Threat Model:")
            click.echo(f"   Changes: {result.threat_model.what_are_we_working_on[:100]}...")
            click.echo(f"   Potential Issues: {len(result.threat_model.what_can_go_wrong)}")
            click.echo(f"   Skills Used: {', '.join(result.skills_used) or 'None'}")
            click.echo("")
        
        # Display verdict
        click.echo(f"🎯 Overall Verdict: {result.overall_verdict or 'N/A'}")
        
        if result.overall_verdict == "TRUE_POSITIVE":
            click.secho("⚠️  TRUE POSITIVE - Security vulnerability confirmed!", fg='red', bold=True)
        elif result.overall_verdict == "FALSE_POSITIVE":
            click.secho("✓  FALSE POSITIVE - No security vulnerability found", fg='green', bold=True)
        elif result.overall_verdict == "MIXED":
            click.secho("⚡ MIXED - Some concerns identified, review recommended", fg='yellow', bold=True)
        
        # Display investigation results
        if result.investigation_results:
            click.echo("\n📊 Investigation Results:")
            for i, inv_result in enumerate(result.investigation_results, 1):
                click.echo(f"   {i}. Verdict: {inv_result.verdict or 'N/A'}")
                click.echo(f"      Confidence: {inv_result.confidence_score or 'N/A'}/10")
                click.echo(f"      Risk Level: {inv_result.risk_level or 'N/A'}")
        
        click.echo("")
        click.echo(f"📈 Metrics:")
        click.echo(f"   Total Tool Calls: {result.total_tool_calls}")
        click.echo(f"   Total Cost: ${result.total_cost:.4f}")
        click.echo(f"   Duration: {result.total_time:.2f}s")
        
        if output_dir:
            click.echo(f"\n📄 Reports saved to {output_dir}:")
            click.echo(f"   - {pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_threat_model.md")
            click.echo(f"   - {pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_investigation.md")
    
    elif result.status == "no_signal":
        click.echo("ℹ️  No security-relevant changes detected in this PR.")
        if result.threat_model:
            click.echo(f"   Reason: {result.threat_model.rationale}")
        click.echo(f"   Duration: {result.total_time:.2f}s")
        if output_dir:
            click.echo(f"\n📄 Report saved to {output_dir}:")
            click.echo(f"   - {pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_threat_model.md")
    
    elif result.status == "no_skills":
        click.echo("ℹ️  Security concerns identified but no matching skills available.")
        if result.threat_model:
            click.echo(f"   Potential Issues: {result.threat_model.what_can_go_wrong}")
        click.echo(f"   Duration: {result.total_time:.2f}s")
        if output_dir:
            click.echo(f"\n📄 Report saved to {output_dir}:")
            click.echo(f"   - {pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_threat_model.md")
    
    else:
        click.echo("❌ Analysis failed!")
        click.echo(f"   Error: {result.error}")
        click.echo(f"   Duration: {result.total_time:.2f}s")
    
    # Output results to file or stdout
    result_json = json.dumps(result.to_dict(), indent=2, default=str)
    
    if output:
        with open(output, 'w') as f:
            f.write(result_json)
        click.echo(f"\nFull results written to {output}")
    else:
        click.echo("\n--- Full Results ---")
        click.echo(result_json)


if __name__ == '__main__':
    cli()
