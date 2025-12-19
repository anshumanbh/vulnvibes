"""PR-based vulnerability triage orchestrator using Claude Agent SDK.

This package provides a multi-stage PR triage workflow:
- Stage 1: PR Analysis & Threat Modeling
- Stage 2: Full Codebase Investigation

Example usage:
    from vulnvibes.orchestrator import PRTriageOrchestrator
    
    orchestrator = PRTriageOrchestrator(
        github_token="...",
        anthropic_api_key="...",
    )
    
    result = await orchestrator.analyze_pr(pr_input)
"""

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..agents.definitions import create_agent_definitions
from ..providers.github_client import GitHubClient
from ..providers.github_tools import create_github_tools_server, set_github_client
from ..models import (
    PRTriageInput, PRTriageResult, TriageStatus, UserContext
)
from ..utils.logging import get_logger

# Import from submodules
from .schemas import THREAT_MODEL_SCHEMA, INVESTIGATION_RESULT_SCHEMA
from .parsers import aggregate_verdicts
from .reports import generate_threat_model_report, generate_investigation_report, generate_investigation_json
from .stages import run_stage1, run_stage2

logger = get_logger("orchestrator")

# Export schemas for backward compatibility
__all__ = [
    'PRTriageOrchestrator',
    'THREAT_MODEL_SCHEMA',
    'INVESTIGATION_RESULT_SCHEMA',
]


class PRTriageOrchestrator:
    """
    Multi-stage PR triage orchestrator.
    
    Stage 1: PR Analysis & Threat Modeling (pr-analyzer subagent)
    - Fetch and summarize PR diff
    - Perform threat modeling (4 key questions)
    - Match to available skills
    - Go/No-Go decision
    
    Stage 2: Full Codebase Investigation (vuln-investigator subagent)
    - Only if Stage 1 identifies positive signals
    - Only if matching skills are available
    - Deep investigation using skills
    - Multi-repo tracing
    """
    
    def __init__(
        self,
        github_token: str,
        anthropic_api_key: str,
        model: Optional[str] = None,
        max_tool_calls: int = 30,
        user_context: Optional[UserContext] = None,
        output_dir: Optional[str] = None,
    ):
        """
        Initialize the PR triage orchestrator.
        
        Args:
            github_token: GitHub personal access token
            anthropic_api_key: Anthropic API key
            model: Model to use (sonnet, opus, haiku, or full model ID)
            max_tool_calls: Maximum tool calls per stage
            user_context: UserContext with related repos, ignore list, and free-form markdown
            output_dir: Directory to save markdown reports (optional)
        """
        logger.info("Initializing PRTriageOrchestrator")
        
        # Set up GitHub client
        self.github_client = GitHubClient(token=github_token)
        set_github_client(self.github_client)
        
        # Store configuration
        self.anthropic_api_key = anthropic_api_key
        self.model = model
        self.max_tool_calls = max_tool_calls
        self.user_context = user_context
        self.output_dir = output_dir
        
        # Create output directory if specified
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            logger.info(f"Reports will be saved to: {output_dir}")
        
        # Create GitHub tools server
        self.github_tools_server = create_github_tools_server()
        
        # Create agent definitions with model override
        self.agents = create_agent_definitions(cli_model=model)
        
        logger.info(f"Orchestrator initialized with model={model}, max_tool_calls={max_tool_calls}")
        if user_context and user_context.has_context:
            logger.info(f"User context provided: {len(user_context.related_repos)} related repos, "
                       f"{len(user_context.ignore_vulns)} ignored vulns")
        
        # Ensure skills are available for Claude Agent SDK
        self._setup_skills()
    
    def _setup_skills(self):
        """Copy bundled skills to cwd for Claude Agent SDK discovery.
        
        Skills are bundled with the vulnvibes package and need to be available
        in the current working directory's .claude/skills/ for the SDK to find them.
        """
        from ..skills import get_skills_dir
        
        package_skills = get_skills_dir()
        target_skills = Path.cwd() / ".claude" / "skills"
        
        if not package_skills.exists():
            logger.warning(f"Bundled skills not found at {package_skills}")
            return
        
        # Copy each skill directory
        for skill_dir in package_skills.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("_"):
                target_skill = target_skills / skill_dir.name
                if not target_skill.exists():
                    target_skill.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(skill_dir, target_skill)
                    logger.debug(f"Copied skill: {skill_dir.name}")
        
        logger.info(f"Skills setup complete in {target_skills}")
    
    def _format_user_context(self) -> str:
        """Format user context for inclusion in prompts."""
        if not self.user_context or not self.user_context.has_context:
            return ""
        
        parts = []
        
        if self.user_context.related_repos:
            repos_str = "\n".join(
                f"  - **{r.get('name', r)}**: {r.get('purpose', 'Related repository')}"
                for r in self.user_context.related_repos
            )
            parts.append(f"### Related Repositories\n{repos_str}")
        
        if self.user_context.ignore_vulns:
            ignore_str = ", ".join(self.user_context.ignore_vulns)
            parts.append(f"### Known Issues to Ignore\nThe following are known issues being addressed separately: {ignore_str}")
        
        if self.user_context.free_form_context.strip():
            parts.append(f"### Architecture & Security Context\n{self.user_context.free_form_context}")
        
        return "\n\n".join(parts)
    
    async def analyze_pr(
        self,
        pr_input: PRTriageInput,
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> PRTriageResult:
        """
        Analyze a pull request for security vulnerabilities.
        
        This is the main entry point that orchestrates the multi-stage workflow.
        
        Args:
            pr_input: PRTriageInput with PR URL and optional overrides
            additional_context: Additional context for this specific analysis
        
        Returns:
            PRTriageResult with threat model and investigation findings
        """
        logger.info(
            f"Starting PR analysis: {pr_input.pr_url} "
            f"(owner={pr_input.owner}, repo={pr_input.repo}, pr={pr_input.pull_number})"
        )
        
        start_time = time.time()
        
        try:
            # Stage 1: PR Analysis & Threat Modeling
            stage1_start = time.time()
            stage1_result = await run_stage1(self, pr_input, additional_context)
            stage1_duration = time.time() - stage1_start
            
            # Save Stage 1 report
            if self.output_dir:
                report = generate_threat_model_report(pr_input, stage1_result, stage1_duration)
                self._save_report(f"{pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_threat_model.md", report)
            
            # Check if we should proceed to Stage 2
            if not stage1_result.should_investigate:
                duration = time.time() - start_time
                logger.info(f"Stage 1 complete: No investigation needed. Reason: {stage1_result.rationale}")
                
                return PRTriageResult(
                    status=TriageStatus.NO_SIGNAL.value,
                    threat_model=stage1_result,
                    total_time=duration,
                )
            
            if not stage1_result.matching_skills:
                duration = time.time() - start_time
                logger.info(f"Stage 1 complete: No matching skills available.")
                
                return PRTriageResult(
                    status=TriageStatus.NO_SKILLS.value,
                    threat_model=stage1_result,
                    total_time=duration,
                )
            
            # Stage 2: Full Codebase Investigation
            logger.info(
                f"Stage 1 passed. Proceeding to Stage 2 with skills: {stage1_result.matching_skills}"
            )
            
            stage2_start = time.time()
            investigation_results = await run_stage2(
                self, pr_input, stage1_result, additional_context
            )
            stage2_duration = time.time() - stage2_start
            
            duration = time.time() - start_time
            
            # Aggregate results
            overall_verdict = aggregate_verdicts(investigation_results)
            
            # Save Stage 2 reports
            if self.output_dir:
                # Markdown report
                report = generate_investigation_report(
                    pr_input, stage1_result, investigation_results, overall_verdict, stage2_duration
                )
                self._save_report(f"{pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_investigation.md", report)
                
                # JSON for benchmarking
                json_output = generate_investigation_json(
                    pr_input, stage1_result, investigation_results, stage2_duration
                )
                self._save_report(
                    f"{pr_input.owner}_{pr_input.repo}_PR-{pr_input.pull_number}_investigation.json",
                    json.dumps(json_output, indent=2)
                )
            
            total_tool_calls = sum(r.tool_calls for r in investigation_results)
            total_cost = sum(r.cost for r in investigation_results)
            
            logger.info(
                f"PR analysis complete: verdict={overall_verdict}, "
                f"skills_used={stage1_result.matching_skills}, "
                f"duration={duration:.2f}s"
            )
            
            return PRTriageResult(
                status=TriageStatus.COMPLETED.value,
                threat_model=stage1_result,
                investigation_results=investigation_results,
                overall_verdict=overall_verdict,
                skills_used=stage1_result.matching_skills,
                repos_searched=[pr_input.repository],
                total_tool_calls=total_tool_calls,
                total_cost=total_cost,
                total_time=duration,
            )
        
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"PR analysis failed after {duration:.2f}s: {e}", exc_info=True)
            
            return PRTriageResult(
                status=TriageStatus.FAILED.value,
                error=str(e),
                total_time=duration,
            )
    
    def _save_report(self, filename: str, content: str) -> Optional[str]:
        """Save a report to the output directory."""
        if not self.output_dir:
            return None
        
        filepath = Path(self.output_dir) / filename
        filepath.write_text(content)
        logger.info(f"Report saved: {filepath}")
        return str(filepath)
    
    async def close(self):
        """Clean up resources."""
        logger.info("Closing orchestrator resources")
        await self.github_client.close()
        logger.info("Orchestrator closed")
