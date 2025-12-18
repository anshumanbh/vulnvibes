"""Stage execution logic for PR triage workflow.

This module contains the execution logic for Stage 1 (Threat Modeling)
and Stage 2 (Investigation) of the PR triage workflow.
"""

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

from ..models import (
    PRTriageInput, ThreatModel, InvestigationResult, IdentifiedThreat
)
from ..skill_registry import generate_skill_table, get_skill_names
from ..utils.logging import get_logger
from .schemas import THREAT_MODEL_SCHEMA, INVESTIGATION_RESULT_SCHEMA
from .parsers import extract_final_response, parse_threat_model, parse_investigation_result

if TYPE_CHECKING:
    from . import PRTriageOrchestrator

logger = get_logger("orchestrator.stages")


async def run_stage1(
    orchestrator: 'PRTriageOrchestrator',
    pr_input: PRTriageInput,
    additional_context: Optional[Dict[str, Any]] = None,
) -> ThreatModel:
    """Run Stage 1: PR Analysis & Threat Modeling.
    
    Uses the pr-analyzer subagent to:
    1. Fetch the PR diff
    2. Summarize changes
    3. Perform threat modeling
    4. Match to available skills
    
    Args:
        orchestrator: The PRTriageOrchestrator instance
        pr_input: PR input details
        additional_context: Optional additional context
        
    Returns:
        Parsed ThreatModel object
    """
    logger.info("Starting Stage 1: PR Analysis & Threat Modeling")
    
    # Format user context if available
    user_context_section = orchestrator._format_user_context()
    context_instructions = ""
    if user_context_section:
        context_instructions = f"""
## User-Provided Context (IMPORTANT - Use this to understand the architecture)
{user_context_section}
"""
    else:
        context_instructions = """
## No User Context Provided
No architectural context was provided. Focus solely on threats visible in the PR diff.
If you need to understand the broader architecture, use github_list_org_repos to discover related repositories.
"""
    
    # Generate dynamic skill information
    stage1_skill_table = generate_skill_table()
    valid_skill_names = ", ".join(get_skill_names())
    
    # Build the Stage 1 task
    task = f"""Analyze this pull request and identify SPECIFIC threats introduced by the changes.

## Pull Request
- **URL**: {pr_input.pr_url}
- **Repository**: {pr_input.repository}
- **PR Number**: {pr_input.pull_number}
- **Organization**: {pr_input.org}
{context_instructions}
## Your Task
1. Use `github_get_pr_diff` to fetch the PR diff for {pr_input.owner}/{pr_input.repo} PR #{pr_input.pull_number}
2. Identify SPECIFIC security threats introduced by THIS PR (not pre-existing issues)
3. For EACH threat, generate investigation questions that Stage 2 must answer
4. Match each threat to the skills needed to validate it

## CRITICAL INSTRUCTIONS
- Focus ONLY on threats introduced by THIS PR's changes
- Do NOT report pre-existing vulnerabilities unrelated to the PR
- Each threat must have specific investigation questions
- Questions should guide Stage 2 to check for security controls at ALL layers

## Available Skills (dynamically loaded from .claude/skills/)
{stage1_skill_table}

## Output Format
{{
    "what_are_we_working_on": "Summary of PR changes",
    "what_can_go_wrong": ["High-level threat summary"],
    "identified_threats": [
        {{
            "threat_id": "THREAT-001",
            "description": "Potential IDOR in GET /documents/{{doc_id}} - endpoint queries DB with user-provided ID",
            "cwe_ids": ["CWE-639", "CWE-862"],
            "affected_code": "src/main.py:45-50 - GET /documents/{{doc_id}}",
            "investigation_questions": [
                "Does this endpoint have application-level ownership checks (e.g., doc.owner_id == user_id)?",
                "Is there middleware that validates document access before the handler runs?",
                "Are there infrastructure controls (nginx, API gateway) that restrict access?",
                "How do similar endpoints in this codebase handle authorization?"
            ],
            "matching_skills": ["sast-authorization-testing"]
        }}
    ],
    "matching_skills": ["sast-authorization-testing"],
    "potential_vulns": ["CWE-639", "CWE-862"],
    "should_investigate": true,
    "rationale": "PR adds new endpoint with potential IDOR vulnerability"
}}

Valid skill names: {valid_skill_names}

If no security concerns from the PR, set should_investigate to false with empty identified_threats.
"""
    
    # Set up Claude Agent options for Stage 1 with structured output
    options = ClaudeAgentOptions(
        mcp_servers={"github": orchestrator.github_tools_server},
        allowed_tools=["mcp__github__*"],
        max_turns=orchestrator.max_tool_calls,
        agents=orchestrator.agents,
        setting_sources=["project"],
        output_format=THREAT_MODEL_SCHEMA,
        permission_mode='bypassPermissions',
    )
    
    messages = []
    
    async with ClaudeSDKClient(options=options) as client:
        logger.info("Sending Stage 1 task to pr-analyzer agent")
        
        # Request the pr-analyzer subagent
        await client.query(f"Use the pr-analyzer agent: {task}")
        
        async for msg in client.receive_response():
            messages.append(msg)
            logger.debug(f"Stage 1 message: {type(msg).__name__}")
    
    # Log message details for debugging
    logger.info(f"Stage 1 received {len(messages)} messages")
    for i, msg in enumerate(messages):
        msg_type = type(msg).__name__
        has_content = hasattr(msg, 'content') and msg.content
        role = getattr(msg, 'role', 'N/A')
        logger.info(f"  Message {i}: type={msg_type}, role={role}, has_content={has_content}")
        if has_content and isinstance(msg.content, list):
            for j, block in enumerate(msg.content):
                block_type = getattr(block, 'type', type(block).__name__)
                logger.info(f"    Block {j}: type={block_type}")
    
    # Parse the response into ThreatModel
    final_response = extract_final_response(messages)
    
    # Log what we extracted
    logger.info(f"Stage 1 extracted response: {len(final_response)} chars")
    if final_response:
        logger.info(f"Stage 1 response preview: {final_response[:500]}...")
    else:
        logger.warning("Stage 1 extracted response is EMPTY - check message extraction logic")
    
    threat_model = parse_threat_model(final_response)
    
    logger.info(
        f"Stage 1 complete: should_investigate={threat_model.should_investigate}, "
        f"matching_skills={threat_model.matching_skills}"
    )
    
    return threat_model


async def run_stage2(
    orchestrator: 'PRTriageOrchestrator',
    pr_input: PRTriageInput,
    threat_model: ThreatModel,
    additional_context: Optional[Dict[str, Any]] = None,
) -> List[InvestigationResult]:
    """Run Stage 2: Threat Validation.
    
    Validates each specific threat identified in Stage 1:
    1. Uses the investigation questions to guide analysis
    2. Checks for security controls at ALL layers
    3. Produces verdict with full reasoning chain
    
    Args:
        orchestrator: The PRTriageOrchestrator instance
        pr_input: PR input details
        threat_model: Threat model from Stage 1
        additional_context: Optional additional context
        
    Returns:
        List of InvestigationResult objects
    """
    import time
    
    threats_to_validate = threat_model.identified_threats
    
    # Fallback for backward compatibility
    if not threats_to_validate and threat_model.matching_skills:
        logger.warning("No identified_threats found, falling back to skill-based investigation")
        threats_to_validate = [
            IdentifiedThreat(
                threat_id=f"LEGACY-{i+1}",
                description=issue,
                cwe_ids=threat_model.potential_vulns,
                investigation_questions=["Investigate this potential vulnerability"],
                matching_skills=threat_model.matching_skills
            )
            for i, issue in enumerate(threat_model.what_can_go_wrong or ["Potential security issue"])
        ]
    
    # Scale max_turns based on number of threats
    base_turns = 30
    turns_per_threat = 15
    scaled_max_turns = base_turns + max(0, len(threats_to_validate) - 1) * turns_per_threat
    
    logger.info(
        f"Starting Stage 2: Validating {len(threats_to_validate)} threat(s) "
        f"with {scaled_max_turns} max turns"
    )
    
    results = []
    user_context_section = orchestrator._format_user_context()
    
    for threat in threats_to_validate:
        logger.info(f"Validating threat: {threat.threat_id} - {threat.description}")
        
        questions_str = "\n".join(f"  {i+1}. {q}" for i, q in enumerate(threat.investigation_questions))
        skills_str = ", ".join(threat.matching_skills) if threat.matching_skills else "general security analysis"
        
        if user_context_section:
            context_block = f"""## User-Provided Context (PRIORITIZE THIS)
{user_context_section}
"""
        else:
            context_block = """## No User Context Provided
Discover context using available tools. Use github_list_org_repos to find related repositories.
"""
        
        skill_coverage_table = generate_skill_table()
        
        task = f"""Validate this SPECIFIC threat from PR #{pr_input.pull_number}:

## Threat to Validate
- **Threat ID**: {threat.threat_id}
- **Description**: {threat.description}
- **CWEs**: {', '.join(threat.cwe_ids) if threat.cwe_ids else 'Not specified'}
- **Affected Code**: {threat.affected_code or 'See PR diff'}
- **Suggested Skills**: {skills_str}

## Investigation Questions (YOU MUST ANSWER EACH ONE)
{questions_str}

## Repository Context
- **Repository**: {pr_input.repository}
- **PR Number**: {pr_input.pull_number}
- **Organization**: {pr_input.org}

{context_block}
## AVAILABLE SKILLS AND CWE COVERAGE (IMPORTANT)
You MUST use a skill to investigate this threat. Skills are invoked automatically based on context.
Check if the threat's CWEs match any skill's coverage:

{skill_coverage_table}

**SKILL MATCHING RULES:**
- If the threat's CWEs match a skill's coverage → USE that skill and investigate
- If NO skill covers any of the threat's CWEs → Set verdict to "NO_SKILL_AVAILABLE" immediately
- Do NOT attempt to investigate threats without a matching skill

## CRITICAL INSTRUCTIONS
1. FIRST check if any skill covers the threat's CWEs ({', '.join(threat.cwe_ids) if threat.cwe_ids else 'None'})
2. If NO matching skill exists, return verdict "NO_SKILL_AVAILABLE" with a brief explanation
3. If a matching skill exists, use it and validate the specific threat ({threat.threat_id})
4. Answer EACH investigation question with evidence from the codebase
5. Check for security controls at ALL layers
6. Document EVERY step of your investigation in the reasoning_chain

## Output Format
{{
    "threat_id": "{threat.threat_id}",
    "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NO_SKILL_AVAILABLE",
    "confidence_score": 1-10,
    "risk_level": "LOW", "MEDIUM", "HIGH", or "CRITICAL" (or null if NO_SKILL_AVAILABLE),
    "risk_score": 0-100 (or null if NO_SKILL_AVAILABLE),
    "reasoning_chain": [
        {{"step": 1, "action": "Checked skill coverage", "finding": "...", "significance": "..."}},
        ...
    ],
    "conclusion": "Final summary",
    "recommendations": "Remediation steps or explanation"
}}
"""
        
        options = ClaudeAgentOptions(
            mcp_servers={"github": orchestrator.github_tools_server},
            allowed_tools=["mcp__github__*", "Skill"],
            max_turns=scaled_max_turns,
            agents=orchestrator.agents,
            setting_sources=["project"],
            output_format=INVESTIGATION_RESULT_SCHEMA,
            permission_mode='bypassPermissions',
        )
        
        messages = []
        start_time = time.time()
        turn_count = 0
        total_cost = 0.0
        budget_exhausted = False
        
        async with ClaudeSDKClient(options=options) as client:
            logger.info(f"Sending Stage 2 task for threat: {threat.threat_id}")
            
            await client.query(f"Use the vuln-investigator agent: {task}")
            
            async for msg in client.receive_response():
                messages.append(msg)
                msg_type = type(msg).__name__
                
                # Track cost from ResultMessage
                if msg_type == 'ResultMessage':
                    usage = getattr(msg, 'usage', None)
                    if usage and isinstance(usage, dict):
                        input_tokens = usage.get('input_tokens', 0)
                        output_tokens = usage.get('output_tokens', 0)
                        cache_read = usage.get('cache_read_input_tokens', 0)
                        cache_creation = usage.get('cache_creation_input_tokens', 0)
                        
                        cost = (
                            (input_tokens * 3.0 / 1_000_000) +
                            (output_tokens * 15.0 / 1_000_000) +
                            (cache_read * 0.30 / 1_000_000) +
                            (cache_creation * 3.75 / 1_000_000)
                        )
                        total_cost += cost
                
                if msg_type == 'AssistantMessage':
                    turn_count += 1
                    if turn_count >= scaled_max_turns:
                        logger.warning(f"Turn budget EXHAUSTED for {threat.threat_id}")
                        budget_exhausted = True
                        break
        
        duration = time.time() - start_time
        
        tool_call_count = sum(
            1 for msg in messages 
            if type(msg).__name__ == 'AssistantMessage' and hasattr(msg, 'content') and msg.content
            for block in msg.content
            if type(block).__name__ == 'ToolUseBlock' or (hasattr(block, 'type') and block.type == 'tool_use')
        )
        
        final_response = extract_final_response(messages)
        result = parse_investigation_result(final_response, duration, threat.threat_id)
        result.tool_calls = tool_call_count
        result.cost = total_cost
        results.append(result)
        
        logger.info(
            f"Threat {threat.threat_id} validation complete: verdict={result.verdict}, "
            f"turns_used={turn_count}/{scaled_max_turns}, cost=${total_cost:.4f}"
        )
    
    return results
