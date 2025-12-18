"""Response parsing for Stage 1 and Stage 2 outputs.

This module handles parsing of Claude Agent SDK responses into
structured data models for threat models and investigation results.
"""

import json
import re
from typing import List, Optional

from ..models import (
    ThreatModel, InvestigationResult, IdentifiedThreat, ReasoningStep
)
from ..skill_registry import get_skill_names
from ..utils.logging import get_logger

logger = get_logger("orchestrator.parsers")


def extract_final_response(messages: list) -> str:
    """Extract final assistant response from messages.
    
    Prioritizes StructuredOutput tool use blocks (from output_format schema),
    then falls back to text blocks.
    
    Note: We check type(msg).__name__ instead of msg.role because the SDK
    returns AssistantMessage objects where .role may be None/N/A.
    
    Args:
        messages: List of messages from Claude Agent SDK
        
    Returns:
        Extracted response string (JSON or text)
    """
    # First pass: Look for StructuredOutput tool use blocks (structured output)
    for msg in reversed(messages):
        if type(msg).__name__ == 'AssistantMessage':
            if hasattr(msg, 'content') and msg.content:
                for block in msg.content:
                    block_class = type(block).__name__
                    if block_class == 'ToolUseBlock' or (hasattr(block, 'type') and block.type == 'tool_use'):
                        tool_name = getattr(block, 'name', '')
                        if tool_name == 'StructuredOutput':
                            tool_input = getattr(block, 'input', {})
                            logger.info(f"Found StructuredOutput tool use, input type: {type(tool_input).__name__}")
                            if tool_input:
                                json_str = json.dumps(tool_input)
                                logger.info(f"Extracted JSON ({len(json_str)} chars): {json_str[:200]}...")
                                return json_str
                            else:
                                logger.warning(f"StructuredOutput tool_input is empty: {tool_input}")
    
    # Second pass: Look for text blocks
    for msg in reversed(messages):
        if type(msg).__name__ == 'AssistantMessage':
            if hasattr(msg, 'content') and msg.content:
                text_parts = []
                for block in msg.content:
                    block_class = type(block).__name__
                    if block_class == 'TextBlock' or (hasattr(block, 'type') and block.type == 'text'):
                        if hasattr(block, 'text'):
                            text_parts.append(block.text)
                if text_parts:
                    return "\n\n".join(text_parts)
    
    # Fallback
    for msg in reversed(messages):
        if hasattr(msg, 'content'):
            content = msg.content
            if isinstance(content, str):
                return content
            elif isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and block.get('type') == 'text':
                        text_parts.append(block.get('text', ''))
                    elif hasattr(block, 'text'):
                        text_parts.append(block.text)
                if text_parts:
                    return "\n\n".join(text_parts)
    
    return ""


def parse_threat_model(response: str) -> ThreatModel:
    """Parse threat model from Stage 1 response (JSON or fallback to regex).
    
    Args:
        response: Raw response string from Stage 1
        
    Returns:
        Parsed ThreatModel object
    """
    model = ThreatModel()
    
    # Try to parse as JSON first (structured output)
    try:
        json_str = response.strip()
        
        # Handle markdown code blocks
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()
        
        data = json.loads(json_str)
        
        model.what_are_we_working_on = data.get("what_are_we_working_on", "")
        model.what_can_go_wrong = data.get("what_can_go_wrong", [])
        model.matching_skills = data.get("matching_skills", [])
        model.potential_vulns = data.get("potential_vulns", [])
        model.should_investigate = data.get("should_investigate", False)
        model.rationale = data.get("rationale", "")
        
        # Parse identified_threats (new format)
        identified_threats_data = data.get("identified_threats", [])
        for threat_data in identified_threats_data:
            threat = IdentifiedThreat(
                threat_id=threat_data.get("threat_id", f"THREAT-{len(model.identified_threats)+1}"),
                description=threat_data.get("description", ""),
                cwe_ids=threat_data.get("cwe_ids", []),
                affected_code=threat_data.get("affected_code", ""),
                investigation_questions=threat_data.get("investigation_questions", []),
                matching_skills=threat_data.get("matching_skills", [])
            )
            model.identified_threats.append(threat)
        
        logger.info(f"Successfully parsed Stage 1 response: {len(model.identified_threats)} threats identified")
        return model
        
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.warning(f"Failed to parse Stage 1 response as JSON ({e}), falling back to regex parsing")
    
    # Fallback: Parse using regex (old method)
    if "### What are we working on?" in response:
        section = response.split("### What are we working on?")[1]
        if "###" in section:
            section = section.split("###")[0]
        model.what_are_we_working_on = section.strip()
    
    if "### What can go wrong?" in response:
        section = response.split("### What can go wrong?")[1]
        if "###" in section:
            section = section.split("###")[0]
        model.what_can_go_wrong = [line.strip() for line in section.strip().split("\n") if line.strip()]
    
    if "### Matching Skills" in response:
        section = response.split("### Matching Skills")[1]
        if "###" in section:
            section = section.split("###")[0]
        skills = []
        available_skills = get_skill_names()
        for line in section.strip().split("\n"):
            line = line.strip().strip("-").strip()
            if line and line.lower() != "none":
                for skill_name in available_skills:
                    if skill_name in line.lower():
                        skills.append(skill_name)
        model.matching_skills = skills
    
    # Parse decision
    if "should_investigate" in response.lower():
        model.should_investigate = "true" in response.lower().split("should_investigate")[1][:50].lower()
    
    if "rationale" in response.lower():
        section = response.lower().split("rationale")[1]
        if "\n" in section:
            model.rationale = section.split("\n")[0].strip(": ").strip()
    
    # Extract CWE IDs
    cwe_pattern = r"CWE-\d+"
    model.potential_vulns = list(set(re.findall(cwe_pattern, response)))
    
    return model


def parse_investigation_result(
    response: str, 
    duration: float,
    threat_id: str
) -> InvestigationResult:
    """Parse investigation result from Stage 2 response (JSON or fallback to regex).
    
    Args:
        response: Raw response string from Stage 2
        duration: Investigation duration in seconds
        threat_id: The threat ID being validated
        
    Returns:
        Parsed InvestigationResult object
    """
    logger.info(f"Parsing Stage 2 ({threat_id}) response: {len(response)} chars, preview: {response[:100]}...")
    
    # Try to parse as JSON first (structured output)
    data = None
    json_str = response.strip()
    
    # Strategy 1: Try direct JSON parse
    if json_str.startswith('{'):
        try:
            data = json.loads(json_str)
            logger.info(f"Successfully parsed Stage 2 ({threat_id}) response as direct JSON")
        except json.JSONDecodeError:
            pass
    
    # Strategy 2: Try extracting from markdown code blocks
    if data is None and "```json" in json_str:
        try:
            extracted = json_str.split("```json")[1].split("```")[0].strip()
            data = json.loads(extracted)
            logger.info(f"Successfully parsed Stage 2 ({threat_id}) response from ```json block")
        except (json.JSONDecodeError, IndexError):
            pass
    
    # Strategy 3: Try finding JSON object in the response
    if data is None:
        try:
            start = json_str.find('{')
            end = json_str.rfind('}')
            if start != -1 and end != -1 and end > start:
                extracted = json_str[start:end+1]
                data = json.loads(extracted)
                logger.info(f"Successfully parsed Stage 2 ({threat_id}) response by extracting JSON object")
        except json.JSONDecodeError:
            pass
    
    # If JSON parsing succeeded, build the result with reasoning chain
    if data is not None:
        reasoning_chain = []
        for step_data in data.get("reasoning_chain", []):
            step = ReasoningStep(
                step=step_data.get("step", len(reasoning_chain) + 1),
                action=step_data.get("action", ""),
                finding=step_data.get("finding", ""),
                significance=step_data.get("significance", "")
            )
            reasoning_chain.append(step)
        
        result = InvestigationResult(
            status="completed",
            verdict=data.get("verdict"),
            confidence_score=data.get("confidence_score"),
            risk_level=data.get("risk_level"),
            risk_score=data.get("risk_score"),
            agent_analysis=json.dumps(data),
            reasoning_chain=reasoning_chain,
            conclusion=data.get("conclusion", ""),
            threat_id=data.get("threat_id", threat_id),
            investigation_time=duration,
        )
        logger.info(f"Parsed {threat_id}: verdict={result.verdict}, {len(reasoning_chain)} reasoning steps")
        return result
    
    logger.warning(f"Failed to parse Stage 2 ({threat_id}) response as JSON, falling back to regex parsing")
    
    # Fallback: Parse using regex (old method)
    result = InvestigationResult(
        status="completed",
        verdict=None,
        confidence_score=None,
        risk_level=None,
        risk_score=None,
        agent_analysis=response,
        threat_id=threat_id,
        investigation_time=duration,
    )
    
    # Parse verdict
    response_lower = response.lower()
    if "true_positive" in response_lower:
        result.verdict = "TRUE_POSITIVE"
    elif "false_positive" in response_lower:
        result.verdict = "FALSE_POSITIVE"
    
    # Parse confidence score
    confidence_match = re.search(r"confidence_score[:\s]*(\d+)", response_lower)
    if confidence_match:
        result.confidence_score = int(confidence_match.group(1))
    
    # Parse risk level
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level.lower() in response_lower:
            result.risk_level = level
            break
    
    # Try to parse risk_score
    risk_score_match = re.search(r"risk_score[:\s]*(\d+)", response_lower)
    if risk_score_match:
        result.risk_score = int(risk_score_match.group(1))
    
    return result


def aggregate_verdicts(results: List[InvestigationResult]) -> Optional[str]:
    """Aggregate verdicts from multiple investigations.
    
    Args:
        results: List of InvestigationResult objects
        
    Returns:
        Aggregated verdict string or None if no verdicts
    """
    verdicts = [r.verdict for r in results if r.verdict]
    
    if not verdicts:
        return None
    
    # Filter out NO_SKILL_AVAILABLE for the main verdict assessment
    actionable_verdicts = [v for v in verdicts if v != "NO_SKILL_AVAILABLE"]
    
    if not actionable_verdicts:
        return "NO_SKILL_AVAILABLE"
    
    if all(v == "TRUE_POSITIVE" for v in actionable_verdicts):
        return "TRUE_POSITIVE"
    elif all(v == "FALSE_POSITIVE" for v in actionable_verdicts):
        return "FALSE_POSITIVE"
    else:
        return "MIXED"
