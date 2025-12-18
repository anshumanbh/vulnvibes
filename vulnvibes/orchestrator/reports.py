"""Markdown report generation for triage results.

This module generates human-readable markdown reports for
Stage 1 (Threat Model) and Stage 2 (Investigation) results.
"""

import json
from datetime import datetime
from typing import List, Optional

from ..models import PRTriageInput, ThreatModel, InvestigationResult


def generate_threat_model_report(
    pr_input: PRTriageInput, 
    threat_model: ThreatModel,
    duration: float
) -> str:
    """Generate markdown report for Stage 1 threat model.
    
    Args:
        pr_input: PR input details
        threat_model: Parsed threat model from Stage 1
        duration: Analysis duration in seconds
        
    Returns:
        Markdown formatted report string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        f"# Threat Model: PR #{pr_input.pull_number}",
        "",
        f"**Repository:** {pr_input.repository}  ",
        f"**PR URL:** {pr_input.pr_url}  ",
        f"**Organization:** {pr_input.org}  ",
        f"**Analyzed:** {timestamp}  ",
        f"**Duration:** {duration:.2f}s  ",
        f"**Analyzer:** pr-analyzer subagent",
        "",
        "---",
        "",
        "## PR Summary",
        "",
        threat_model.what_are_we_working_on or "_No summary available_",
        "",
    ]
    
    # What can go wrong section
    if threat_model.what_can_go_wrong:
        lines.extend([
            "## What Can Go Wrong",
            "",
        ])
        for issue in threat_model.what_can_go_wrong:
            lines.append(f"- {issue}")
        lines.append("")
    
    # Identified threats section
    if threat_model.identified_threats:
        lines.extend([
            "## Identified Threats",
            "",
        ])
        
        for threat in threat_model.identified_threats:
            lines.extend([
                f"### {threat.threat_id}: {threat.description[:80]}{'...' if len(threat.description) > 80 else ''}",
                "",
                f"**Description:** {threat.description}",
                "",
            ])
            
            if threat.cwe_ids:
                lines.append(f"**CWEs:** {', '.join(threat.cwe_ids)}")
                lines.append("")
            
            if threat.affected_code:
                lines.append(f"**Affected Code:** `{threat.affected_code}`")
                lines.append("")
            
            if threat.investigation_questions:
                lines.append("**Investigation Questions:**")
                for i, q in enumerate(threat.investigation_questions, 1):
                    lines.append(f"{i}. {q}")
                lines.append("")
            
            if threat.matching_skills:
                lines.append(f"**Skills to Use:** {', '.join(threat.matching_skills)}")
                lines.append("")
            
            lines.extend(["---", ""])
    
    # Decision section
    lines.extend([
        "## Decision",
        "",
        f"**Should Investigate:** {'✅ Yes' if threat_model.should_investigate else '❌ No'}  ",
    ])
    
    if threat_model.matching_skills:
        lines.append(f"**Matching Skills:** {', '.join(threat_model.matching_skills)}  ")
    
    if threat_model.potential_vulns:
        lines.append(f"**Potential CWEs:** {', '.join(threat_model.potential_vulns)}  ")
    
    lines.extend([
        "",
        f"**Rationale:** {threat_model.rationale or '_No rationale provided_'}",
        "",
    ])
    
    return "\n".join(lines)


def generate_investigation_report(
    pr_input: PRTriageInput,
    threat_model: ThreatModel,
    results: List[InvestigationResult],
    overall_verdict: Optional[str],
    duration: float
) -> str:
    """Generate markdown report for Stage 2 investigation.
    
    Args:
        pr_input: PR input details
        threat_model: Threat model from Stage 1
        results: List of investigation results from Stage 2
        overall_verdict: Aggregated verdict
        duration: Investigation duration in seconds
        
    Returns:
        Markdown formatted report string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Verdict emoji
    verdict_display = {
        "TRUE_POSITIVE": "⚠️ TRUE POSITIVE",
        "FALSE_POSITIVE": "✅ FALSE POSITIVE",
        "NO_SKILL_AVAILABLE": "🔧 NO SKILL AVAILABLE",
        "MIXED": "⚡ MIXED RESULTS",
    }.get(overall_verdict, "❓ UNKNOWN")
    
    lines = [
        f"# Security Investigation Report: PR #{pr_input.pull_number}",
        "",
        f"**Repository:** {pr_input.repository}  ",
        f"**PR URL:** {pr_input.pr_url}  ",
        f"**Organization:** {pr_input.org}  ",
        f"**Completed:** {timestamp}  ",
        f"**Duration:** {duration:.2f}s  ",
        f"**Investigator:** vuln-investigator subagent",
        "",
        f"## Overall Verdict: {verdict_display}",
        "",
        "---",
        "",
    ]
    
    # Individual threat results
    for result in results:
        threat_id = result.threat_id or "UNKNOWN"
        
        # Find the original threat for context
        original_threat = next(
            (t for t in threat_model.identified_threats if t.threat_id == threat_id),
            None
        )
        
        verdict_emoji = {
            "TRUE_POSITIVE": "⚠️",
            "FALSE_POSITIVE": "✅",
            "NO_SKILL_AVAILABLE": "🔧",
        }.get(result.verdict, "❓")
        
        threat_desc = ""
        if original_threat:
            threat_desc = original_threat.description[:60] + '...' if len(original_threat.description) > 60 else original_threat.description
        else:
            threat_desc = "Investigation Result"
        
        lines.extend([
            f"## {threat_id}: {threat_desc}",
            "",
            f"**Verdict:** {verdict_emoji} {result.verdict or 'UNKNOWN'}  ",
            f"**Confidence:** {result.confidence_score or 'N/A'}/10  ",
            f"**Risk Level:** {result.risk_level or 'N/A'}" + (f" ({result.risk_score}/100)" if result.risk_score else ""),
            "",
        ])
        
        # Reasoning chain table
        if result.reasoning_chain:
            lines.extend([
                "### Reasoning Chain",
                "",
                "| Step | Action | Finding | Significance |",
                "|------|--------|---------|--------------|",
            ])
            
            for step in result.reasoning_chain:
                # Escape pipe characters and truncate long text
                action = (step.action or "").replace("|", "\\|")[:80]
                finding = (step.finding or "").replace("|", "\\|")[:100]
                significance = (step.significance or "").replace("|", "\\|")[:80]
                
                lines.append(f"| {step.step} | {action} | {finding} | {significance} |")
            
            lines.append("")
        
        # Conclusion
        if result.conclusion:
            lines.extend([
                "### Conclusion",
                "",
                result.conclusion,
                "",
            ])
        
        # Recommendations (parse from agent_analysis if available)
        if result.agent_analysis and "recommendations" in result.agent_analysis.lower():
            try:
                analysis_data = json.loads(result.agent_analysis)
                if analysis_data.get("recommendations"):
                    lines.extend([
                        "### Recommendations",
                        "",
                        analysis_data["recommendations"],
                        "",
                    ])
            except (json.JSONDecodeError, KeyError):
                pass
        
        lines.extend(["---", ""])
    
    # Summary section
    successful = sum(1 for r in results if r.verdict)
    true_positives = sum(1 for r in results if r.verdict == "TRUE_POSITIVE")
    false_positives = sum(1 for r in results if r.verdict == "FALSE_POSITIVE")
    no_skill = sum(1 for r in results if r.verdict == "NO_SKILL_AVAILABLE")
    
    lines.extend([
        "## Summary",
        "",
        f"- **Threats Analyzed:** {len(results)}",
        f"- **Successful Validations:** {successful}/{len(results)}",
        f"- **True Positives:** {true_positives}",
        f"- **False Positives:** {false_positives}",
    ])
    
    if no_skill > 0:
        lines.append(f"- **No Skill Available:** {no_skill} (CWEs not covered by available skills)")
    
    lines.extend([
        f"- **Total Duration:** {duration:.2f}s",
        "",
    ])
    
    return "\n".join(lines)
