#!/usr/bin/env python3
"""
Hook: Validate Investigation Result

Validates that the vuln-investigator subagent produced a complete
investigation result with verdict, confidence, and evidence.

Hook Event: SubagentStop
Matcher: vuln-investigator
"""
import json
import sys
import re


def validate_investigation(result: str) -> dict:
    """
    Validate that the investigation result contains required elements.
    
    Required elements:
    - verdict (TRUE_POSITIVE or FALSE_POSITIVE)
    - confidence_score (1-10)
    - risk_level (LOW, MEDIUM, HIGH, CRITICAL)
    - Evidence section
    """
    issues = []
    
    # Check for verdict
    result_lower = result.lower()
    has_verdict = "true_positive" in result_lower or "false_positive" in result_lower
    if not has_verdict:
        issues.append("Missing verdict (TRUE_POSITIVE or FALSE_POSITIVE)")
    
    # Check for confidence score
    confidence_match = re.search(r"confidence_score[:\s]*(\d+)", result_lower)
    if not confidence_match:
        issues.append("Missing confidence_score (1-10)")
    else:
        score = int(confidence_match.group(1))
        if not 1 <= score <= 10:
            issues.append(f"Invalid confidence_score: {score} (must be 1-10)")
    
    # Check for risk level
    risk_levels = ["critical", "high", "medium", "low"]
    has_risk = any(level in result_lower for level in risk_levels)
    if not has_risk:
        issues.append("Missing risk_level (LOW, MEDIUM, HIGH, or CRITICAL)")
    
    # Check for evidence section
    has_evidence = "evidence" in result_lower or "location" in result_lower
    if not has_evidence:
        issues.append("Missing Evidence section with code locations")
    
    if issues:
        return {
            "valid": False,
            "issues": issues,
            "message": f"Investigation incomplete: {'; '.join(issues)}"
        }
    
    return {"valid": True, "message": "Investigation validation passed"}


def main():
    """Main hook entry point."""
    try:
        # Read hook input from stdin
        input_data = json.load(sys.stdin)
        
        # Get the subagent result
        result = input_data.get("result", "")
        
        # Validate the investigation result
        validation = validate_investigation(result)
        
        if not validation["valid"]:
            # Return a system message to guide the agent
            output = {
                "systemMessage": (
                    f"[Hook] Investigation validation failed: {validation['message']}. "
                    f"Please provide a complete investigation result with: "
                    f"1) verdict (TRUE_POSITIVE or FALSE_POSITIVE) "
                    f"2) confidence_score (1-10) "
                    f"3) risk_level (LOW/MEDIUM/HIGH/CRITICAL) "
                    f"4) Evidence with specific code locations"
                )
            }
            print(json.dumps(output))
        else:
            # Validation passed, no action needed
            print(json.dumps({}))
    
    except Exception as e:
        # Log error but don't block the agent
        sys.stderr.write(f"Hook error: {e}\n")
        print(json.dumps({}))


if __name__ == "__main__":
    main()
