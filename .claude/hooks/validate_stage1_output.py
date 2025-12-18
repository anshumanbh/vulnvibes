#!/usr/bin/env python3
"""
Hook: Validate Stage 1 Output

Validates that the pr-analyzer subagent produced a complete threat model
with all required sections before proceeding to Stage 2.

Hook Event: SubagentStop
Matcher: pr-analyzer
"""
import json
import sys


def validate_threat_model(result: str) -> dict:
    """
    Validate that the threat model contains required sections.
    
    Required sections:
    - What are we working on?
    - What can go wrong?
    - Matching Skills
    - Decision (with should_investigate)
    """
    required_sections = [
        "What are we working on",
        "What can go wrong",
        "Matching Skills",
        "Decision",
    ]
    
    missing = []
    for section in required_sections:
        # Check for various formats (###, ##, or just the text)
        if section.lower() not in result.lower():
            missing.append(section)
    
    if missing:
        return {
            "valid": False,
            "missing": missing,
            "message": f"Threat model incomplete. Missing sections: {missing}"
        }
    
    # Check for should_investigate decision
    if "should_investigate" not in result.lower():
        return {
            "valid": False,
            "missing": ["should_investigate decision"],
            "message": "Threat model missing should_investigate decision"
        }
    
    return {"valid": True, "message": "Threat model validation passed"}


def main():
    """Main hook entry point."""
    try:
        # Read hook input from stdin
        input_data = json.load(sys.stdin)
        
        # Get the subagent result
        result = input_data.get("result", "")
        
        # Validate the threat model
        validation = validate_threat_model(result)
        
        if not validation["valid"]:
            # Return a system message to guide the agent
            output = {
                "systemMessage": (
                    f"[Hook] Stage 1 validation failed: {validation['message']}. "
                    f"Please complete the threat model with all required sections: "
                    f"1) What are we working on? 2) What can go wrong? "
                    f"3) Matching Skills 4) Decision (should_investigate: true/false)"
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
