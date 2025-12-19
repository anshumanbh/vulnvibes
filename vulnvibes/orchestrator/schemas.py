"""JSON schemas for structured output from Claude Agent SDK.

These schemas define the expected output format for Stage 1 (Threat Model)
and Stage 2 (Investigation Result) responses.
"""

# Structured output schema for Stage 1: Threat Model
THREAT_MODEL_SCHEMA = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {
            "what_are_we_working_on": {
                "type": "string",
                "description": "Summary of what the PR changes"
            },
            "what_can_go_wrong": {
                "type": "array",
                "items": {"type": "string"},
                "description": "High-level list of potential security issues"
            },
            "identified_threats": {
                "type": "array",
                "description": "Specific threats identified from the PR diff with investigation questions",
                "items": {
                    "type": "object",
                    "properties": {
                        "threat_id": {
                            "type": "string",
                            "description": "Unique identifier like THREAT-001"
                        },
                        "name": {
                            "type": "string",
                            "description": "Short threat title (e.g., 'IDOR in Document Access')"
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description of the specific threat"
                        },
                        "cwe_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Applicable CWE IDs"
                        },
                        "affected_code": {
                            "type": "string",
                            "description": "Specific file:line or endpoint affected"
                        },
                        "investigation_questions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Questions Stage 2 must answer to validate/invalidate this threat"
                        },
                        "matching_skills": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Skills to use for validating this threat"
                        }
                    },
                    "required": ["threat_id", "name", "description", "investigation_questions"]
                }
            },
            "matching_skills": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Aggregate list of all skills needed across threats (from .claude/skills/)"
            },
            "potential_vulns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of all CWE IDs identified"
            },
            "should_investigate": {
                "type": "boolean",
                "description": "Whether Stage 2 investigation is needed"
            },
            "rationale": {
                "type": "string",
                "description": "Reasoning for the should_investigate decision"
            }
        },
        "required": ["what_are_we_working_on", "identified_threats", "should_investigate", "rationale"]
    }
}


# Structured output schema for Stage 2: Investigation Result (Threat Validation)
INVESTIGATION_RESULT_SCHEMA = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {
            "threat_id": {
                "type": "string",
                "description": "The threat ID being validated (from Stage 1)"
            },
            "verdict": {
                "type": "string",
                "enum": ["TRUE_POSITIVE", "FALSE_POSITIVE", "NO_SKILL_AVAILABLE"],
                "description": "Final verdict: TRUE_POSITIVE (confirmed vuln), FALSE_POSITIVE (not a vuln), NO_SKILL_AVAILABLE (no skill covers the CWEs)"
            },
            "confidence_score": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10,
                "description": "Confidence score from 1-10"
            },
            "risk_level": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "description": "Risk severity level if TRUE_POSITIVE"
            },
            "risk_score": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "description": "Risk score from 0-100"
            },
            "reasoning_chain": {
                "type": "array",
                "description": "Step-by-step reasoning showing how the verdict was reached",
                "items": {
                    "type": "object",
                    "properties": {
                        "step": {"type": "integer", "description": "Step number"},
                        "action": {"type": "string", "description": "What was examined or done"},
                        "finding": {"type": "string", "description": "What was discovered"},
                        "significance": {"type": "string", "description": "Why this matters for the verdict"}
                    },
                    "required": ["step", "action", "finding", "significance"]
                }
            },
            "conclusion": {
                "type": "string",
                "description": "Final summary connecting evidence to verdict"
            },
            "recommendations": {
                "type": "string",
                "description": "Remediation steps if TRUE_POSITIVE"
            }
        },
        "required": ["verdict", "confidence_score", "reasoning_chain", "conclusion"]
    }
}
