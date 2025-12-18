"""Pytest configuration and fixtures."""

import json
from pathlib import Path
from typing import Dict, Any

import pytest
from pytest_mock import MockerFixture

from vulnvibes.models import InvestigationResult


@pytest.fixture
def sample_investigation_result() -> InvestigationResult:
    """Sample investigation result for testing."""
    return InvestigationResult(
        status="completed",
        verdict="TRUE_POSITIVE",
        confidence_score=8,
        risk_level="HIGH",
        risk_score=75,
        risk_rationale="Direct SQL injection with no validation",
        agent_analysis="""
**VERDICT**: [TRUE POSITIVE - High Confidence]

**CONFIDENCE SCORE**: [8]

**DETAILED ANALYSIS:**
The vulnerability is a true positive SQL injection...

Risk Level: HIGH
Risk Score: 75
Risk Rationale: User input flows directly to SQL query without sanitization.
        """,
        reasoning_steps=[
            "Step 1: github_read_file(repo='test-org/test-app', path='app/auth.py')",
            "Step 2: github_code_search(query='username')",
            "Step 3: github_read_file(repo='test-org/test-app', path='app/routes.py')",
        ],
        tool_calls=3,
        cost=0.0123,
        investigation_time=15.7,
    )


@pytest.fixture
def mock_github_search_response() -> Dict[str, Any]:
    """Mock GitHub code search API response."""
    return {
        "total_count": 2,
        "items": [
            {
                "name": "auth.py",
                "path": "app/auth.py",
                "sha": "abc123",
                "repository": {
                    "full_name": "test-org/test-app"
                },
                "html_url": "https://github.com/test-org/test-app/blob/main/app/auth.py"
            },
            {
                "name": "routes.py",
                "path": "app/routes.py",
                "sha": "def456",
                "repository": {
                    "full_name": "test-org/test-app"
                },
                "html_url": "https://github.com/test-org/test-app/blob/main/app/routes.py"
            }
        ]
    }


@pytest.fixture
def mock_github_file_response() -> Dict[str, Any]:
    """Mock GitHub file contents API response."""
    import base64
    
    code = '''def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
'''
    
    return {
        "name": "auth.py",
        "path": "app/auth.py",
        "size": len(code),
        "content": base64.b64encode(code.encode()).decode(),
        "encoding": "base64"
    }


@pytest.fixture
def user_context() -> Dict[str, Any]:
    """Sample user context for testing."""
    return {
        "organization": "TestOrg",
        "security_standards": "OWASP Top 10",
        "tech_stack": "Python Flask",
    }


@pytest.fixture
def github_token() -> str:
    """Mock GitHub token."""
    return "ghp_test_token_123456"


@pytest.fixture
def anthropic_api_key() -> str:
    """Mock Anthropic API key."""
    return "sk-ant-test-key-123456"
