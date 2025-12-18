"""Tests for data models."""

import pytest

from vulnvibes.models import (
    InvestigationResult,
    PRTriageInput,
    PRTriageResult,
    ThreatModel,
    UserContext,
    IdentifiedThreat,
    ReasoningStep,
    TriageStatus,
)


class TestTriageStatus:
    """Tests for TriageStatus enum."""
    
    def test_enum_values(self):
        """Test that all expected status values exist."""
        assert TriageStatus.COMPLETED.value == "completed"
        assert TriageStatus.FAILED.value == "failed"
        assert TriageStatus.NO_SIGNAL.value == "no_signal"
        assert TriageStatus.NO_SKILLS.value == "no_skills"
        assert TriageStatus.IN_PROGRESS.value == "in_progress"
    
    def test_enum_count(self):
        """Test that we have exactly 5 statuses."""
        assert len(TriageStatus) == 5


class TestUserContext:
    """Tests for UserContext model."""
    
    def test_creation_empty(self):
        """Test creating empty UserContext."""
        ctx = UserContext()
        assert ctx.related_repos == []
        assert ctx.ignore_vulns == []
        assert ctx.free_form_context == ""
    
    def test_has_context_false_when_empty(self):
        """Test has_context is False for empty context."""
        ctx = UserContext()
        assert ctx.has_context is False
    
    def test_has_context_true_with_repos(self):
        """Test has_context is True when related_repos provided."""
        ctx = UserContext(related_repos=[{"name": "infra", "purpose": "configs"}])
        assert ctx.has_context is True
    
    def test_has_context_true_with_ignore_vulns(self):
        """Test has_context is True when ignore_vulns provided."""
        ctx = UserContext(ignore_vulns=["CWE-916"])
        assert ctx.has_context is True
    
    def test_has_context_true_with_free_form(self):
        """Test has_context is True when free_form_context provided."""
        ctx = UserContext(free_form_context="Architecture notes here")
        assert ctx.has_context is True
    
    def test_has_context_false_with_whitespace_only(self):
        """Test has_context is False when free_form_context is only whitespace."""
        ctx = UserContext(free_form_context="   \n\t  ")
        assert ctx.has_context is False
    
    def test_to_dict(self):
        """Test UserContext serialization."""
        ctx = UserContext(
            related_repos=[{"name": "api"}],
            ignore_vulns=["CWE-79"],
            free_form_context="Notes"
        )
        data = ctx.to_dict()
        assert data["related_repos"] == [{"name": "api"}]
        assert data["ignore_vulns"] == ["CWE-79"]
        assert data["free_form_context"] == "Notes"


class TestIdentifiedThreat:
    """Tests for IdentifiedThreat model."""
    
    def test_creation(self):
        """Test creating IdentifiedThreat."""
        threat = IdentifiedThreat(
            threat_id="THREAT-001",
            description="Potential IDOR vulnerability",
            cwe_ids=["CWE-639", "CWE-862"],
            affected_code="src/api.py:45-60",
            investigation_questions=["Is there auth check?"],
            matching_skills=["sast-authorization-testing"]
        )
        assert threat.threat_id == "THREAT-001"
        assert len(threat.cwe_ids) == 2
        assert "CWE-639" in threat.cwe_ids
    
    def test_defaults(self):
        """Test IdentifiedThreat default values."""
        threat = IdentifiedThreat(
            threat_id="THREAT-002",
            description="Test threat"
        )
        assert threat.cwe_ids == []
        assert threat.affected_code == ""
        assert threat.investigation_questions == []
        assert threat.matching_skills == []
    
    def test_to_dict(self):
        """Test IdentifiedThreat serialization."""
        threat = IdentifiedThreat(
            threat_id="THREAT-001",
            description="Test",
            cwe_ids=["CWE-89"]
        )
        data = threat.to_dict()
        assert data["threat_id"] == "THREAT-001"
        assert data["cwe_ids"] == ["CWE-89"]


class TestReasoningStep:
    """Tests for ReasoningStep model."""
    
    def test_creation(self):
        """Test creating ReasoningStep."""
        step = ReasoningStep(
            step=1,
            action="Read auth.py",
            finding="No input validation",
            significance="User input flows directly to SQL"
        )
        assert step.step == 1
        assert step.action == "Read auth.py"
    
    def test_to_dict(self):
        """Test ReasoningStep serialization."""
        step = ReasoningStep(step=2, action="Search", finding="Found", significance="Important")
        data = step.to_dict()
        assert data["step"] == 2
        assert data["action"] == "Search"


class TestPRTriageInput:
    """Tests for PRTriageInput model."""
    
    def test_url_parsing(self):
        """Test PR URL parsing extracts owner, repo, pull_number."""
        pr_input = PRTriageInput(pr_url="https://github.com/acme/webapp/pull/123")
        assert pr_input.owner == "acme"
        assert pr_input.repo == "webapp"
        assert pr_input.pull_number == 123
        assert pr_input.org == "acme"
    
    def test_url_parsing_with_trailing_content(self):
        """Test PR URL parsing with extra path segments."""
        pr_input = PRTriageInput(pr_url="https://github.com/org/repo/pull/456/files")
        assert pr_input.owner == "org"
        assert pr_input.repo == "repo"
        assert pr_input.pull_number == 456
    
    def test_repository_property(self):
        """Test repository property returns owner/repo format."""
        pr_input = PRTriageInput(pr_url="https://github.com/test/project/pull/1")
        assert pr_input.repository == "test/project"
    
    def test_org_override(self):
        """Test org can be overridden."""
        pr_input = PRTriageInput(
            pr_url="https://github.com/user/repo/pull/1",
            org="my-org"
        )
        assert pr_input.org == "my-org"
        assert pr_input.owner == "user"
    
    def test_invalid_url(self):
        """Test that invalid URL doesn't crash, just leaves fields empty."""
        pr_input = PRTriageInput(pr_url="not-a-valid-url")
        assert pr_input.owner == ""
        assert pr_input.repo == ""
        assert pr_input.pull_number == 0
    
    def test_to_dict(self):
        """Test PRTriageInput serialization."""
        pr_input = PRTriageInput(pr_url="https://github.com/a/b/pull/99")
        data = pr_input.to_dict()
        assert data["pr_url"] == "https://github.com/a/b/pull/99"
        assert data["owner"] == "a"
        assert data["pull_number"] == 99


class TestThreatModel:
    """Tests for ThreatModel model."""
    
    def test_creation(self):
        """Test creating ThreatModel."""
        model = ThreatModel(
            what_are_we_working_on="Adding new API endpoint",
            what_can_go_wrong=["SQL injection", "IDOR"],
            should_investigate=True,
            matching_skills=["sast-injection-testing"],
            potential_vulns=["CWE-89"]
        )
        assert model.should_investigate is True
        assert len(model.what_can_go_wrong) == 2
    
    def test_defaults(self):
        """Test ThreatModel default values."""
        model = ThreatModel()
        assert model.what_are_we_working_on == ""
        assert model.what_can_go_wrong == []
        assert model.should_investigate is False
        assert model.identified_threats == []
    
    def test_to_dict_with_nested_threats(self):
        """Test ThreatModel serialization with nested IdentifiedThreat objects."""
        threat = IdentifiedThreat(threat_id="T-1", description="Test")
        model = ThreatModel(
            what_are_we_working_on="Test",
            identified_threats=[threat]
        )
        data = model.to_dict()
        assert len(data["identified_threats"]) == 1
        assert data["identified_threats"][0]["threat_id"] == "T-1"


class TestPRTriageResult:
    """Tests for PRTriageResult model."""
    
    def test_creation(self):
        """Test creating PRTriageResult."""
        result = PRTriageResult(
            status="completed",
            overall_verdict="TRUE_POSITIVE",
            skills_used=["sast-injection-testing"],
            total_cost=0.50
        )
        assert result.status == "completed"
        assert result.overall_verdict == "TRUE_POSITIVE"
    
    def test_defaults(self):
        """Test PRTriageResult default values."""
        result = PRTriageResult(status="no_signal")
        assert result.threat_model is None
        assert result.investigation_results == []
        assert result.overall_verdict is None
        assert result.total_cost == 0.0
    
    def test_to_dict_with_nested_objects(self):
        """Test PRTriageResult serialization with nested objects."""
        threat_model = ThreatModel(what_are_we_working_on="Test PR")
        inv_result = InvestigationResult(
            status="completed",
            verdict="FALSE_POSITIVE",
            confidence_score=9,
            risk_level="LOW",
            risk_score=10
        )
        result = PRTriageResult(
            status="completed",
            threat_model=threat_model,
            investigation_results=[inv_result]
        )
        data = result.to_dict()
        assert data["threat_model"]["what_are_we_working_on"] == "Test PR"
        assert data["investigation_results"][0]["verdict"] == "FALSE_POSITIVE"


class TestInvestigationResult:
    """Tests for InvestigationResult model."""
    
    def test_creation(self):
        """Test InvestigationResult model creation."""
        result = InvestigationResult(
            status="completed",
            verdict="TRUE_POSITIVE",
            confidence_score=8,
            risk_level="HIGH",
            risk_score=75,
            agent_analysis="Test analysis",
            tool_calls=5,
            cost=0.01,
            investigation_time=10.5,
        )
        assert result.status == "completed"
        assert result.verdict == "TRUE_POSITIVE"
        assert result.confidence_score == 8
        assert result.risk_level == "HIGH"
        assert result.risk_score == 75
        assert result.tool_calls == 5
        assert result.cost == 0.01

    def test_to_dict(self):
        """Test InvestigationResult serialization."""
        result = InvestigationResult(
            status="completed",
            verdict="FALSE_POSITIVE",
            confidence_score=9,
            risk_level="LOW",
            risk_score=10,
            agent_analysis="No vulnerability found",
            reasoning_steps=["Step 1", "Step 2"],
            tool_calls=3,
            cost=0.005,
            investigation_time=5.2,
        )
        data = result.to_dict()
        assert isinstance(data, dict)
        assert data["status"] == "completed"
        assert data["verdict"] == "FALSE_POSITIVE"
        assert data["confidence_score"] == 9
        assert len(data["reasoning_steps"]) == 2

    def test_defaults(self):
        """Test InvestigationResult default values."""
        result = InvestigationResult(
            status="completed",
            verdict="TRUE_POSITIVE",
            confidence_score=7,
            risk_level=None,
            risk_score=None,
        )
        assert result.risk_level is None
        assert result.risk_score is None
        assert result.risk_rationale is None
        assert result.agent_analysis == ""
        assert result.reasoning_steps == []
        assert result.tool_calls == 0
        assert result.cost == 0.0
        assert result.investigation_time == 0.0
        assert result.error is None

    def test_failed(self):
        """Test InvestigationResult for failed investigation."""
        result = InvestigationResult(
            status="failed",
            verdict=None,
            confidence_score=None,
            risk_level=None,
            risk_score=None,
            error="Connection timeout",
        )
        assert result.status == "failed"
        assert result.verdict is None
        assert result.error == "Connection timeout"
    
    def test_to_dict_with_reasoning_chain(self):
        """Test InvestigationResult serialization with ReasoningStep objects."""
        step = ReasoningStep(step=1, action="Read", finding="Found issue", significance="Critical")
        result = InvestigationResult(
            status="completed",
            verdict="TRUE_POSITIVE",
            confidence_score=8,
            risk_level="HIGH",
            risk_score=80,
            reasoning_chain=[step]
        )
        data = result.to_dict()
        assert len(data["reasoning_chain"]) == 1
        assert data["reasoning_chain"][0]["step"] == 1
