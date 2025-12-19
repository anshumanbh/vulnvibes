"""Tests for orchestrator reports module."""

import pytest
from vulnvibes.orchestrator.reports import generate_investigation_json
from vulnvibes.models import (
    PRTriageInput,
    ThreatModel,
    IdentifiedThreat,
    InvestigationResult,
    ReasoningStep,
)


@pytest.fixture
def sample_pr_input() -> PRTriageInput:
    """Create a sample PR input for testing."""
    return PRTriageInput(
        pr_url="https://github.com/acme/backend/pull/42",
        org="acme"
    )


@pytest.fixture
def sample_threat() -> IdentifiedThreat:
    """Create a sample identified threat."""
    return IdentifiedThreat(
        threat_id="THREAT-001",
        name="IDOR in Document Access",
        description="GET /documents/{doc_id} missing ownership validation",
        cwe_ids=["CWE-639", "CWE-862"],
        affected_code="src/api.py:45-60",
        investigation_questions=["Is there auth check?"],
        matching_skills=["sast-authorization-testing"]
    )


@pytest.fixture
def sample_threat_model(sample_threat) -> ThreatModel:
    """Create a sample threat model."""
    model = ThreatModel(
        what_are_we_working_on="Adding document API",
        what_can_go_wrong=["IDOR vulnerability"],
        should_investigate=True,
        rationale="PR adds new endpoint"
    )
    model.identified_threats = [sample_threat]
    model.matching_skills = ["sast-authorization-testing"]
    return model


@pytest.fixture
def sample_investigation_result() -> InvestigationResult:
    """Create a sample investigation result."""
    return InvestigationResult(
        status="completed",
        verdict="TRUE_POSITIVE",
        confidence_score=8,
        risk_level="HIGH",
        risk_score=75,
        threat_id="THREAT-001",
        conclusion="Vulnerability confirmed",
        reasoning_chain=[
            ReasoningStep(
                step=1,
                action="Analyzed endpoint handler",
                finding="No ownership check found",
                significance="Direct IDOR vulnerability"
            )
        ]
    )


class TestGenerateInvestigationJson:
    """Tests for generate_investigation_json function."""

    def test_structure_has_required_keys(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test that JSON has required top-level keys."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=45.5
        )
        
        assert "pr_url" in result
        assert "investigation_metadata" in result
        assert "threats" in result
        assert "summary" in result

    def test_pr_url_preserved(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test that PR URL is preserved in output."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=45.5
        )
        
        assert result["pr_url"] == "https://github.com/acme/backend/pull/42"

    def test_investigation_metadata(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test investigation metadata fields."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=45.5
        )
        
        metadata = result["investigation_metadata"]
        assert metadata["agent_name"] == "vulnvibes"
        assert metadata["duration_seconds"] == 45.5
        assert metadata["repository"] == "acme/backend"
        assert "timestamp" in metadata

    def test_true_positive_verdict(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test TRUE_POSITIVE verdict passes through."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        assert result["threats"][0]["verdict"] == "TRUE_POSITIVE"

    def test_false_positive_verdict(self, sample_pr_input, sample_threat_model):
        """Test FALSE_POSITIVE verdict passes through."""
        inv_result = InvestigationResult(
            status="completed",
            verdict="FALSE_POSITIVE",
            confidence_score=9,
            risk_level=None,
            risk_score=None,
            threat_id="THREAT-001"
        )
        
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [inv_result],
            duration=10.0
        )
        
        assert result["threats"][0]["verdict"] == "FALSE_POSITIVE"

    def test_no_skill_available_maps_to_unknown(self, sample_pr_input, sample_threat_model):
        """Test NO_SKILL_AVAILABLE maps to UNKNOWN."""
        inv_result = InvestigationResult(
            status="completed",
            verdict="NO_SKILL_AVAILABLE",
            confidence_score=5,
            risk_level=None,
            risk_score=None,
            threat_id="THREAT-001"
        )
        
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [inv_result],
            duration=10.0
        )
        
        assert result["threats"][0]["verdict"] == "UNKNOWN"

    def test_missing_verdict_defaults_to_unknown(self, sample_pr_input, sample_threat_model):
        """Test missing verdict defaults to UNKNOWN."""
        inv_result = InvestigationResult(
            status="completed",
            verdict=None,
            confidence_score=5,
            risk_level=None,
            risk_score=None,
            threat_id="THREAT-001"
        )
        
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [inv_result],
            duration=10.0
        )
        
        assert result["threats"][0]["verdict"] == "UNKNOWN"

    def test_confidence_scaling(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test confidence scales from 1-10 to 0-100."""
        # sample_investigation_result has confidence_score=8
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        assert result["threats"][0]["confidence"] == 80

    def test_confidence_max_capped_at_100(self, sample_pr_input, sample_threat_model):
        """Test confidence capped at 100."""
        inv_result = InvestigationResult(
            status="completed",
            verdict="TRUE_POSITIVE",
            confidence_score=10,
            risk_level="HIGH",
            risk_score=80,
            threat_id="THREAT-001"
        )
        
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [inv_result],
            duration=10.0
        )
        
        assert result["threats"][0]["confidence"] == 100

    def test_confidence_default_when_missing(self, sample_pr_input, sample_threat_model):
        """Test confidence defaults to 50 when no investigation result."""
        # Create threat model with threat that has no matching investigation result
        threat = IdentifiedThreat(
            threat_id="THREAT-999",
            name="Unmatched threat",
            description="No investigation result for this"
        )
        model = ThreatModel()
        model.identified_threats = [threat]
        
        result = generate_investigation_json(
            sample_pr_input,
            model,
            [],  # No investigation results
            duration=10.0
        )
        
        assert result["threats"][0]["confidence"] == 50

    def test_severity_preserved(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test severity is preserved from investigation result."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        assert result["threats"][0]["severity"] == "HIGH"

    def test_severity_fallback_to_na(self, sample_pr_input, sample_threat_model):
        """Test severity defaults to N/A when missing."""
        inv_result = InvestigationResult(
            status="completed",
            verdict="FALSE_POSITIVE",
            confidence_score=9,
            risk_level=None,
            risk_score=None,
            threat_id="THREAT-001"
        )
        
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [inv_result],
            duration=10.0
        )
        
        assert result["threats"][0]["severity"] == "N/A"

    def test_name_from_threat(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test threat name is used when available."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        assert result["threats"][0]["name"] == "IDOR in Document Access"

    def test_name_fallback_to_description(self, sample_pr_input):
        """Test name falls back to truncated description when missing."""
        threat = IdentifiedThreat(
            threat_id="THREAT-001",
            name="",  # Empty name
            description="This is a very long description that should be truncated"
        )
        model = ThreatModel()
        model.identified_threats = [threat]
        
        result = generate_investigation_json(
            sample_pr_input,
            model,
            [],
            duration=10.0
        )
        
        assert result["threats"][0]["name"] == "This is a very long description that should be tru"

    def test_cwes_preserved(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test CWEs are preserved from threat."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        assert result["threats"][0]["cwes"] == ["CWE-639", "CWE-862"]

    def test_reasoning_chain_format(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test reasoning_chain includes repos_analyzed."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=10.0
        )
        
        chain = result["threats"][0]["reasoning_chain"]
        assert len(chain) == 1
        assert chain[0]["step"] == 1
        assert chain[0]["action"] == "Analyzed endpoint handler"
        assert chain[0]["finding"] == "No ownership check found"
        assert chain[0]["repos_analyzed"] == ["acme/backend"]

    def test_summary_counts(self, sample_pr_input):
        """Test true_positives and false_positives counts."""
        threat1 = IdentifiedThreat(threat_id="THREAT-001", name="T1")
        threat2 = IdentifiedThreat(threat_id="THREAT-002", name="T2")
        threat3 = IdentifiedThreat(threat_id="THREAT-003", name="T3")
        
        model = ThreatModel()
        model.identified_threats = [threat1, threat2, threat3]
        
        results = [
            InvestigationResult(status="completed", verdict="TRUE_POSITIVE", confidence_score=8, risk_level="HIGH", risk_score=75, threat_id="THREAT-001"),
            InvestigationResult(status="completed", verdict="FALSE_POSITIVE", confidence_score=9, risk_level=None, risk_score=None, threat_id="THREAT-002"),
            InvestigationResult(status="completed", verdict="TRUE_POSITIVE", confidence_score=7, risk_level="MEDIUM", risk_score=50, threat_id="THREAT-003"),
        ]
        
        output = generate_investigation_json(sample_pr_input, model, results, duration=30.0)
        
        assert output["summary"]["true_positives"] == 2
        assert output["summary"]["false_positives"] == 1

    def test_highest_severity_critical(self, sample_pr_input):
        """Test highest_severity identifies CRITICAL as worst."""
        threat1 = IdentifiedThreat(threat_id="THREAT-001", name="T1")
        threat2 = IdentifiedThreat(threat_id="THREAT-002", name="T2")
        
        model = ThreatModel()
        model.identified_threats = [threat1, threat2]
        
        results = [
            InvestigationResult(status="completed", verdict="TRUE_POSITIVE", confidence_score=8, risk_level="HIGH", risk_score=75, threat_id="THREAT-001"),
            InvestigationResult(status="completed", verdict="TRUE_POSITIVE", confidence_score=9, risk_level="CRITICAL", risk_score=95, threat_id="THREAT-002"),
        ]
        
        output = generate_investigation_json(sample_pr_input, model, results, duration=30.0)
        
        assert output["summary"]["highest_severity"] == "CRITICAL"

    def test_highest_severity_na_when_all_false_positives(self, sample_pr_input):
        """Test highest_severity is N/A when all false positives."""
        threat = IdentifiedThreat(threat_id="THREAT-001", name="T1")
        model = ThreatModel()
        model.identified_threats = [threat]
        
        results = [
            InvestigationResult(status="completed", verdict="FALSE_POSITIVE", confidence_score=9, risk_level=None, risk_score=None, threat_id="THREAT-001"),
        ]
        
        output = generate_investigation_json(sample_pr_input, model, results, duration=10.0)
        
        assert output["summary"]["highest_severity"] == "N/A"

    def test_empty_threats(self, sample_pr_input):
        """Test handling when no threats identified."""
        model = ThreatModel()
        model.identified_threats = []
        
        result = generate_investigation_json(
            sample_pr_input,
            model,
            [],
            duration=5.0
        )
        
        assert result["threats"] == []
        assert result["summary"]["true_positives"] == 0
        assert result["summary"]["false_positives"] == 0
        assert result["summary"]["highest_severity"] == "N/A"

    def test_duration_rounded(self, sample_pr_input, sample_threat_model, sample_investigation_result):
        """Test duration is rounded to 2 decimal places."""
        result = generate_investigation_json(
            sample_pr_input,
            sample_threat_model,
            [sample_investigation_result],
            duration=45.5678
        )
        
        assert result["investigation_metadata"]["duration_seconds"] == 45.57
