"""Tests for agent definitions module."""

import pytest

from vulnvibes.agents.definitions import (
    _build_pr_analyzer_prompt,
    create_agent_definitions,
    get_available_skills,
    AGENT_PROMPTS,
)
from vulnvibes.skill_registry import clear_cache


@pytest.fixture(autouse=True)
def clear_skill_cache():
    """Clear skill cache before each test."""
    clear_cache()
    yield
    clear_cache()


class TestBuildPrAnalyzerPrompt:
    """Tests for dynamic prompt building."""
    
    def test_includes_skill_table(self):
        """Test that prompt includes dynamic skill table."""
        prompt = _build_pr_analyzer_prompt()
        
        assert "| Skill Name | CWEs Covered |" in prompt
        assert "sast-authorization-testing" in prompt
        assert "sast-browser-security-testing" in prompt
    
    def test_includes_skill_matching_rules(self):
        """Test that prompt includes skill matching guidance."""
        prompt = _build_pr_analyzer_prompt()
        
        assert "Match by CWE" in prompt
        assert "No matching skill?" in prompt
        assert "matching_skills: []" in prompt
    
    def test_includes_new_skills(self):
        """Test that prompt includes newly added skills."""
        prompt = _build_pr_analyzer_prompt()
        
        # New skills added in recent session
        assert "sast-ssrf-testing" in prompt
        assert "sast-deserialization-testing" in prompt
        assert "sast-file-security-testing" in prompt
        assert "sast-security-misconfiguration-testing" in prompt


class TestGetAvailableSkills:
    """Tests for get_available_skills convenience function."""
    
    def test_returns_skill_list(self):
        """Test that function returns list of skill names."""
        skills = get_available_skills()
        
        assert isinstance(skills, list)
        assert len(skills) >= 10
    
    def test_includes_all_skill_categories(self):
        """Test that all skill categories are represented."""
        skills = get_available_skills()
        
        # Original 6 skills
        assert "sast-authentication-testing" in skills
        assert "sast-authorization-testing" in skills
        assert "sast-browser-security-testing" in skills
        assert "sast-cryptography-testing" in skills
        assert "sast-data-exposure-testing" in skills
        assert "sast-injection-testing" in skills
        
        # New 4 skills
        assert "sast-ssrf-testing" in skills
        assert "sast-deserialization-testing" in skills
        assert "sast-file-security-testing" in skills
        assert "sast-security-misconfiguration-testing" in skills


class TestCreateAgentDefinitions:
    """Tests for agent definition creation."""
    
    def test_creates_both_agents(self):
        """Test that both agents are created."""
        agents = create_agent_definitions()
        
        assert "pr-analyzer" in agents
        assert "vuln-investigator" in agents
    
    def test_pr_analyzer_has_skill_table(self):
        """Test that pr-analyzer prompt has skill table."""
        agents = create_agent_definitions()
        
        prompt = agents["pr-analyzer"].prompt
        assert "| Skill Name | CWEs Covered |" in prompt
    
    def test_vuln_investigator_has_methodology(self):
        """Test that vuln-investigator prompt has investigation methodology."""
        agents = create_agent_definitions()
        
        prompt = agents["vuln-investigator"].prompt
        assert "Investigation Methodology" in prompt
        assert "TRUE_POSITIVE" in prompt
        assert "FALSE_POSITIVE" in prompt
    
    def test_vuln_investigator_has_github_tools(self):
        """Test that vuln-investigator prompt documents all GitHub tools."""
        agents = create_agent_definitions()
        
        prompt = agents["vuln-investigator"].prompt
        
        # Check all 8 GitHub tools are documented
        assert "github_read_file" in prompt
        assert "github_list_files" in prompt
        assert "github_glob_files" in prompt
        assert "github_code_search" in prompt
        assert "github_org_code_search" in prompt
        assert "github_get_diff" in prompt
        assert "github_get_pr_diff" in prompt
        assert "github_list_org_repos" in prompt
        
        # Check tool categories
        assert "Reading Code" in prompt
        assert "Searching Code" in prompt
        assert "Comparing Changes" in prompt
        assert "Organization Discovery" in prompt


class TestAgentPrompts:
    """Tests for AGENT_PROMPTS dictionary."""
    
    def test_contains_vuln_investigator(self):
        """Test that AGENT_PROMPTS has vuln_investigator prompt."""
        # pr_analyzer is built dynamically via _build_pr_analyzer_prompt()
        # and is NOT cached in AGENT_PROMPTS (it has dynamic skill table)
        assert "vuln_investigator" in AGENT_PROMPTS
    
    def test_vuln_investigator_prompt_not_empty(self):
        """Test that vuln_investigator prompt is non-empty."""
        assert len(AGENT_PROMPTS["vuln_investigator"]) > 100
    
    def test_pr_analyzer_built_dynamically(self):
        """Test that pr_analyzer prompt is built fresh each time."""
        prompt1 = _build_pr_analyzer_prompt()
        prompt2 = _build_pr_analyzer_prompt()
        
        # Both should be non-empty and contain skill table
        assert len(prompt1) > 100
        assert "| Skill Name | CWEs Covered |" in prompt1
        assert prompt1 == prompt2  # Should be identical (same skills)
