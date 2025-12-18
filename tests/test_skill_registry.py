"""Tests for skill registry module."""

import tempfile
from pathlib import Path

import pytest

from vulnvibes.skill_registry import (
    discover_skills,
    get_skill_names,
    get_skill_cwes,
    generate_skill_table,
    generate_skill_list_for_prompt,
    get_skill_enum_values,
    find_skills_for_cwes,
    clear_cache,
    SkillInfo,
)


@pytest.fixture(autouse=True)
def clear_skill_cache():
    """Clear skill cache before each test."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def mock_skills_dir(tmp_path):
    """Create a temporary skills directory with mock skills."""
    skills_dir = tmp_path / ".claude" / "skills"
    skills_dir.mkdir(parents=True)
    
    # Create mock skill 1: authorization testing
    skill1_dir = skills_dir / "sast-authorization-testing"
    skill1_dir.mkdir()
    (skill1_dir / "SKILL.md").write_text("""---
name: sast-authorization-testing
description: Test authorization vulnerabilities including CWE-639 (IDOR), CWE-862, CWE-863.
allowed-tools: Read, Grep
---

# Authorization Testing Skill

## CWE Mapping
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
""")
    
    # Create mock skill 2: browser security
    skill2_dir = skills_dir / "sast-browser-security"
    skill2_dir.mkdir()
    (skill2_dir / "SKILL.md").write_text("""---
name: sast-browser-security
description: Browser security testing for CWE-346 (CORS) and CWE-352 (CSRF).
allowed-tools: Read, Grep
---

# Browser Security Skill
""")
    
    # Create an invalid skill (no SKILL.md)
    invalid_dir = skills_dir / "invalid-skill"
    invalid_dir.mkdir()
    
    return skills_dir


class TestDiscoverSkills:
    """Tests for discover_skills function."""
    
    def test_discover_skills_from_mock_dir(self, mock_skills_dir):
        """Test discovering skills from a mock directory."""
        skills = discover_skills(mock_skills_dir)
        
        assert len(skills) == 2
        assert "sast-authorization-testing" in skills
        assert "sast-browser-security" in skills
    
    def test_discover_skills_extracts_cwes_from_description(self, mock_skills_dir):
        """Test that CWEs are extracted from skill descriptions."""
        skills = discover_skills(mock_skills_dir)
        
        auth_skill = skills["sast-authorization-testing"]
        assert "CWE-639" in auth_skill.cwes
        assert "CWE-862" in auth_skill.cwes
        assert "CWE-863" in auth_skill.cwes
    
    def test_discover_skills_extracts_cwes_from_mapping_section(self, mock_skills_dir):
        """Test that CWEs are also extracted from CWE Mapping section."""
        skills = discover_skills(mock_skills_dir)
        
        # The authorization skill has CWEs in both description and mapping
        auth_skill = skills["sast-authorization-testing"]
        # Should have all unique CWEs from both sections
        assert len(auth_skill.cwes) >= 3
    
    def test_discover_skills_skips_invalid_dirs(self, mock_skills_dir):
        """Test that directories without SKILL.md are skipped."""
        skills = discover_skills(mock_skills_dir)
        
        assert "invalid-skill" not in skills
    
    def test_discover_skills_empty_dir(self, tmp_path):
        """Test discovering skills from an empty directory."""
        empty_dir = tmp_path / ".claude" / "skills"
        empty_dir.mkdir(parents=True)
        
        skills = discover_skills(empty_dir)
        
        assert len(skills) == 0
    
    def test_discover_skills_nonexistent_dir(self, tmp_path):
        """Test discovering skills from a non-existent directory."""
        nonexistent = tmp_path / "nonexistent"
        
        skills = discover_skills(nonexistent)
        
        assert len(skills) == 0
    
    def test_discover_skills_uses_real_skills_dir(self):
        """Test discovering skills from the real .claude/skills directory."""
        # This tests the actual skills in the repo
        skills = discover_skills()
        
        # Should find at least the known skills
        assert len(skills) >= 5
        assert "sast-authorization-testing" in skills
        assert "sast-authentication-testing" in skills
        assert "sast-browser-security-testing" in skills


class TestGetSkillNames:
    """Tests for get_skill_names function."""
    
    def test_get_skill_names_returns_sorted_list(self, mock_skills_dir):
        """Test that skill names are returned as a sorted list."""
        # First discover from mock dir to populate cache
        discover_skills(mock_skills_dir)
        clear_cache()  # Clear cache so it uses real dir
        
        names = get_skill_names()
        
        assert isinstance(names, list)
        assert names == sorted(names)
    
    def test_get_skill_names_from_real_dir(self):
        """Test getting skill names from real directory."""
        names = get_skill_names()
        
        assert "sast-authorization-testing" in names
        assert "sast-browser-security-testing" in names


class TestGetSkillCwes:
    """Tests for get_skill_cwes function."""
    
    def test_get_skill_cwes_returns_dict(self):
        """Test that get_skill_cwes returns a dictionary."""
        cwes = get_skill_cwes()
        
        assert isinstance(cwes, dict)
        
        # Check structure
        for skill_name, cwe_list in cwes.items():
            assert isinstance(skill_name, str)
            assert isinstance(cwe_list, list)
            for cwe in cwe_list:
                assert cwe.startswith("CWE-")
    
    def test_get_skill_cwes_includes_browser_security(self):
        """Test that browser security skill CWEs are included."""
        cwes = get_skill_cwes()
        
        assert "sast-browser-security-testing" in cwes
        browser_cwes = cwes["sast-browser-security-testing"]
        assert "CWE-346" in browser_cwes  # CORS
        assert "CWE-352" in browser_cwes  # CSRF


class TestGenerateSkillTable:
    """Tests for generate_skill_table function."""
    
    def test_generate_skill_table_format(self):
        """Test that generated table has correct markdown format."""
        table = generate_skill_table()
        
        lines = table.strip().split("\n")
        
        # Should have header row
        assert "| Skill Name | CWEs Covered |" in lines[0]
        # Should have separator row
        assert "|---" in lines[1]
        # Should have data rows
        assert len(lines) >= 3
    
    def test_generate_skill_table_includes_all_skills(self):
        """Test that table includes all discovered skills."""
        table = generate_skill_table()
        
        assert "sast-authorization-testing" in table
        assert "sast-authentication-testing" in table
        assert "sast-browser-security-testing" in table
        assert "sast-injection-testing" in table
    
    def test_generate_skill_table_includes_cwes(self):
        """Test that table includes CWE IDs."""
        table = generate_skill_table()
        
        assert "CWE-" in table
        assert "CWE-346" in table  # Browser security
        assert "CWE-639" in table  # Authorization


class TestFindSkillsForCwes:
    """Tests for find_skills_for_cwes function."""
    
    def test_find_skills_for_cors_cwes(self):
        """Test finding skills for CORS-related CWEs."""
        cwes = ["CWE-346", "CWE-942"]
        matching = find_skills_for_cwes(cwes)
        
        assert "sast-browser-security-testing" in matching
    
    def test_find_skills_for_auth_cwes(self):
        """Test finding skills for authentication CWEs."""
        cwes = ["CWE-287", "CWE-384"]
        matching = find_skills_for_cwes(cwes)
        
        assert "sast-authentication-testing" in matching
    
    def test_find_skills_for_authz_cwes(self):
        """Test finding skills for authorization CWEs."""
        cwes = ["CWE-639", "CWE-862"]
        matching = find_skills_for_cwes(cwes)
        
        assert "sast-authorization-testing" in matching
    
    def test_find_skills_for_unknown_cwe(self):
        """Test finding skills for an unknown CWE."""
        cwes = ["CWE-99999"]
        matching = find_skills_for_cwes(cwes)
        
        assert len(matching) == 0
    
    def test_find_skills_for_empty_list(self):
        """Test finding skills with empty CWE list."""
        matching = find_skills_for_cwes([])
        
        assert len(matching) == 0
    
    def test_find_skills_returns_sorted(self):
        """Test that matching skills are returned sorted."""
        # Use multiple CWEs that might match different skills
        cwes = ["CWE-287", "CWE-639"]
        matching = find_skills_for_cwes(cwes)
        
        assert matching == sorted(matching)


class TestSkillInfo:
    """Tests for SkillInfo named tuple."""
    
    def test_skill_info_creation(self):
        """Test creating a SkillInfo object."""
        info = SkillInfo(
            name="test-skill",
            description="A test skill for CWE-123",
            cwes=["CWE-123", "CWE-456"]
        )
        
        assert info.name == "test-skill"
        assert info.description == "A test skill for CWE-123"
        assert len(info.cwes) == 2
        assert "CWE-123" in info.cwes


class TestCacheClearing:
    """Tests for cache clearing functionality."""
    
    def test_clear_cache_resets_discovery(self, mock_skills_dir):
        """Test that clear_cache allows re-discovery."""
        # First discovery
        skills1 = discover_skills(mock_skills_dir)
        
        # Clear and discover from real dir
        clear_cache()
        skills2 = discover_skills()
        
        # Should have different skills
        # (mock has 2, real has 6)
        assert len(skills1) != len(skills2)


class TestGenerateSkillListForPrompt:
    """Tests for generate_skill_list_for_prompt function."""
    
    def test_generates_bullet_list(self):
        """Test that skill list has bullet format."""
        result = generate_skill_list_for_prompt()
        
        lines = result.strip().split("\n")
        assert all(line.startswith("- ") for line in lines)
    
    def test_includes_cwes_in_parentheses(self):
        """Test that CWEs appear in parentheses format."""
        result = generate_skill_list_for_prompt()
        
        assert "(CWE-" in result
        assert ")" in result
    
    def test_includes_all_skills(self):
        """Test that all skills appear in list."""
        result = generate_skill_list_for_prompt()
        
        assert "sast-authorization-testing" in result
        assert "sast-ssrf-testing" in result


class TestGetSkillEnumValues:
    """Tests for get_skill_enum_values function."""
    
    def test_returns_same_as_get_skill_names(self):
        """Test that enum values match skill names."""
        enum_values = get_skill_enum_values()
        skill_names = get_skill_names()
        
        assert enum_values == skill_names
    
    def test_returns_list_of_strings(self):
        """Test that enum values are strings."""
        enum_values = get_skill_enum_values()
        
        assert isinstance(enum_values, list)
        assert all(isinstance(v, str) for v in enum_values)
