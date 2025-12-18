"""Tests for bundled skills module."""

from pathlib import Path

import pytest

from vulnvibes.skills import get_skills_dir, SKILLS_DIR


class TestSkillsDir:
    """Tests for skills directory utilities."""
    
    def test_skills_dir_constant(self):
        """Test SKILLS_DIR is a Path object."""
        assert isinstance(SKILLS_DIR, Path)
    
    def test_skills_dir_exists(self):
        """Test bundled skills directory exists."""
        assert SKILLS_DIR.exists()
        assert SKILLS_DIR.is_dir()
    
    def test_get_skills_dir_returns_path(self):
        """Test get_skills_dir returns a Path."""
        result = get_skills_dir()
        assert isinstance(result, Path)
    
    def test_get_skills_dir_equals_constant(self):
        """Test get_skills_dir returns same path as SKILLS_DIR."""
        assert get_skills_dir() == SKILLS_DIR
    
    def test_skills_dir_contains_skills(self):
        """Test skills directory contains expected skill subdirectories."""
        skills_dir = get_skills_dir()
        subdirs = [d.name for d in skills_dir.iterdir() if d.is_dir() and not d.name.startswith("_")]
        
        # Should have at least 10 skills
        assert len(subdirs) >= 10
        
        # Check for expected skills
        assert "sast-authorization-testing" in subdirs
        assert "sast-authentication-testing" in subdirs
        assert "sast-injection-testing" in subdirs
        assert "sast-browser-security-testing" in subdirs
    
    def test_each_skill_has_skill_md(self):
        """Test each skill directory contains a SKILL.md file."""
        skills_dir = get_skills_dir()
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("_"):
                skill_file = skill_dir / "SKILL.md"
                assert skill_file.exists(), f"Missing SKILL.md in {skill_dir.name}"
    
    def test_skill_md_has_frontmatter(self):
        """Test SKILL.md files have YAML frontmatter."""
        skills_dir = get_skills_dir()
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("_"):
                skill_file = skill_dir / "SKILL.md"
                content = skill_file.read_text()
                assert content.startswith("---"), f"No frontmatter in {skill_dir.name}/SKILL.md"
                # Should have closing frontmatter delimiter
                parts = content.split("---", 2)
                assert len(parts) >= 3, f"Incomplete frontmatter in {skill_dir.name}/SKILL.md"
    
    def test_skill_md_has_name_field(self):
        """Test SKILL.md frontmatter contains name field."""
        skills_dir = get_skills_dir()
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("_"):
                skill_file = skill_dir / "SKILL.md"
                content = skill_file.read_text()
                assert "name:" in content, f"No name field in {skill_dir.name}/SKILL.md"
    
    def test_skill_md_has_description_field(self):
        """Test SKILL.md frontmatter contains description field."""
        skills_dir = get_skills_dir()
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("_"):
                skill_file = skill_dir / "SKILL.md"
                content = skill_file.read_text()
                assert "description:" in content, f"No description field in {skill_dir.name}/SKILL.md"
