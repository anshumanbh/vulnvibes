"""Skill registry - single source of truth for available skills.

This module discovers skills bundled in the vulnvibes/skills/ directory.
Skills are distributed with the package and copied to target repos at runtime.

Provides:
- Automatic skill discovery from package
- CWE extraction from skill descriptions
- Dynamic table generation for prompts

Skills are automatically included in Stage 1 and Stage 2 prompts.
"""

import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional
import logging

logger = logging.getLogger(__name__)


class SkillInfo(NamedTuple):
    """Information about a discovered skill."""
    name: str
    description: str
    cwes: List[str]


# Cache for performance (skills don't change during runtime)
_cached_skills: Optional[Dict[str, SkillInfo]] = None


def discover_skills(skills_dir: Optional[Path] = None) -> Dict[str, SkillInfo]:
    """Discover all skills bundled with the package.
    
    Parses YAML frontmatter from SKILL.md files to extract:
    - name: skill name
    - description: skill description (CWEs are extracted from here)
    
    Args:
        skills_dir: Optional path to skills directory. If None, uses
                   the bundled skills in vulnvibes/skills/.
    
    Returns:
        Dictionary mapping skill names to SkillInfo objects.
    """
    global _cached_skills
    
    if _cached_skills is not None:
        return _cached_skills
    
    if skills_dir is None:
        # Primary: bundled skills inside package
        skills_dir = Path(__file__).parent / "skills"
    
    skills = {}
    
    if not skills_dir.exists():
        logger.warning(f"Skills directory not found: {skills_dir}")
        return skills
    
    logger.debug(f"Discovering skills from: {skills_dir}")
    
    for skill_dir in skills_dir.iterdir():
        if not skill_dir.is_dir():
            continue
        
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue
        
        try:
            content = skill_file.read_text()
            
            # Parse YAML frontmatter (between --- markers)
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    frontmatter_text = parts[1]
                    
                    # Simple YAML parsing (avoid heavy dependency)
                    name = skill_dir.name
                    description = ""
                    
                    for line in frontmatter_text.strip().split("\n"):
                        if line.startswith("name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("description:"):
                            description = line.split(":", 1)[1].strip()
                    
                    # Extract CWEs from description
                    cwes = re.findall(r"CWE-\d+", description)
                    
                    # Also check the full content for CWE mapping section
                    if "## CWE Mapping" in content:
                        cwe_section = content.split("## CWE Mapping")[1]
                        if "##" in cwe_section:
                            cwe_section = cwe_section.split("##")[0]
                        cwes.extend(re.findall(r"CWE-\d+", cwe_section))
                    
                    # Dedupe and sort
                    cwes = sorted(set(cwes), key=lambda x: int(x.split("-")[1]))
                    
                    skills[name] = SkillInfo(
                        name=name,
                        description=description,
                        cwes=cwes
                    )
                    logger.debug(f"Discovered skill: {name} with CWEs: {cwes}")
        
        except Exception as e:
            logger.warning(f"Failed to parse skill {skill_dir.name}: {e}")
            continue
    
    _cached_skills = skills
    logger.info(f"Discovered {len(skills)} skills: {list(skills.keys())}")
    
    return skills


def get_skill_names() -> List[str]:
    """Get list of all available skill names."""
    skills = discover_skills()
    return sorted(skills.keys())


def get_skill_cwes() -> Dict[str, List[str]]:
    """Get mapping of skill name to CWEs covered."""
    skills = discover_skills()
    return {name: list(info.cwes) for name, info in skills.items()}


def generate_skill_table() -> str:
    """Generate markdown table of skill coverage.
    
    Returns a markdown table like:
    | Skill Name | CWEs Covered |
    |------------|--------------|
    | sast-authorization-testing | CWE-269, CWE-639, CWE-862, CWE-863 |
    """
    skills = discover_skills()
    
    lines = [
        "| Skill Name | CWEs Covered |",
        "|------------|--------------|"
    ]
    
    for name in sorted(skills.keys()):
        info = skills[name]
        cwes = ", ".join(info.cwes) if info.cwes else "No CWEs specified"
        lines.append(f"| {name} | {cwes} |")
    
    return "\n".join(lines)


def generate_skill_list_for_prompt() -> str:
    """Generate skill list for Stage 1 prompt (with descriptions).
    
    Returns a bullet list like:
    - sast-authorization-testing: IDOR, privilege escalation (CWE-639, CWE-862, CWE-863)
    """
    skills = discover_skills()
    
    lines = []
    for name in sorted(skills.keys()):
        info = skills[name]
        # Truncate description if too long
        desc = info.description
        if len(desc) > 100:
            desc = desc[:97] + "..."
        
        cwes = f"({', '.join(info.cwes)})" if info.cwes else ""
        lines.append(f"- {name}: {desc} {cwes}".strip())
    
    return "\n".join(lines)


def get_skill_enum_values() -> List[str]:
    """Get skill names as list for JSON schema enum validation."""
    return get_skill_names()


def find_skills_for_cwes(cwe_ids: List[str]) -> List[str]:
    """Find skills that cover the given CWE IDs.
    
    Args:
        cwe_ids: List of CWE IDs like ["CWE-639", "CWE-862"]
    
    Returns:
        List of skill names that cover at least one of the given CWEs.
    """
    skills = discover_skills()
    matching = []
    
    cwe_set = set(cwe_ids)
    
    for name, info in skills.items():
        if set(info.cwes) & cwe_set:
            matching.append(name)
    
    return sorted(matching)


def clear_cache():
    """Clear the skill cache (useful for testing)."""
    global _cached_skills
    _cached_skills = None


# Convenience function for prompts
def get_skill_table() -> str:
    """Alias for generate_skill_table() for backward compatibility."""
    return generate_skill_table()
