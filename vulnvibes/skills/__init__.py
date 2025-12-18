"""Bundled skills for vulnerability investigation.

Skills are copied to target repositories at runtime for Claude Agent SDK discovery.
"""

from pathlib import Path

SKILLS_DIR = Path(__file__).parent


def get_skills_dir() -> Path:
    """Return the path to the bundled skills directory."""
    return SKILLS_DIR
