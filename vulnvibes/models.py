"""Data models for vulnerability triage agent."""
import re
from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any
from enum import Enum


class TriageStatus(Enum):
    """Status of a triage operation."""
    COMPLETED = "completed"
    FAILED = "failed"
    NO_SIGNAL = "no_signal"
    NO_SKILLS = "no_skills"
    IN_PROGRESS = "in_progress"


@dataclass
class UserContext:
    """User-provided context for PR analysis from markdown file with optional YAML frontmatter."""
    
    related_repos: List[Dict[str, str]] = field(default_factory=list)  # [{"name": "infra-ops", "purpose": "nginx configs"}]
    ignore_vulns: List[str] = field(default_factory=list)  # ["CWE-916"] - known issues to skip
    free_form_context: str = ""  # The markdown body with architecture notes, security controls, etc.
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @property
    def has_context(self) -> bool:
        """Check if any context was provided."""
        return bool(self.related_repos or self.ignore_vulns or self.free_form_context.strip())


@dataclass
class IdentifiedThreat:
    """A specific threat identified from the PR diff in Stage 1."""
    
    threat_id: str  # Unique ID like "THREAT-001"
    name: str = ""  # Short title like "IDOR in Document Access"
    description: str = ""  # Detailed description of the threat
    cwe_ids: List[str] = field(default_factory=list)  # ["CWE-639", "CWE-862"]
    affected_code: str = ""  # "src/main.py:45-50 - GET /documents/{doc_id}"
    investigation_questions: List[str] = field(default_factory=list)  # Questions to answer in Stage 2
    matching_skills: List[str] = field(default_factory=list)  # Skills to use for validation
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReasoningStep:
    """A single step in the investigation reasoning chain."""
    
    step: int
    action: str  # What was done
    finding: str  # What was found
    significance: str  # Why it matters
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PRTriageInput:
    """Input: A pull request to analyze for security vulnerabilities."""
    
    pr_url: str  # "https://github.com/owner/repo/pull/123"
    
    # Parsed from PR URL
    owner: str = ""
    repo: str = ""
    pull_number: int = 0
    
    # Optional overrides
    org: Optional[str] = None  # For org-wide scanning
    related_repos: List[str] = field(default_factory=list)  # Additional repos to consider
    
    def __post_init__(self):
        """Parse PR URL to extract owner, repo, and pull number."""
        if self.pr_url and not self.owner:
            self._parse_pr_url()
    
    def _parse_pr_url(self):
        """Extract owner, repo, pull_number from GitHub PR URL."""
        pattern = r"github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        match = re.search(pattern, self.pr_url)
        if match:
            self.owner = match.group(1)
            self.repo = match.group(2)
            self.pull_number = int(match.group(3))
            if not self.org:
                self.org = self.owner
    
    @property
    def repository(self) -> str:
        """Return owner/repo format."""
        return f"{self.owner}/{self.repo}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ThreatModel:
    """Threat model output from Stage 1 analysis."""
    
    # Threat Modeling Manifesto: 4 key questions
    what_are_we_working_on: str = ""  # Summary of PR changes
    what_can_go_wrong: List[str] = field(default_factory=list)  # High-level threat descriptions
    what_to_do_about_it: List[str] = field(default_factory=list)  # Skills to apply
    did_we_do_good_job: str = ""  # Confidence assessment
    
    # Specific threats identified from PR (new: for targeted investigation)
    identified_threats: List[IdentifiedThreat] = field(default_factory=list)
    
    # Skill matching
    matching_skills: List[str] = field(default_factory=list)
    should_investigate: bool = False
    rationale: str = ""
    
    # Identified vulnerability types (CWE mapping)
    potential_vulns: List[str] = field(default_factory=list)  # ["CWE-639", "CWE-862"]
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = asdict(self)
        if self.identified_threats:
            result["identified_threats"] = [t.to_dict() for t in self.identified_threats]
        return result


@dataclass
class InvestigationResult:
    """Output: Investigation results with verdict and analysis."""
    
    # Status
    status: str                   # "completed", "failed"
    
    # Core findings
    verdict: Optional[str]        # "TRUE_POSITIVE", "FALSE_POSITIVE"
    confidence_score: Optional[int]  # 1-10
    
    # Risk assessment
    risk_level: Optional[str]     # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: Optional[int]     # 0-100
    risk_rationale: Optional[str] = None
    
    # Analysis
    agent_analysis: str = ""      # Full text analysis
    reasoning_steps: list[str] = field(default_factory=list)  # Legacy: simple step list
    
    # Reasoning chain (new: structured reasoning for threat validation)
    reasoning_chain: List[ReasoningStep] = field(default_factory=list)
    conclusion: str = ""  # Final summary connecting evidence to verdict
    
    # Threat being validated (new: links back to Stage 1 threat)
    threat_id: Optional[str] = None  # Reference to IdentifiedThreat.threat_id
    
    # Metrics
    tool_calls: int = 0
    cost: float = 0.0             # USD
    investigation_time: float = 0.0  # Seconds
    
    # Error handling
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = asdict(self)
        if self.reasoning_chain:
            result["reasoning_chain"] = [r.to_dict() for r in self.reasoning_chain]
        return result


@dataclass
class PRTriageResult:
    """Output: PR triage result with threat model and investigation findings."""
    
    # Status
    status: str  # TriageStatus value: "completed", "no_signal", "no_skills", "failed"
    
    # Stage 1: Threat Model
    threat_model: Optional[ThreatModel] = None
    
    # Stage 2: Investigation (only if threat_model.should_investigate)
    investigation_results: List[InvestigationResult] = field(default_factory=list)
    
    # Aggregate verdict (from all investigations)
    overall_verdict: Optional[str] = None  # "TRUE_POSITIVE", "FALSE_POSITIVE", "MIXED"
    
    # Skills that were used
    skills_used: List[str] = field(default_factory=list)
    
    # Multi-repo findings
    repos_searched: List[str] = field(default_factory=list)
    cross_repo_findings: List[str] = field(default_factory=list)
    
    # Metrics
    total_tool_calls: int = 0
    total_cost: float = 0.0
    total_time: float = 0.0
    
    # Error handling
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = asdict(self)
        if self.threat_model:
            result["threat_model"] = self.threat_model.to_dict()
        if self.investigation_results:
            result["investigation_results"] = [
                r.to_dict() if hasattr(r, 'to_dict') else r 
                for r in self.investigation_results
            ]
        return result
