"""
Strategic data structures. No business logic contamination.
Now with properly isolated concerns and zero circular dependencies.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class Severity(Enum):
    """Risk classification levels. Because 'bad' and 'very bad' lacked precision."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HeaderQuality(Enum):
    """Header configuration quality assessment. The tactical spectrum."""
    EXCELLENT = "excellent"
    GOOD = "good"
    WEAK = "weak"
    DANGEROUS = "dangerous"
    MISSING = "missing"


@dataclass
class HeaderAnalysis:
    """Analysis result for a specific header. Mission debrief."""
    name: str
    present: bool
    value: Optional[str] = None
    expected_severity: Severity = Severity.INFO
    effective_severity: Severity = Severity.INFO
    quality: HeaderQuality = HeaderQuality.MISSING
    score: float = 0.0
    max_score: float = 1.0
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    issue_types: set = field(default_factory=set)


@dataclass
class RedirectHop:
    """Information about a redirect in the chain. Breadcrumb forensics."""
    url: str
    status_code: int
    location: Optional[str]
    scheme: str


@dataclass
class SecurityReport:
    """Complete security assessment. The full operational report."""
    final_url: str
    status_code: int
    redirect_chain: List[RedirectHop]
    headers: Dict[str, str]
    analyses: List[HeaderAnalysis]
    total_score: float = 0.0
    max_score: float = 0.0
    exposure_penalty: float = 0.0
    warnings: List[str] = field(default_factory=list)