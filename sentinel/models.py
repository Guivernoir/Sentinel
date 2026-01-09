"""
Strategic data structures. No business logic contamination.
Now with properly isolated concerns and zero circular dependencies.
"""

from dataclasses import dataclass, field
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
    value: str | None = None
    expected_severity: Severity = Severity.INFO
    effective_severity: Severity = Severity.INFO
    quality: HeaderQuality = HeaderQuality.MISSING
    score: float = 0.0
    max_score: float = 1.0
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    issue_types: set = field(default_factory=set)


@dataclass
class RedirectHop:
    """Information about a redirect in the chain. Breadcrumb forensics."""

    url: str
    status_code: int
    location: str | None
    scheme: str


@dataclass
class SecurityReport:
    """Complete security assessment. The full operational report."""

    final_url: str
    status_code: int
    redirect_chain: list[RedirectHop]
    headers: dict[str, str]
    analyses: list[HeaderAnalysis]
    total_score: float = 0.0
    max_score: float = 0.0
    exposure_penalty: float = 0.0
    warnings: list[str] = field(default_factory=list)
