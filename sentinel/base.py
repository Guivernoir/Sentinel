"""
Base protocol for all header analyzers. Because protocols beat inheritance.
Duck typing with a tactical vest.
"""

from typing import Protocol, Tuple, List
from sentinel.models import HeaderQuality


class HeaderAnalyzer(Protocol):
    """Protocol for header-specific analyzers. The contract."""
    
    @staticmethod
    def analyze(value: str) -> Tuple[HeaderQuality, List[str], List[str], set]:
        """
        Analyze header value with surgical precision.
        
        Returns:
            quality: Assessment of configuration
            issues: List of problems found
            recommendations: List of improvements
            issue_types: Set of issue categories for severity calculation
        """
        ...