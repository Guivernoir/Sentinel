"""
Sentinel Security Header Analyzer
Tactical HTTP security header analysis with surgical precision.
"""

__version__ = "1.0.0"
__author__ = "Guilherme F. G. Santos"

from sentinel.analyzer import SecurityHeadersAnalyzer
from sentinel.models import (
    SecurityReport,
    HeaderAnalysis,
    Severity,
    HeaderQuality,
)

__all__ = [
    "SecurityHeadersAnalyzer",
    "SecurityReport",
    "HeaderAnalysis",
    "Severity",
    "HeaderQuality",
]