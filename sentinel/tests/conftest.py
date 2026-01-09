"""
Pytest configuration and shared fixtures.
Because repetition is the enemy of tactical efficiency.
"""

import pytest
from typing import Dict
from sentinel.models import (
    SecurityReport, HeaderAnalysis, RedirectHop,
    Severity, HeaderQuality
)


@pytest.fixture
def sample_headers() -> Dict[str, str]:
    """Provide sample HTTP headers for testing."""
    return {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
    }


@pytest.fixture
def sample_redirect_chain():
    """Provide sample redirect chain for testing."""
    return [
        RedirectHop(
            url="http://example.com",
            status_code=301,
            location="https://example.com",
            scheme="http"
        ),
        RedirectHop(
            url="https://example.com",
            status_code=200,
            location=None,
            scheme="https"
        ),
    ]


@pytest.fixture
def sample_analysis() -> HeaderAnalysis:
    """Provide sample header analysis for testing."""
    return HeaderAnalysis(
        name="test-header",
        present=True,
        value="test-value",
        expected_severity=Severity.HIGH,
        effective_severity=Severity.LOW,
        quality=HeaderQuality.GOOD,
        score=15.0,
        max_score=20.0,
        issues=["Minor issue"],
        recommendations=["Improve configuration"],
        issue_types={"test_issue"}
    )


@pytest.fixture
def sample_report(sample_redirect_chain, sample_headers) -> SecurityReport:
    """Provide sample security report for testing."""
    analyses = [
        HeaderAnalysis(
            name="strict-transport-security",
            present=True,
            value="max-age=31536000",
            expected_severity=Severity.HIGH,
            effective_severity=Severity.INFO,
            quality=HeaderQuality.EXCELLENT,
            score=20.0,
            max_score=20.0,
        )
    ]
    
    return SecurityReport(
        final_url="https://example.com",
        status_code=200,
        redirect_chain=sample_redirect_chain,
        headers=sample_headers,
        analyses=analyses,
        total_score=20.0,
        max_score=20.0,
        exposure_penalty=0.0,
        warnings=[]
    )