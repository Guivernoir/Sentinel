"""
Test data models and enumerations.
Because data structures are the foundation of everything.
"""

import pytest
from sentinel.models import (
    Severity, HeaderQuality, HeaderAnalysis,
    RedirectHop, SecurityReport
)


class TestSeverity:
    """Test Severity enumeration."""
    
    def test_severity_values(self):
        """Verify all severity levels exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    def test_severity_count(self):
        """Ensure no severity levels were accidentally added."""
        assert len(list(Severity)) == 5


class TestHeaderQuality:
    """Test HeaderQuality enumeration."""
    
    def test_quality_values(self):
        """Verify all quality levels exist."""
        assert HeaderQuality.EXCELLENT.value == "excellent"
        assert HeaderQuality.GOOD.value == "good"
        assert HeaderQuality.WEAK.value == "weak"
        assert HeaderQuality.DANGEROUS.value == "dangerous"
        assert HeaderQuality.MISSING.value == "missing"
    
    def test_quality_count(self):
        """Ensure no quality levels were accidentally added."""
        assert len(list(HeaderQuality)) == 5


class TestHeaderAnalysis:
    """Test HeaderAnalysis data structure."""
    
    def test_minimal_creation(self):
        """Test creation with minimal required fields."""
        analysis = HeaderAnalysis(
            name="test-header",
            present=False
        )
        
        assert analysis.name == "test-header"
        assert analysis.present is False
        assert analysis.value is None
        assert analysis.expected_severity == Severity.INFO
        assert analysis.quality == HeaderQuality.MISSING
        assert analysis.score == 0.0
        assert len(analysis.issues) == 0
        assert len(analysis.recommendations) == 0
    
    def test_full_creation(self):
        """Test creation with all fields."""
        analysis = HeaderAnalysis(
            name="strict-transport-security",
            present=True,
            value="max-age=31536000",
            expected_severity=Severity.HIGH,
            effective_severity=Severity.INFO,
            quality=HeaderQuality.EXCELLENT,
            score=20.0,
            max_score=20.0,
            issues=[],
            recommendations=["Keep current configuration"],
            issue_types=set()
        )
        
        assert analysis.name == "strict-transport-security"
        assert analysis.value == "max-age=31536000"
        assert analysis.quality == HeaderQuality.EXCELLENT
        assert analysis.score == 20.0
    
    def test_default_collections(self):
        """Test that default collections are independent."""
        analysis1 = HeaderAnalysis(name="header1", present=True)
        analysis2 = HeaderAnalysis(name="header2", present=True)
        
        analysis1.issues.append("issue1")
        analysis1.issue_types.add("type1")
        
        assert len(analysis2.issues) == 0
        assert len(analysis2.issue_types) == 0


class TestRedirectHop:
    """Test RedirectHop data structure."""
    
    def test_redirect_hop_creation(self):
        """Test redirect hop creation."""
        hop = RedirectHop(
            url="https://example.com",
            status_code=301,
            location="https://www.example.com",
            scheme="https"
        )
        
        assert hop.url == "https://example.com"
        assert hop.status_code == 301
        assert hop.location == "https://www.example.com"
        assert hop.scheme == "https"
    
    def test_final_hop_no_location(self):
        """Test final hop with no location."""
        hop = RedirectHop(
            url="https://example.com",
            status_code=200,
            location=None,
            scheme="https"
        )
        
        assert hop.location is None
        assert hop.status_code == 200


class TestSecurityReport:
    """Test SecurityReport data structure."""
    
    def test_minimal_report_creation(self):
        """Test report creation with minimal data."""
        report = SecurityReport(
            final_url="https://example.com",
            status_code=200,
            redirect_chain=[],
            headers={},
            analyses=[]
        )
        
        assert report.final_url == "https://example.com"
        assert report.status_code == 200
        assert report.total_score == 0.0
        assert report.max_score == 0.0
        assert report.exposure_penalty == 0.0
        assert len(report.warnings) == 0
    
    def test_report_with_analyses(self, sample_analysis):
        """Test report with header analyses."""
        report = SecurityReport(
            final_url="https://example.com",
            status_code=200,
            redirect_chain=[],
            headers={"test-header": "test-value"},
            analyses=[sample_analysis],
            total_score=15.0,
            max_score=20.0
        )
        
        assert len(report.analyses) == 1
        assert report.total_score == 15.0
        assert report.max_score == 20.0
    
    def test_report_with_warnings(self):
        """Test report with security warnings."""
        report = SecurityReport(
            final_url="https://example.com",
            status_code=200,
            redirect_chain=[],
            headers={},
            analyses=[],
            warnings=["HTTPS downgrade detected", "Excessive redirects"]
        )
        
        assert len(report.warnings) == 2
        assert "HTTPS downgrade" in report.warnings[0]
    
    def test_report_with_exposure_penalty(self):
        """Test report with information disclosure penalty."""
        report = SecurityReport(
            final_url="https://example.com",
            status_code=200,
            redirect_chain=[],
            headers={},
            analyses=[],
            total_score=50.0,
            max_score=50.0,
            exposure_penalty=5.0
        )
        
        assert report.exposure_penalty == 5.0
        # Net score would be 45.0 after penalty
    
    def test_default_warnings_list(self):
        """Test that default warnings list is independent."""
        report1 = SecurityReport(
            final_url="https://example.com",
            status_code=200,
            redirect_chain=[],
            headers={},
            analyses=[]
        )
        report2 = SecurityReport(
            final_url="https://example.org",
            status_code=200,
            redirect_chain=[],
            headers={},
            analyses=[]
        )
        
        report1.warnings.append("warning1")
        assert len(report2.warnings) == 0