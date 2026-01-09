"""
Test main analyzer orchestration and integration.
Where all the pieces come together in tactical harmony.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import httpx

from sentinel.analyzer import SecurityHeadersAnalyzer
from sentinel.models import Severity, HeaderQuality, SecurityReport


class TestSecurityHeadersAnalyzer:
    """Test main analyzer orchestration."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization with default parameters."""
        analyzer = SecurityHeadersAnalyzer()
        
        assert analyzer.timeout == 10
        assert analyzer.follow_redirects is True
    
    def test_analyzer_custom_parameters(self):
        """Test analyzer initialization with custom parameters."""
        analyzer = SecurityHeadersAnalyzer(timeout=30, follow_redirects=False)
        
        assert analyzer.timeout == 30
        assert analyzer.follow_redirects is False
    
    def test_url_normalization_https(self):
        """Test URL normalization adds HTTPS."""
        analyzer = SecurityHeadersAnalyzer()
        
        assert analyzer._normalize_url("example.com") == "https://example.com"
        assert analyzer._normalize_url("www.example.com") == "https://www.example.com"
    
    def test_url_normalization_preserves_protocol(self):
        """Test URL normalization preserves existing protocol."""
        analyzer = SecurityHeadersAnalyzer()
        
        assert analyzer._normalize_url("http://example.com") == "http://example.com"
        assert analyzer._normalize_url("https://example.com") == "https://example.com"
    
    def test_severity_to_score_mapping(self):
        """Test severity to score conversion."""
        analyzer = SecurityHeadersAnalyzer()
        
        assert analyzer._severity_to_score(Severity.CRITICAL) == 25.0
        assert analyzer._severity_to_score(Severity.HIGH) == 20.0
        assert analyzer._severity_to_score(Severity.MEDIUM) == 10.0
        assert analyzer._severity_to_score(Severity.LOW) == 5.0
        assert analyzer._severity_to_score(Severity.INFO) == 1.0
    
    def test_quality_to_score_mapping(self):
        """Test quality to score multiplier conversion."""
        analyzer = SecurityHeadersAnalyzer()
        max_score = 20.0
        
        assert analyzer._quality_to_score(HeaderQuality.EXCELLENT, max_score) == 20.0
        assert analyzer._quality_to_score(HeaderQuality.GOOD, max_score) == 15.0
        assert analyzer._quality_to_score(HeaderQuality.WEAK, max_score) == 10.0
        assert analyzer._quality_to_score(HeaderQuality.DANGEROUS, max_score) == 0.0
        assert analyzer._quality_to_score(HeaderQuality.MISSING, max_score) == 0.0


class TestSeverityCalculation:
    """Test effective severity calculation matrix."""
    
    def test_missing_headers_maintain_severity(self):
        """Test that missing headers maintain expected severity."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.HIGH, HeaderQuality.MISSING, set()
        )
        assert effective == Severity.HIGH
        
        effective = analyzer._calculate_effective_severity(
            Severity.MEDIUM, HeaderQuality.MISSING, set()
        )
        assert effective == Severity.MEDIUM
    
    def test_dangerous_headers_maintain_severity(self):
        """Test that dangerous headers maintain high severity."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.HIGH, HeaderQuality.DANGEROUS, set()
        )
        assert effective == Severity.HIGH
    
    def test_excellent_high_reduces_to_info(self):
        """Test that EXCELLENT quality on HIGH severity reduces to INFO."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.HIGH, HeaderQuality.EXCELLENT, set()
        )
        assert effective == Severity.INFO
    
    def test_good_high_reduces_to_low(self):
        """Test that GOOD quality on HIGH severity reduces to LOW."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.HIGH, HeaderQuality.GOOD, set()
        )
        assert effective == Severity.LOW
    
    def test_weak_high_reduces_to_medium(self):
        """Test that WEAK quality on HIGH severity reduces to MEDIUM."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.HIGH, HeaderQuality.WEAK, set()
        )
        assert effective == Severity.MEDIUM
    
    def test_excellent_medium_reduces_to_info(self):
        """Test that EXCELLENT quality on MEDIUM severity reduces to INFO."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.MEDIUM, HeaderQuality.EXCELLENT, set()
        )
        assert effective == Severity.INFO
    
    def test_weak_medium_reduces_to_low(self):
        """Test that WEAK quality on MEDIUM severity reduces to LOW."""
        analyzer = SecurityHeadersAnalyzer()
        
        effective = analyzer._calculate_effective_severity(
            Severity.MEDIUM, HeaderQuality.WEAK, set()
        )
        assert effective == Severity.LOW


class TestSimpleHeaderValidation:
    """Test simple header validation for headers without dedicated analyzers."""
    
    def test_x_frame_options_valid(self):
        """Test X-Frame-Options validation with valid values."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, _ = analyzer._simple_validate("x-frame-options", "DENY")
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
        
        quality, issues, _, _ = analyzer._simple_validate("x-frame-options", "SAMEORIGIN")
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_x_frame_options_deprecated(self):
        """Test X-Frame-Options with deprecated ALLOW-FROM."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, types = analyzer._simple_validate(
            "x-frame-options", "ALLOW-FROM https://example.com"
        )
        assert quality == HeaderQuality.WEAK
        assert any("deprecated" in issue.lower() for issue in issues)
        assert "deprecated" in types
    
    def test_x_frame_options_invalid(self):
        """Test X-Frame-Options with invalid value."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, types = analyzer._simple_validate(
            "x-frame-options", "INVALID"
        )
        assert quality == HeaderQuality.WEAK
        assert any("invalid" in issue.lower() for issue in issues)
    
    def test_x_content_type_options_valid(self):
        """Test X-Content-Type-Options with valid value."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, _ = analyzer._simple_validate(
            "x-content-type-options", "nosniff"
        )
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_x_content_type_options_invalid(self):
        """Test X-Content-Type-Options with invalid value."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, types = analyzer._simple_validate(
            "x-content-type-options", "invalid"
        )
        assert quality == HeaderQuality.WEAK
        assert any("nosniff" in issue.lower() for issue in issues)
    
    def test_x_xss_protection_disabled(self):
        """Test X-XSS-Protection with recommended value (0)."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, _ = analyzer._simple_validate("x-xss-protection", "0")
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_x_xss_protection_enabled(self):
        """Test X-XSS-Protection with enabled value (should be disabled)."""
        analyzer = SecurityHeadersAnalyzer()
        
        quality, issues, _, types = analyzer._simple_validate("x-xss-protection", "1")
        assert quality == HeaderQuality.WEAK
        assert any("0" in issue or "disable" in issue.lower() for issue in issues)


class TestRedirectChainAnalysis:
    """Test redirect chain analysis."""
    
    def test_no_redirects(self):
        """Test single hop with no redirects."""
        from sentinel.models import RedirectHop
        analyzer = SecurityHeadersAnalyzer()
        
        chain = [
            RedirectHop("https://example.com", 200, None, "https")
        ]
        warnings = analyzer._analyze_redirect_chain(chain)
        
        assert len(warnings) == 0
    
    def test_http_to_https_redirect(self):
        """Test HTTP to HTTPS redirect."""
        from sentinel.models import RedirectHop
        analyzer = SecurityHeadersAnalyzer()
        
        chain = [
            RedirectHop("http://example.com", 301, "https://example.com", "http"),
            RedirectHop("https://example.com", 200, None, "https")
        ]
        warnings = analyzer._analyze_redirect_chain(chain)
        
        assert len(warnings) > 0
        assert any("http" in w.lower() for w in warnings)
    
    def test_https_downgrade_detected(self):
        """Test HTTPS downgrade detection."""
        from sentinel.models import RedirectHop
        analyzer = SecurityHeadersAnalyzer()
        
        chain = [
            RedirectHop("https://example.com", 301, "http://example.com", "https"),
            RedirectHop("http://example.com", 200, None, "http")
        ]
        warnings = analyzer._analyze_redirect_chain(chain)
        
        assert len(warnings) > 0
        assert any("downgrade" in w.lower() for w in warnings)
    
    def test_excessive_redirects(self):
        """Test excessive redirect detection."""
        from sentinel.models import RedirectHop
        analyzer = SecurityHeadersAnalyzer()
        
        chain = [
            RedirectHop(f"https://example.com/{i}", 301, f"https://example.com/{i+1}", "https")
            for i in range(5)
        ]
        warnings = analyzer._analyze_redirect_chain(chain)
        
        assert len(warnings) > 0
        assert any("excessive" in w.lower() for w in warnings)
    
    def test_cross_domain_redirects(self):
        """Test cross-domain redirect detection."""
        from sentinel.models import RedirectHop
        analyzer = SecurityHeadersAnalyzer()
        
        chain = [
            RedirectHop("https://example.com", 301, "https://other.com", "https"),
            RedirectHop("https://other.com", 200, None, "https")
        ]
        warnings = analyzer._analyze_redirect_chain(chain)
        
        assert len(warnings) > 0
        assert any("cross-domain" in w.lower() for w in warnings)


class TestMissingHeaderRecommendations:
    """Test recommendation generation for missing headers."""
    
    def test_hsts_recommendation(self):
        """Test HSTS missing header recommendation."""
        analyzer = SecurityHeadersAnalyzer()
        
        rec = analyzer._get_missing_recommendation("strict-transport-security")
        
        assert "hsts" in rec.lower() or "strict-transport-security" in rec.lower()
        assert "31536000" in rec
    
    def test_csp_recommendation(self):
        """Test CSP missing header recommendation."""
        analyzer = SecurityHeadersAnalyzer()
        
        rec = analyzer._get_missing_recommendation("content-security-policy")
        
        assert "csp" in rec.lower() or "content-security-policy" in rec.lower()
        assert "default-src" in rec.lower()
    
    def test_all_headers_have_recommendations(self):
        """Test that all configured headers have recommendations."""
        analyzer = SecurityHeadersAnalyzer()
        
        for header_name in analyzer.HEADER_CONFIGS.keys():
            rec = analyzer._get_missing_recommendation(header_name)
            
            assert len(rec) > 0
            assert header_name.lower().replace("-", "") in rec.lower().replace("-", "")


@pytest.mark.asyncio
class TestAnalyzerIntegration:
    """Integration tests with mocked HTTP responses."""
    
    async def test_analyze_with_mock_response(self):
        """Test full analysis with mocked HTTP response."""
        analyzer = SecurityHeadersAnalyzer()
        
        # Create mock response
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
        })
        
        # Mock the HTTP client
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            
            report = await analyzer.analyze("https://example.com")
            
            assert isinstance(report, SecurityReport)
            assert report.status_code == 200
            assert len(report.analyses) > 0
    
    async def test_analyze_information_disclosure(self):
        """Test detection of information disclosure headers."""
        analyzer = SecurityHeadersAnalyzer()
        
        # Create mock response with disclosure headers
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4.3",
            "x-aspnet-version": "4.0.30319",
        })
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            
            report = await analyzer.analyze("https://example.com")
            
            # Should have exposure penalty
            assert report.exposure_penalty > 0
            
            # Should have analyses for disclosure headers
            disclosure_headers = [a for a in report.analyses 
                                 if a.quality == HeaderQuality.DANGEROUS]
            assert len(disclosure_headers) > 0


class TestHeaderConfigurations:
    """Test header configuration mappings."""
    
    def test_all_headers_have_severity(self):
        """Test that all configured headers have severity."""
        analyzer = SecurityHeadersAnalyzer()
        
        for header_name, config in analyzer.HEADER_CONFIGS.items():
            assert "severity" in config
            assert isinstance(config["severity"], Severity)
    
    def test_high_severity_headers(self):
        """Test identification of high severity headers."""
        analyzer = SecurityHeadersAnalyzer()
        
        high_severity = [
            name for name, config in analyzer.HEADER_CONFIGS.items()
            if config["severity"] == Severity.HIGH
        ]
        
        assert "strict-transport-security" in high_severity
        assert "content-security-policy" in high_severity
    
    def test_discouraged_headers_list(self):
        """Test discouraged headers configuration."""
        analyzer = SecurityHeadersAnalyzer()
        
        assert "server" in analyzer.DISCOURAGED_HEADERS
        assert "x-powered-by" in analyzer.DISCOURAGED_HEADERS
        
        # Each should have reason and penalty
        for header, (reason, penalty) in analyzer.DISCOURAGED_HEADERS.items():
            assert isinstance(reason, str)
            assert len(reason) > 0
            assert isinstance(penalty, float)
            assert penalty > 0