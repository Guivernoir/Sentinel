"""
Test CSP (Content Security Policy) analyzer.
Where the real security theater happens. Now with actual tests.
"""

import pytest
from sentinel.csp import CSPAnalyzer
from sentinel.models import HeaderQuality


class TestCSPParser:
    """Test CSP parsing functionality."""
    
    def test_parse_simple_directive(self):
        """Test parsing single directive."""
        directives = CSPAnalyzer.parse_directives("default-src 'self'")
        
        assert "default-src" in directives
        assert directives["default-src"] == ["'self'"]
    
    def test_parse_multiple_directives(self):
        """Test parsing multiple directives."""
        directives = CSPAnalyzer.parse_directives(
            "default-src 'self'; script-src 'self' 'unsafe-inline'"
        )
        
        assert "default-src" in directives
        assert "script-src" in directives
        assert directives["script-src"] == ["'self'", "'unsafe-inline'"]
    
    def test_parse_directive_no_sources(self):
        """Test parsing directive without sources."""
        directives = CSPAnalyzer.parse_directives("default-src")
        
        assert "default-src" in directives
        assert directives["default-src"] == []
    
    def test_parse_empty_csp(self):
        """Test parsing empty CSP."""
        directives = CSPAnalyzer.parse_directives("")
        
        assert len(directives) == 0
    
    def test_parse_whitespace_handling(self):
        """Test whitespace handling in parsing."""
        directives = CSPAnalyzer.parse_directives(
            "  default-src  'self'  ;  script-src  'self'  "
        )
        
        assert "default-src" in directives
        assert "script-src" in directives
    
    def test_parse_trailing_semicolon(self):
        """Test handling of trailing semicolons."""
        directives = CSPAnalyzer.parse_directives("default-src 'self';")
        
        assert "default-src" in directives
        assert len(directives) == 1


class TestCSPAnalysis:
    """Test CSP analysis functionality."""
    
    def test_empty_csp_is_dangerous(self):
        """Empty CSP should be classified as DANGEROUS."""
        quality, issues, recs, types = CSPAnalyzer.analyze("")
        
        assert quality == HeaderQuality.DANGEROUS
        assert any("empty" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_STRUCTURAL in types
    
    def test_excellent_strict_csp(self):
        """Test well-configured strict CSP."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'self' 'nonce-abc123'; "
            "style-src 'self'; img-src 'self' https:; object-src 'none'"
        )
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_missing_default_src(self):
        """Test CSP without default-src fallback."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "script-src 'self'"
        )
        
        assert any("default-src" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_STRUCTURAL in types
    
    def test_unsafe_inline_detected(self):
        """Test detection of unsafe-inline."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'unsafe-inline'"
        )
        
        assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
        assert any("unsafe-inline" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_UNSAFE in types
    
    def test_unsafe_eval_detected(self):
        """Test detection of unsafe-eval."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'unsafe-eval'"
        )
        
        assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
        assert any("unsafe-eval" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_UNSAFE in types
    
    def test_wildcard_sources_detected(self):
        """Test detection of wildcard sources."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src *"
        )
        
        assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
        assert any("wildcard" in issue.lower() or "*" in issue for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_WILDCARD in types
    
    def test_http_sources_detected(self):
        """Test detection of insecure http: sources."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src http://example.com"
        )
        
        assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
        assert any("http:" in issue.lower() or "insecure" in issue.lower() 
                   for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_DOWNGRADE in types
    
    def test_data_uri_in_script_src(self):
        """Test detection of data: URIs in script-src."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'self' data:"
        )
        
        assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
        assert any("data:" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_UNSAFE in types
    
    def test_deprecated_directives_detected(self):
        """Test detection of deprecated directives."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; block-all-mixed-content"
        )
        
        assert any("deprecated" in issue.lower() for issue in issues)
        assert CSPAnalyzer.ISSUE_TYPE_DEPRECATED in types
    
    def test_multiple_issues_dangerous(self):
        """Test CSP with multiple critical issues is DANGEROUS."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'unsafe-inline' *; style-src http:"
        )
        
        assert quality == HeaderQuality.DANGEROUS
        assert CSPAnalyzer.ISSUE_TYPE_UNSAFE in types
        assert CSPAnalyzer.ISSUE_TYPE_WILDCARD in types
        assert CSPAnalyzer.ISSUE_TYPE_DOWNGRADE in types
    
    def test_report_uri_not_flagged(self):
        """Test that report-uri is not flagged for wildcards."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; report-uri *"
        )
        
        # report-uri with * should not trigger wildcard warning
        assert CSPAnalyzer.ISSUE_TYPE_WILDCARD not in types or \
               not any("report-uri" in issue.lower() for issue in issues)
    
    def test_nonce_sources_good(self):
        """Test that nonce sources are accepted."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'nonce-abc123' 'nonce-def456'"
        )
        
        assert quality in (HeaderQuality.EXCELLENT, HeaderQuality.GOOD)
    
    def test_hash_sources_good(self):
        """Test that hash sources are accepted."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'sha256-abc123...'"
        )
        
        assert quality in (HeaderQuality.EXCELLENT, HeaderQuality.GOOD)
    
    def test_recommendations_provided(self):
        """Test that recommendations are provided for issues."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src 'unsafe-inline'"
        )
        
        assert len(recs) > 0
        assert any("nonce" in rec.lower() or "hash" in rec.lower() for rec in recs)
    
    def test_good_quality_minor_issues(self):
        """Test CSP with minor issues scores GOOD."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "script-src 'self'; style-src 'self'"
        )
        
        # Missing default-src is structural but not critical
        assert quality in (HeaderQuality.GOOD, HeaderQuality.WEAK)
        assert CSPAnalyzer.ISSUE_TYPE_STRUCTURAL in types
    
    def test_single_wildcard_weak(self):
        """Test CSP with single wildcard is WEAK."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; img-src *"
        )
        
        assert quality == HeaderQuality.WEAK
        assert CSPAnalyzer.ISSUE_TYPE_WILDCARD in types
    
    def test_complex_valid_csp(self):
        """Test complex but valid CSP."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; "
            "script-src 'self' https://cdn.example.com 'nonce-random'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.googleapis.com; "
            "connect-src 'self' https://api.example.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        
        # Has unsafe-inline in style-src, but that's common
        assert quality in (HeaderQuality.GOOD, HeaderQuality.WEAK)


class TestCSPEdgeCases:
    """Test CSP edge cases and corner cases."""
    
    def test_quoted_vs_unquoted_keywords(self):
        """Test handling of quoted vs unquoted keywords."""
        # 'self' should be quoted, self shouldn't work
        quality1, _, _, _ = CSPAnalyzer.analyze("default-src 'self'")
        quality2, _, _, _ = CSPAnalyzer.analyze("default-src self")
        
        # Both should work in parsing
        assert quality1 == HeaderQuality.EXCELLENT
        assert quality2 == HeaderQuality.EXCELLENT
    
    def test_duplicate_directives_first_wins(self):
        """Test that first directive wins with duplicates."""
        directives = CSPAnalyzer.parse_directives(
            "default-src 'self'; default-src 'none'"
        )
        
        # First one should win per spec
        assert directives["default-src"] == ["'self'"]
    
    def test_very_long_csp(self):
        """Test handling of very long CSP."""
        long_csp = "default-src 'self'; " + "; ".join([
            f"script-src-{i} 'self'" for i in range(50)
        ])
        
        quality, issues, recs, types = CSPAnalyzer.analyze(long_csp)
        
        # Should parse without errors
        assert quality is not None
    
    def test_special_characters_in_sources(self):
        """Test handling of special characters in sources."""
        quality, issues, recs, types = CSPAnalyzer.analyze(
            "default-src 'self'; script-src https://cdn-1.example.com:443"
        )
        
        assert quality in (HeaderQuality.EXCELLENT, HeaderQuality.GOOD)