"""
Test HSTS (Strict-Transport-Security) analyzer.
Because transport security isn't optional.
"""

import pytest
from sentinel.hsts import HSTSAnalyzer
from sentinel.models import HeaderQuality


class TestHSTSAnalyzer:
    """Test HSTS header analysis."""
    
    def test_excellent_configuration(self):
        """Test perfectly configured HSTS."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=31536000; includeSubDomains; preload"
        )
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
        assert len(types) == 0
    
    def test_excellent_without_preload(self):
        """Test excellent configuration without preload."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=31536000; includeSubDomains"
        )
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_good_without_subdomains(self):
        """Test good configuration missing includeSubDomains."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=31536000"
        )
        
        assert quality == HeaderQuality.GOOD
        assert any("includesubdomains" in issue.lower() for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_MISSING_SUBDOMAINS in types
    
    def test_short_max_age_below_minimum(self):
        """Test max-age below 30 days minimum."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=86400"  # 1 day
        )
        
        assert quality == HeaderQuality.WEAK
        assert any("too short" in issue.lower() for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_SHORT_MAXAGE in types
    
    def test_short_max_age_below_recommended(self):
        """Test max-age below 1 year recommendation."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=7776000; includeSubDomains"  # 90 days
        )
        
        assert quality == HeaderQuality.GOOD
        assert any("below recommended" in issue.lower() for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_SHORT_MAXAGE in types
    
    def test_missing_max_age(self):
        """Test HSTS without max-age directive."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "includeSubDomains"
        )
        
        assert quality == HeaderQuality.DANGEROUS
        assert any("missing" in issue.lower() and "max-age" in issue.lower() 
                   for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_MISSING_MAXAGE in types
    
    def test_max_age_zero(self):
        """Test max-age=0 which disables HSTS."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=0"
        )
        
        assert quality == HeaderQuality.DANGEROUS
        assert any("disables" in issue.lower() for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_MISSING_MAXAGE in types
    
    def test_invalid_max_age(self):
        """Test invalid max-age value."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=invalid"
        )
        
        assert quality == HeaderQuality.DANGEROUS
        assert any("invalid" in issue.lower() for issue in issues)
        assert HSTSAnalyzer.ISSUE_TYPE_INVALID_VALUE in types
    
    def test_preload_without_subdomains(self):
        """Test preload directive without includeSubDomains."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=31536000; preload"
        )
        
        assert any("preload" in issue.lower() and "includesubdomains" in issue.lower() 
                   for issue in issues)
    
    def test_case_insensitive_directives(self):
        """Test that directives are case-insensitive."""
        quality1, _, _, _ = HSTSAnalyzer.analyze(
            "max-age=31536000; includeSubDomains"
        )
        quality2, _, _, _ = HSTSAnalyzer.analyze(
            "max-age=31536000; IncludeSubDomains"
        )
        quality3, _, _, _ = HSTSAnalyzer.analyze(
            "MAX-AGE=31536000; INCLUDESUBDOMAINS"
        )
        
        assert quality1 == quality2 == quality3 == HeaderQuality.EXCELLENT
    
    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = HSTSAnalyzer.analyze(
            "  max-age=31536000  ;  includeSubDomains  "
        )
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_empty_directives_ignored(self):
        """Test that empty directives are ignored."""
        quality, issues, _, _ = HSTSAnalyzer.analyze(
            "max-age=31536000;;includeSubDomains;"
        )
        
        assert quality == HeaderQuality.EXCELLENT
    
    def test_recommendations_for_weak_config(self):
        """Test that recommendations are provided for weak configs."""
        quality, issues, recs, types = HSTSAnalyzer.analyze(
            "max-age=86400"  # 1 day
        )
        
        assert quality == HeaderQuality.WEAK
        assert len(recs) > 0
        assert any("31536000" in rec for rec in recs)