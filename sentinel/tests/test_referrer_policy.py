"""
Test Referrer-Policy analyzer.
Privacy matters, even if marketing doesn't think so.
"""

import pytest
from sentinel.referrer_policy import ReferrerPolicyAnalyzer
from sentinel.models import HeaderQuality


class TestReferrerPolicyAnalyzer:
    """Test Referrer-Policy analysis."""
    
    def test_no_referrer_excellent(self):
        """Test that no-referrer is EXCELLENT."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("no-referrer")
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_same_origin_excellent(self):
        """Test that same-origin is EXCELLENT."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("same-origin")
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_strict_origin_excellent(self):
        """Test that strict-origin is EXCELLENT."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("strict-origin")
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_strict_origin_when_cross_origin_excellent(self):
        """Test that strict-origin-when-cross-origin is EXCELLENT."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(
            "strict-origin-when-cross-origin"
        )
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_no_referrer_when_downgrade_good(self):
        """Test that no-referrer-when-downgrade is GOOD."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(
            "no-referrer-when-downgrade"
        )
        
        assert quality == HeaderQuality.GOOD
        assert any("default" in issue.lower() or "stricter" in issue.lower() 
                   for issue in issues)
    
    def test_origin_weak(self):
        """Test that origin is WEAK."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("origin")
        
        assert quality == HeaderQuality.WEAK
        assert any("leak" in issue.lower() for issue in issues)
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_LEAKY in types
    
    def test_origin_when_cross_origin_weak(self):
        """Test that origin-when-cross-origin is WEAK."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(
            "origin-when-cross-origin"
        )
        
        assert quality == HeaderQuality.WEAK
        assert any("leak" in issue.lower() for issue in issues)
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_LEAKY in types
    
    def test_unsafe_url_weak(self):
        """Test that unsafe-url is WEAK."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("unsafe-url")
        
        assert quality == HeaderQuality.WEAK
        assert any("unsafe" in issue.lower() or "full url" in issue.lower() 
                   for issue in issues)
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_LEAKY in types
    
    def test_invalid_policy_weak(self):
        """Test that invalid policy is WEAK."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("invalid-policy")
        
        assert quality == HeaderQuality.WEAK
        assert any("unknown" in issue.lower() or "invalid" in issue.lower() 
                   for issue in issues)
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_INVALID in types
    
    def test_case_insensitive(self):
        """Test case-insensitive policy parsing."""
        quality1, _, _, _ = ReferrerPolicyAnalyzer.analyze("no-referrer")
        quality2, _, _, _ = ReferrerPolicyAnalyzer.analyze("No-Referrer")
        quality3, _, _, _ = ReferrerPolicyAnalyzer.analyze("NO-REFERRER")
        
        assert quality1 == quality2 == quality3 == HeaderQuality.EXCELLENT
    
    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze("  no-referrer  ")
        
        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
    
    def test_recommendations_for_weak(self):
        """Test that recommendations are provided for weak policies."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("unsafe-url")
        
        assert len(recs) > 0
        assert any("strict-origin-when-cross-origin" in rec.lower() for rec in recs)
    
    def test_multiple_policies_comma_separated(self):
        """Test handling of multiple comma-separated policies."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(
            "origin, strict-origin-when-cross-origin"
        )
        
        # Last policy should win (strict-origin-when-cross-origin)
        assert quality == HeaderQuality.EXCELLENT
        assert any("multiple" in issue.lower() for issue in issues)
    
    def test_multiple_policies_last_wins(self):
        """Test that last policy in list wins."""
        quality1, _, _, _ = ReferrerPolicyAnalyzer.analyze(
            "unsafe-url, no-referrer"
        )
        quality2, _, _, _ = ReferrerPolicyAnalyzer.analyze(
            "no-referrer, unsafe-url"
        )
        
        # First should be EXCELLENT (no-referrer wins)
        assert quality1 == HeaderQuality.EXCELLENT
        # Second should be WEAK (unsafe-url wins)
        assert quality2 == HeaderQuality.WEAK
    
    def test_empty_policy(self):
        """Test handling of empty policy."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze("")
        
        assert quality == HeaderQuality.WEAK
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_INVALID in types


class TestReferrerPolicyRecommendations:
    """Test recommendation generation for Referrer-Policy."""
    
    def test_recommendations_specific_to_issue(self):
        """Test that recommendations address specific issues."""
        # Test unsafe-url
        _, _, recs_unsafe, _ = ReferrerPolicyAnalyzer.analyze("unsafe-url")
        assert any("strict-origin" in rec.lower() for rec in recs_unsafe)
        
        # Test origin
        _, _, recs_origin, _ = ReferrerPolicyAnalyzer.analyze("origin")
        assert any("strict-origin" in rec.lower() for rec in recs_origin)
        
        # Test no-referrer-when-downgrade
        _, _, recs_default, _ = ReferrerPolicyAnalyzer.analyze(
            "no-referrer-when-downgrade"
        )
        assert any("strict-origin" in rec.lower() for rec in recs_default)
    
    def test_no_recommendations_for_excellent(self):
        """Test that excellent policies don't generate recommendations."""
        # Though they might still have informational messages
        excellent_policies = [
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin"
        ]
        
        for policy in excellent_policies:
            quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(policy)
            assert quality == HeaderQuality.EXCELLENT
            # Recommendations should be empty or minimal
            assert len(recs) == 0 or all(
                "consider" in rec.lower() for rec in recs
            )


class TestReferrerPolicyEdgeCases:
    """Test edge cases in Referrer-Policy parsing."""
    
    def test_multiple_commas(self):
        """Test handling of multiple commas."""
        quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze(
            "origin,, strict-origin"
        )
        
        # Should still parse correctly (last valid policy wins)
        assert quality == HeaderQuality.EXCELLENT
    
    def test_trailing_comma(self):
        """Test handling of trailing comma."""
        quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze(
            "no-referrer,"
        )
        
        assert quality == HeaderQuality.EXCELLENT
    
    def test_whitespace_in_multiple_policies(self):
        """Test whitespace handling in multiple policies."""
        quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze(
            "  origin  ,  strict-origin-when-cross-origin  "
        )
        
        assert quality == HeaderQuality.EXCELLENT
    
    def test_mixed_valid_invalid_policies(self):
        """Test mix of valid and invalid policies."""
        quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze(
            "invalid, no-referrer"
        )
        
        # Last valid policy (no-referrer) should win
        assert quality == HeaderQuality.EXCELLENT
    
    def test_all_invalid_policies(self):
        """Test all invalid policies."""
        quality, issues, recs, types = ReferrerPolicyAnalyzer.analyze(
            "invalid1, invalid2, invalid3"
        )
        
        assert quality == HeaderQuality.WEAK
        assert ReferrerPolicyAnalyzer.ISSUE_TYPE_INVALID in types