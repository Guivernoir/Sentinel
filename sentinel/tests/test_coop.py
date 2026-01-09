"""
Test Cross-Origin-* analyzers (COOP, COEP, CORP).
Because cross-origin isolation actually matters now.
"""

from sentinel.coop import COEPAnalyzer, COOPAnalyzer, CORPAnalyzer
from sentinel.models import HeaderQuality


class TestCOOPAnalyzer:
    """Test Cross-Origin-Opener-Policy analyzer."""

    def test_same_origin_excellent(self):
        """Test that same-origin policy is EXCELLENT."""
        quality, issues, recs, types = COOPAnalyzer.analyze("same-origin")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
        assert len(types) == 0

    def test_same_origin_allow_popups_good(self):
        """Test that same-origin-allow-popups is GOOD."""
        quality, issues, recs, types = COOPAnalyzer.analyze("same-origin-allow-popups")

        assert quality == HeaderQuality.GOOD
        assert any("popup" in issue.lower() for issue in issues)

    def test_unsafe_none_weak(self):
        """Test that unsafe-none is WEAK."""
        quality, issues, recs, types = COOPAnalyzer.analyze("unsafe-none")

        assert quality == HeaderQuality.WEAK
        assert any("no isolation" in issue.lower() or "unsafe" in issue.lower() for issue in issues)
        assert COOPAnalyzer.ISSUE_TYPE_PERMISSIVE in types

    def test_invalid_policy_weak(self):
        """Test that invalid policy is WEAK."""
        quality, issues, recs, types = COOPAnalyzer.analyze("invalid-policy")

        assert quality == HeaderQuality.WEAK
        assert any("unknown" in issue.lower() for issue in issues)
        assert COOPAnalyzer.ISSUE_TYPE_INVALID in types

    def test_case_insensitive(self):
        """Test case-insensitive policy parsing."""
        quality1, _, _, _ = COOPAnalyzer.analyze("same-origin")
        quality2, _, _, _ = COOPAnalyzer.analyze("Same-Origin")
        quality3, _, _, _ = COOPAnalyzer.analyze("SAME-ORIGIN")

        assert quality1 == quality2 == quality3 == HeaderQuality.EXCELLENT

    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = COOPAnalyzer.analyze("  same-origin  ")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_recommendations_for_weak(self):
        """Test that recommendations are provided for weak configs."""
        quality, issues, recs, types = COOPAnalyzer.analyze("unsafe-none")

        assert len(recs) > 0
        assert any("same-origin" in rec.lower() for rec in recs)


class TestCOEPAnalyzer:
    """Test Cross-Origin-Embedder-Policy analyzer."""

    def test_require_corp_excellent(self):
        """Test that require-corp is EXCELLENT."""
        quality, issues, recs, types = COEPAnalyzer.analyze("require-corp")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
        assert len(types) == 0

    def test_credentialless_good(self):
        """Test that credentialless is GOOD."""
        quality, issues, recs, types = COEPAnalyzer.analyze("credentialless")

        assert quality == HeaderQuality.GOOD
        assert any("less restrictive" in issue.lower() for issue in issues)

    def test_unsafe_none_weak(self):
        """Test that unsafe-none is WEAK."""
        quality, issues, recs, types = COEPAnalyzer.analyze("unsafe-none")

        assert quality == HeaderQuality.WEAK
        assert any(
            "no protection" in issue.lower() or "unsafe" in issue.lower() for issue in issues
        )
        assert COEPAnalyzer.ISSUE_TYPE_PERMISSIVE in types

    def test_invalid_policy_weak(self):
        """Test that invalid policy is WEAK."""
        quality, issues, recs, types = COEPAnalyzer.analyze("invalid-policy")

        assert quality == HeaderQuality.WEAK
        assert any("unknown" in issue.lower() for issue in issues)
        assert COEPAnalyzer.ISSUE_TYPE_INVALID in types

    def test_case_insensitive(self):
        """Test case-insensitive policy parsing."""
        quality1, _, _, _ = COEPAnalyzer.analyze("require-corp")
        quality2, _, _, _ = COEPAnalyzer.analyze("Require-Corp")
        quality3, _, _, _ = COEPAnalyzer.analyze("REQUIRE-CORP")

        assert quality1 == quality2 == quality3 == HeaderQuality.EXCELLENT

    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = COEPAnalyzer.analyze("  require-corp  ")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_recommendations_for_weak(self):
        """Test that recommendations are provided for weak configs."""
        quality, issues, recs, types = COEPAnalyzer.analyze("unsafe-none")

        assert len(recs) > 0
        assert any("require-corp" in rec.lower() for rec in recs)


class TestCORPAnalyzer:
    """Test Cross-Origin-Resource-Policy analyzer."""

    def test_same_origin_excellent(self):
        """Test that same-origin is EXCELLENT."""
        quality, issues, recs, types = CORPAnalyzer.analyze("same-origin")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0
        assert len(types) == 0

    def test_same_site_good(self):
        """Test that same-site is GOOD."""
        quality, issues, recs, types = CORPAnalyzer.analyze("same-site")

        assert quality == HeaderQuality.GOOD
        assert any(
            "same-site" in issue.lower() or "cross-origin" in issue.lower() for issue in issues
        )

    def test_cross_origin_weak(self):
        """Test that cross-origin is WEAK."""
        quality, issues, recs, types = CORPAnalyzer.analyze("cross-origin")

        assert quality == HeaderQuality.WEAK
        assert any(
            "unrestricted" in issue.lower() or "cross-origin" in issue.lower() for issue in issues
        )
        assert CORPAnalyzer.ISSUE_TYPE_PERMISSIVE in types

    def test_invalid_policy_weak(self):
        """Test that invalid policy is WEAK."""
        quality, issues, recs, types = CORPAnalyzer.analyze("invalid-policy")

        assert quality == HeaderQuality.WEAK
        assert any("unknown" in issue.lower() for issue in issues)
        assert CORPAnalyzer.ISSUE_TYPE_INVALID in types

    def test_case_insensitive(self):
        """Test case-insensitive policy parsing."""
        quality1, _, _, _ = CORPAnalyzer.analyze("same-origin")
        quality2, _, _, _ = CORPAnalyzer.analyze("Same-Origin")
        quality3, _, _, _ = CORPAnalyzer.analyze("SAME-ORIGIN")

        assert quality1 == quality2 == quality3 == HeaderQuality.EXCELLENT

    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = CORPAnalyzer.analyze("  same-origin  ")

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_recommendations_for_weak(self):
        """Test that recommendations are provided for weak configs."""
        quality, issues, recs, types = CORPAnalyzer.analyze("cross-origin")

        assert len(recs) > 0
        assert any("same-origin" in rec.lower() for rec in recs)


class TestCrossOriginAnalyzersCommon:
    """Test common patterns across all cross-origin analyzers."""

    def test_all_excellent_policies(self):
        """Test that all analyzers have excellent policies."""
        coop_quality, _, _, _ = COOPAnalyzer.analyze("same-origin")
        coep_quality, _, _, _ = COEPAnalyzer.analyze("require-corp")
        corp_quality, _, _, _ = CORPAnalyzer.analyze("same-origin")

        assert coop_quality == HeaderQuality.EXCELLENT
        assert coep_quality == HeaderQuality.EXCELLENT
        assert corp_quality == HeaderQuality.EXCELLENT

    def test_all_reject_empty_strings(self):
        """Test that all analyzers handle empty strings."""
        coop_quality, _, _, _ = COOPAnalyzer.analyze("")
        coep_quality, _, _, _ = COEPAnalyzer.analyze("")
        corp_quality, _, _, _ = CORPAnalyzer.analyze("")

        assert coop_quality == HeaderQuality.WEAK
        assert coep_quality == HeaderQuality.WEAK
        assert corp_quality == HeaderQuality.WEAK

    def test_all_provide_recommendations(self):
        """Test that all analyzers provide recommendations for weak configs."""
        _, _, coop_recs, _ = COOPAnalyzer.analyze("unsafe-none")
        _, _, coep_recs, _ = COEPAnalyzer.analyze("unsafe-none")
        _, _, corp_recs, _ = CORPAnalyzer.analyze("cross-origin")

        assert len(coop_recs) > 0
        assert len(coep_recs) > 0
        assert len(corp_recs) > 0

    def test_all_track_issue_types(self):
        """Test that all analyzers track issue types correctly."""
        _, _, _, coop_types = COOPAnalyzer.analyze("unsafe-none")
        _, _, _, coep_types = COEPAnalyzer.analyze("unsafe-none")
        _, _, _, corp_types = CORPAnalyzer.analyze("cross-origin")

        assert len(coop_types) > 0
        assert len(coep_types) > 0
        assert len(corp_types) > 0
