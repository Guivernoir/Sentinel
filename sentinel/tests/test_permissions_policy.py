"""
Test Permissions-Policy analyzer.
Because every API should prove it needs camera access.
"""

from sentinel.models import HeaderQuality
from sentinel.permissions_policy import PermissionsPolicyAnalyzer


class TestPermissionsPolicyAnalyzer:
    """Test Permissions-Policy analysis."""

    def test_empty_policy_weak(self):
        """Test that empty policy is WEAK."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze("")

        assert quality == HeaderQuality.WEAK
        assert any("empty" in issue.lower() for issue in issues)
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_EMPTY in types

    def test_excellent_restrictive_policy(self):
        """Test well-configured restrictive policy."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=(), microphone=(), geolocation=()"
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_excellent_self_policy(self):
        """Test policy with self restrictions."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=(self), microphone=(self), geolocation=(self)"
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_wildcard_nonsensitive_weak(self):
        """Test wildcard on non-sensitive features."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze("autoplay=*, fullscreen=*")

        assert quality == HeaderQuality.WEAK
        assert any("wildcard" in issue.lower() or "*" in issue for issue in issues)
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_WILDCARD in types

    def test_wildcard_sensitive_dangerous(self):
        """Test wildcard on sensitive features is DANGEROUS."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze("camera=*, microphone=*")

        assert quality == HeaderQuality.DANGEROUS
        assert any("sensitive" in issue.lower() for issue in issues)
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_SENSITIVE in types
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_WILDCARD in types

    def test_malformed_directive(self):
        """Test handling of malformed directives."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze("camera, microphone=")

        assert quality == HeaderQuality.WEAK
        assert any("malformed" in issue.lower() for issue in issues)
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_MALFORMED in types

    def test_parentheses_wrapped_allowlist(self):
        """Test handling of parentheses-wrapped allowlists."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=(self), microphone=()"
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_no_parentheses_allowlist(self):
        """Test handling of allowlists without parentheses."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=self, microphone=self"
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_specific_origins_excellent(self):
        """Test policy with specific origins."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=(self https://example.com), microphone=(self)"
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_mixed_sensitive_nonsensitive(self):
        """Test mixed sensitive and non-sensitive features."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=*, fullscreen=*, autoplay=*"
        )

        # Camera is sensitive with wildcard = DANGEROUS
        assert quality == HeaderQuality.DANGEROUS
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_SENSITIVE in types

    def test_recommendations_for_sensitive_wildcard(self):
        """Test recommendations for sensitive features with wildcards."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze("camera=*, geolocation=*")

        assert len(recs) > 0
        assert any("camera" in rec.lower() or "geolocation" in rec.lower() for rec in recs)
        assert any("self" in rec.lower() for rec in recs)

    def test_all_sensitive_features_recognized(self):
        """Test that all sensitive features are recognized."""
        sensitive_features = [
            "camera",
            "microphone",
            "geolocation",
            "payment",
            "usb",
            "serial",
            "bluetooth",
            "midi",
        ]

        for feature in sensitive_features:
            quality, issues, _, types = PermissionsPolicyAnalyzer.analyze(f"{feature}=*")

            assert quality == HeaderQuality.DANGEROUS
            assert PermissionsPolicyAnalyzer.ISSUE_TYPE_SENSITIVE in types

    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        quality, issues, _, _ = PermissionsPolicyAnalyzer.analyze(
            "  camera = ( self ) , microphone = ( )  "
        )

        assert quality == HeaderQuality.EXCELLENT
        assert len(issues) == 0

    def test_complex_valid_policy(self):
        """Test complex but valid policy."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera=(self), microphone=(self), geolocation=(self), "
            "payment=(self https://checkout.example.com), "
            "usb=(), bluetooth=(), autoplay=(self), fullscreen=*"
        )

        # fullscreen=* is non-sensitive wildcard = WEAK
        assert quality == HeaderQuality.WEAK
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_WILDCARD in types
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_SENSITIVE not in types


class TestPermissionsPolicyEdgeCases:
    """Test edge cases in Permissions-Policy parsing."""

    def test_empty_allowlist(self):
        """Test features with empty allowlists."""
        quality, issues, _, _ = PermissionsPolicyAnalyzer.analyze("camera=(), microphone=()")

        assert quality == HeaderQuality.EXCELLENT

    def test_none_keyword(self):
        """Test handling of 'none' keyword."""
        quality, issues, _, _ = PermissionsPolicyAnalyzer.analyze(
            "camera=(none), microphone=(none)"
        )

        # Should be treated as origin 'none', which is fine
        assert quality in (HeaderQuality.EXCELLENT, HeaderQuality.GOOD)

    def test_multiple_origins_in_allowlist(self):
        """Test multiple origins in allowlist."""
        quality, issues, _, _ = PermissionsPolicyAnalyzer.analyze(
            "camera=(self https://cam1.example.com https://cam2.example.com)"
        )

        assert quality == HeaderQuality.EXCELLENT

    def test_missing_equals_sign(self):
        """Test directive without equals sign."""
        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(
            "camera(self), microphone=()"
        )

        assert quality == HeaderQuality.WEAK
        assert PermissionsPolicyAnalyzer.ISSUE_TYPE_MALFORMED in types

    def test_duplicate_features(self):
        """Test handling of duplicate feature definitions."""
        quality, issues, _, _ = PermissionsPolicyAnalyzer.analyze(
            "camera=(self), camera=*, microphone=()"
        )

        # Should still detect the wildcard camera
        assert quality == HeaderQuality.DANGEROUS

    def test_very_long_policy(self):
        """Test handling of very long policy."""
        features = [f"feature{i}=(self)" for i in range(50)]
        long_policy = ", ".join(features)

        quality, issues, recs, types = PermissionsPolicyAnalyzer.analyze(long_policy)

        # Should parse without errors
        assert quality is not None
