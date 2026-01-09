"""
Referrer-Policy analysis. Privacy matters, even if marketing doesn't think so.
The eternal battle between tracking and user privacy.
"""

from sentinel.models import HeaderQuality


class ReferrerPolicyAnalyzer:
    """Referrer-Policy analyzer. Privacy protection specialist."""

    # Policies ranked by privacy protection
    STRICT_POLICIES = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }

    MODERATE_POLICIES = {"no-referrer-when-downgrade"}

    WEAK_POLICIES = {"origin", "origin-when-cross-origin", "unsafe-url"}

    ISSUE_TYPE_LEAKY = "leaky_policy"
    ISSUE_TYPE_INVALID = "invalid_policy"
    ISSUE_TYPE_DEPRECATED = "deprecated_policy"

    @classmethod
    def analyze(cls, policy_value: str) -> tuple[HeaderQuality, list[str], list[str], set]:
        """Analyze Referrer-Policy configuration. Protect user navigation privacy."""
        issues = []
        recommendations = []
        issue_types = set()

        # Handle multiple policies (last one wins per spec)
        policies = [p.strip().lower() for p in policy_value.split(",") if p.strip()]
        policy = policies[-1] if policies else ""

        if policy in cls.STRICT_POLICIES:
            quality = HeaderQuality.EXCELLENT
            if policy == "same-origin":
                # Perfect for same-origin apps
                pass
            elif policy == "strict-origin-when-cross-origin":
                # Best balance for most sites
                pass

        elif policy in cls.MODERATE_POLICIES:
            quality = HeaderQuality.GOOD
            issues.append("Default policy - consider stricter options")
            recommendations.append("Use 'strict-origin-when-cross-origin' for better privacy")

        elif policy in cls.WEAK_POLICIES:
            quality = HeaderQuality.WEAK
            issue_types.add(cls.ISSUE_TYPE_LEAKY)

            if policy == "unsafe-url":
                issues.append("Policy 'unsafe-url' leaks full URL including path and query")
                recommendations.append("Use 'strict-origin-when-cross-origin' instead")
            elif policy in ("origin", "origin-when-cross-origin"):
                issues.append(f"Policy '{policy}' leaks origin to all destinations")
                recommendations.append("Consider 'strict-origin-when-cross-origin'")

        else:
            quality = HeaderQuality.WEAK
            issues.append(f"Unknown or invalid policy: '{policy}'")
            recommendations.append("Use 'strict-origin-when-cross-origin' or stricter")
            issue_types.add(cls.ISSUE_TYPE_INVALID)

        # Check for multiple policies (can indicate confusion)
        if len(policies) > 1:
            issues.append(f"Multiple policies defined: {', '.join(policies)}")
            issues.append("Note: Browsers use the last valid policy")

        return quality, issues, recommendations, issue_types
