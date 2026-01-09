"""
HSTS analysis. Because transport security isn't optional.
Unless you enjoy man-in-the-middle attacks, of course.
"""

from sentinel.models import HeaderQuality


class HSTSAnalyzer:
    """Strict-Transport-Security analyzer. The HTTPS enforcer."""

    RECOMMENDED_MAX_AGE = 31536000  # 1 year
    MINIMUM_MAX_AGE = 2592000  # 30 days

    ISSUE_TYPE_MISSING_MAXAGE = "missing_maxage"
    ISSUE_TYPE_SHORT_MAXAGE = "short_maxage"
    ISSUE_TYPE_MISSING_SUBDOMAINS = "missing_subdomains"
    ISSUE_TYPE_INVALID_VALUE = "invalid_value"

    @classmethod
    def analyze(cls, hsts_value: str) -> tuple[HeaderQuality, list[str], list[str], set]:
        """Analyze HSTS configuration. Accept no compromise."""
        issues = []
        recommendations = []
        issue_types = set()

        max_age = None
        has_includesubdomains = False
        has_preload = False

        directives = [d.strip() for d in hsts_value.split(";") if d.strip()]

        for directive in directives:
            directive_lower = directive.lower()
            if directive_lower.startswith("max-age="):
                try:
                    max_age = int(directive.split("=", 1)[1])
                except (ValueError, IndexError):
                    issues.append("Invalid max-age value")
                    issue_types.add(cls.ISSUE_TYPE_INVALID_VALUE)
            elif directive_lower == "includesubdomains":
                has_includesubdomains = True
            elif directive_lower == "preload":
                has_preload = True

        # Validate max-age - the foundation of HSTS
        if max_age is None:
            issues.append("Missing required max-age directive")
            issue_types.add(cls.ISSUE_TYPE_MISSING_MAXAGE)
            quality = HeaderQuality.DANGEROUS
        elif max_age == 0:
            issues.append("max-age=0 disables HSTS protection")
            issue_types.add(cls.ISSUE_TYPE_MISSING_MAXAGE)
            quality = HeaderQuality.DANGEROUS
        elif max_age < cls.MINIMUM_MAX_AGE:
            issues.append(f"max-age too short: {max_age} seconds (< 30 days)")
            recommendations.append(f"Increase max-age to at least {cls.RECOMMENDED_MAX_AGE}")
            issue_types.add(cls.ISSUE_TYPE_SHORT_MAXAGE)
            quality = HeaderQuality.WEAK
        elif max_age < cls.RECOMMENDED_MAX_AGE:
            issues.append(f"max-age below recommended: {max_age} seconds (< 1 year)")
            recommendations.append(f"Consider increasing to {cls.RECOMMENDED_MAX_AGE} seconds")
            issue_types.add(cls.ISSUE_TYPE_SHORT_MAXAGE)
            quality = HeaderQuality.GOOD
        else:
            quality = HeaderQuality.EXCELLENT

        # Check includeSubDomains - because subdomain compromises are real
        if not has_includesubdomains and quality in (HeaderQuality.GOOD, HeaderQuality.EXCELLENT):
            issues.append("Missing includeSubDomains directive - subdomains not protected")
            recommendations.append("Add includeSubDomains to protect all subdomains")
            issue_types.add(cls.ISSUE_TYPE_MISSING_SUBDOMAINS)
            if quality == HeaderQuality.EXCELLENT:
                quality = HeaderQuality.GOOD

        # Preload validation - can't preload without subdomain coverage
        if has_preload and not has_includesubdomains:
            issues.append("preload directive requires includeSubDomains")
            recommendations.append("Add includeSubDomains for preload eligibility")

        return quality, issues, recommendations, issue_types
