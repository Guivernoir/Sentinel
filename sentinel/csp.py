"""
Content Security Policy analysis. Where the real security theater happens.
Nonces, hashes, and the eternal struggle against 'unsafe-inline'.
"""

from sentinel.models import HeaderQuality


class CSPAnalyzer:
    """Content Security Policy parser and analyzer. The XSS battleground."""

    # Issue type taxonomy - surgical classification
    ISSUE_TYPE_STRUCTURAL = "structural"
    ISSUE_TYPE_UNSAFE = "unsafe"
    ISSUE_TYPE_WILDCARD = "wildcard"
    ISSUE_TYPE_DOWNGRADE = "downgrade"
    ISSUE_TYPE_DEPRECATED = "deprecated"

    UNSAFE_KEYWORDS = {"unsafe-inline", "unsafe-eval", "unsafe-hashes"}
    RISKY_SOURCES = {"*", "data:", "http:", "https:"}
    DEPRECATED_DIRECTIVES = {"block-all-mixed-content", "plugin-types", "referrer"}

    # Critical directives that should almost always be present
    RECOMMENDED_DIRECTIVES = {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "base-uri",
    }

    @staticmethod
    def parse_directives(csp_value: str) -> dict[str, list[str]]:
        """Parse CSP string into directive dictionary. Proper parsing, not regex chaos."""
        directives = {}
        parts = [p.strip() for p in csp_value.split(";") if p.strip()]

        for part in parts:
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                sources = tokens[1:] if len(tokens) > 1 else []
                # Handle duplicate directives - first one wins per spec
                if directive not in directives:
                    directives[directive] = sources

        return directives

    @classmethod
    def analyze(cls, csp_value: str) -> tuple[HeaderQuality, list[str], list[str], set]:
        """Analyze CSP quality with tactical precision."""
        directives = cls.parse_directives(csp_value)
        issues = []
        recommendations = []
        issue_types = set()

        # Empty CSP is security theater at its finest
        if not directives:
            return (
                HeaderQuality.DANGEROUS,
                ["Empty CSP provides no protection"],
                ["Implement CSP starting with default-src 'self'"],
                {cls.ISSUE_TYPE_STRUCTURAL},
            )

        # Structural validation - the foundation
        if "default-src" not in directives:
            issues.append("Missing 'default-src' fallback directive")
            recommendations.append("Add 'default-src' as baseline policy")
            issue_types.add(cls.ISSUE_TYPE_STRUCTURAL)

        # Check for deprecated directives
        deprecated_found = [d for d in directives if d in cls.DEPRECATED_DIRECTIVES]
        if deprecated_found:
            issues.append(f"Deprecated directives: {', '.join(deprecated_found)}")
            recommendations.append("Remove deprecated directives")
            issue_types.add(cls.ISSUE_TYPE_DEPRECATED)

        # Unsafe keywords - the "we gave up" flag
        unsafe_found = []
        for directive, sources in directives.items():
            unsafe_in_directive = [s for s in sources if s.strip("'") in cls.UNSAFE_KEYWORDS]
            if unsafe_in_directive:
                unsafe_found.extend([(directive, u) for u in unsafe_in_directive])

        if unsafe_found:
            issue_types.add(cls.ISSUE_TYPE_UNSAFE)
            for directive, keyword in unsafe_found:
                issues.append(f"Directive '{directive}' contains {keyword}")
            if "unsafe-inline" in [u.strip("'") for _, u in unsafe_found]:
                recommendations.append("Replace 'unsafe-inline' with nonces or hashes")
            if "unsafe-eval" in [u.strip("'") for _, u in unsafe_found]:
                recommendations.append("Remove 'unsafe-eval' - it enables XSS vectors")

        # Wildcard sources - asterisks are not a security strategy
        wildcards = []
        for directive, sources in directives.items():
            # Skip reporting directives
            if directive in ("report-uri", "report-to"):
                continue
            for source in sources:
                if source in ("*", "'*'"):
                    wildcards.append(directive)
                    break

        if wildcards:
            issue_types.add(cls.ISSUE_TYPE_WILDCARD)
            issues.append(f"Wildcard (*) sources in: {', '.join(set(wildcards))}")
            recommendations.append("Replace wildcards with specific origins")

        # HTTP sources - the downgrade attack gift basket
        http_sources = []
        for directive, sources in directives.items():
            for source in sources:
                if source.startswith("http://") or source == "http:":
                    http_sources.append(directive)
                    break

        if http_sources:
            issue_types.add(cls.ISSUE_TYPE_DOWNGRADE)
            issues.append(f"Insecure http: sources in: {', '.join(set(http_sources))}")
            recommendations.append("Use https: instead of http: for all sources")

        # Data URIs in script-src - because inline scripts needed a backdoor
        if "script-src" in directives:
            if "data:" in directives["script-src"]:
                issue_types.add(cls.ISSUE_TYPE_UNSAFE)
                issues.append("'data:' in script-src allows inline script execution")
                recommendations.append("Remove 'data:' from script-src")

        # Quality determination - tactical assessment
        has_structural = cls.ISSUE_TYPE_STRUCTURAL in issue_types
        has_unsafe = cls.ISSUE_TYPE_UNSAFE in issue_types
        has_wildcard = cls.ISSUE_TYPE_WILDCARD in issue_types
        has_downgrade = cls.ISSUE_TYPE_DOWNGRADE in issue_types

        # Multiple critical issues = mission failure
        critical_count = sum([has_unsafe, has_wildcard, has_downgrade])

        if critical_count >= 2 or (has_wildcard and len(directives) < 2):
            quality = HeaderQuality.DANGEROUS
        elif critical_count >= 1 or (has_structural and len(issues) >= 2):
            quality = HeaderQuality.WEAK
        elif has_structural or len(issues) >= 1:
            quality = HeaderQuality.GOOD
        else:
            quality = HeaderQuality.EXCELLENT

        return quality, issues, recommendations, issue_types
