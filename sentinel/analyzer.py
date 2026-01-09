"""
Core orchestration engine. Now with improved severity calculation.
The command center where tactical analysis becomes strategic intelligence.
"""

import logging
from urllib.parse import urlparse

import httpx

from sentinel.coop import COEPAnalyzer, COOPAnalyzer, CORPAnalyzer
from sentinel.csp import CSPAnalyzer
from sentinel.exceptions import AnalysisTimeout, ConnectionFailed, SentinelException
from sentinel.hsts import HSTSAnalyzer
from sentinel.models import HeaderAnalysis, HeaderQuality, RedirectHop, SecurityReport, Severity
from sentinel.permissions_policy import PermissionsPolicyAnalyzer
from sentinel.referrer_policy import ReferrerPolicyAnalyzer

logger = logging.getLogger(__name__)

# Constants - because magic numbers are for amateurs
MAX_REDIRECT_HOPS = 10
DEFAULT_TIMEOUT = 10


class SecurityHeadersAnalyzer:
    """Core security header analysis engine. Mission control."""

    # Header configuration with expected severity and analyzer
    HEADER_CONFIGS = {
        "strict-transport-security": {
            "severity": Severity.HIGH,
            "analyzer": HSTSAnalyzer.analyze,
        },
        "content-security-policy": {
            "severity": Severity.HIGH,
            "analyzer": CSPAnalyzer.analyze,
        },
        "x-frame-options": {
            "severity": Severity.MEDIUM,
            "analyzer": None,
        },
        "x-content-type-options": {
            "severity": Severity.MEDIUM,
            "analyzer": None,
        },
        "referrer-policy": {
            "severity": Severity.MEDIUM,
            "analyzer": ReferrerPolicyAnalyzer.analyze,
        },
        "permissions-policy": {
            "severity": Severity.MEDIUM,
            "analyzer": PermissionsPolicyAnalyzer.analyze,
        },
        "cross-origin-embedder-policy": {
            "severity": Severity.LOW,
            "analyzer": COEPAnalyzer.analyze,
        },
        "cross-origin-opener-policy": {
            "severity": Severity.LOW,
            "analyzer": COOPAnalyzer.analyze,
        },
        "cross-origin-resource-policy": {
            "severity": Severity.LOW,
            "analyzer": CORPAnalyzer.analyze,
        },
        "x-xss-protection": {
            "severity": Severity.INFO,
            "analyzer": None,
        },
    }

    # Information disclosure headers - now with actual consequences
    DISCOURAGED_HEADERS = {
        "server": ("Reveals server version information", 2.0),
        "x-powered-by": ("Exposes technology stack", 3.0),
        "x-aspnet-version": ("Discloses framework version", 2.0),
        "x-aspnetmvc-version": ("Discloses MVC version", 2.0),
        "x-generator": ("Reveals CMS/generator information", 2.0),
    }

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        follow_redirects: bool = True,
        max_redirects: int = MAX_REDIRECT_HOPS,
    ):
        """Initialize analyzer with tactical parameters."""
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper protocol. HTTPS by default, we're not savages."""
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    async def analyze(self, url: str) -> SecurityReport:
        """
        Execute analysis on target URL. Deploy all sensors.

        Args:
            url: Target URL to analyze

        Returns:
            SecurityReport with comprehensive analysis

        Raises:
            AnalysisTimeout: If request times out
            ConnectionFailed: If connection cannot be established
            SentinelException: For other analysis failures
        """
        url = self._normalize_url(url)
        logger.info(f"Initiating analysis: {url}")

        try:
            redirect_chain = []

            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                headers={"User-Agent": "Sentinel-SecurityAnalyzer/1.0"},
            ) as client:
                current_url = url

                # Follow redirect chain manually for full control
                for hop_num in range(self.max_redirects):
                    try:
                        response = await client.get(current_url)
                        logger.debug(f"Hop {hop_num + 1}: {response.status_code} - {current_url}")
                    except httpx.ConnectError as e:
                        logger.error(f"Connection failed: {current_url}")
                        raise ConnectionFailed(f"Unable to connect to {current_url}") from e

                    parsed = urlparse(current_url)
                    hop = RedirectHop(
                        url=current_url,
                        status_code=response.status_code,
                        location=response.headers.get("location"),
                        scheme=parsed.scheme,
                    )
                    redirect_chain.append(hop)

                    # Check if redirect
                    if response.status_code not in (301, 302, 303, 307, 308):
                        break

                    if not self.follow_redirects:
                        logger.debug("Redirect following disabled, stopping chain")
                        break

                    location = response.headers.get("location")
                    if not location:
                        logger.warning("Redirect status but no Location header")
                        break

                    # Handle relative redirects
                    if location.startswith("/"):
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith(("http://", "https://")):
                        location = f"{parsed.scheme}://{parsed.netloc}/{location.lstrip('/')}"

                    current_url = location

                final_response = response

            logger.info(f"Analysis complete: {len(redirect_chain)} hops")
            return self._generate_report(url, final_response, redirect_chain)

        except httpx.TimeoutException as e:
            logger.error(f"Request timeout: {url}")
            raise AnalysisTimeout(f"{url} did not respond within {self.timeout}s") from e
        except ConnectionFailed:
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            logger.exception(f"Analysis failed unexpectedly: {url}")
            raise SentinelException(f"Analysis failed: {str(e)}") from e

    def _generate_report(
        self, original_url: str, response: httpx.Response, redirect_chain: list[RedirectHop]
    ) -> SecurityReport:
        """Generate comprehensive analysis report. The full intelligence brief."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        analyses: list[HeaderAnalysis] = []
        warnings: list[str] = []
        total_score = 0.0
        max_score = 0.0
        exposure_penalty = 0.0

        # Analyze security headers
        for header_name, config in self.HEADER_CONFIGS.items():
            analysis = self._analyze_header(header_name, headers.get(header_name), config)
            analyses.append(analysis)
            total_score += analysis.score
            max_score += analysis.max_score

        # Check for discouraged headers - information disclosure penalty
        for header_name, (reason, penalty) in self.DISCOURAGED_HEADERS.items():
            if header_name in headers:
                analysis = HeaderAnalysis(
                    name=header_name,
                    present=True,
                    value=headers[header_name],
                    expected_severity=Severity.LOW,
                    effective_severity=Severity.LOW,
                    quality=HeaderQuality.DANGEROUS,
                    score=0.0,
                    max_score=0.0,
                    issues=[f"Header present: {reason}"],
                    recommendations=["Remove this header from server responses"],
                )
                analyses.append(analysis)
                exposure_penalty += penalty

        # Check redirect chain
        if len(redirect_chain) > 1:
            warnings.extend(self._analyze_redirect_chain(redirect_chain))

        # Additional protocol-level warnings
        final_url = redirect_chain[-1].url if redirect_chain else original_url
        if final_url.startswith("http://"):
            warnings.append("Final destination uses HTTP - no transport encryption")

        return SecurityReport(
            final_url=final_url,
            status_code=response.status_code,
            redirect_chain=redirect_chain,
            headers=dict(response.headers),
            analyses=analyses,
            total_score=total_score,
            max_score=max_score,
            exposure_penalty=exposure_penalty,
            warnings=warnings,
        )

    def _analyze_header(
        self, header_name: str, header_value: str | None, config: dict
    ) -> HeaderAnalysis:
        """Analyze individual header with improved severity calculation."""
        expected_severity = config["severity"]
        analyzer = config.get("analyzer")

        if header_value is None:
            return HeaderAnalysis(
                name=header_name,
                present=False,
                expected_severity=expected_severity,
                effective_severity=expected_severity,
                quality=HeaderQuality.MISSING,
                score=0.0,
                max_score=self._severity_to_score(expected_severity),
                recommendations=[self._get_missing_recommendation(header_name)],
            )

        # Header present - analyze quality
        if analyzer:
            quality, issues, recommendations, issue_types = analyzer(header_value)
        else:
            quality, issues, recommendations, issue_types = self._simple_validate(
                header_name, header_value
            )

        # Calculate scores
        max_score = self._severity_to_score(expected_severity)
        score = self._quality_to_score(quality, max_score)

        # Effective severity calculation - the strategic assessment
        effective_severity = self._calculate_effective_severity(
            expected_severity, quality, issue_types
        )

        return HeaderAnalysis(
            name=header_name,
            present=True,
            value=header_value,
            expected_severity=expected_severity,
            effective_severity=effective_severity,
            quality=quality,
            score=score,
            max_score=max_score,
            issues=issues,
            recommendations=recommendations,
            issue_types=issue_types,
        )

    def _calculate_effective_severity(
        self, expected: Severity, quality: HeaderQuality, issue_types: set
    ) -> Severity:
        """
        Calculate effective severity based on expected severity and quality.

        The severity matrix: where optimism meets reality.
        Well, that was quite the strategic decision, wasn't it?
        """
        # Missing headers maintain expected severity - absence is the issue
        if quality == HeaderQuality.MISSING:
            return expected

        # Dangerous headers maintain high severity - presence makes it worse
        if quality == HeaderQuality.DANGEROUS:
            return expected

        # Severity reduction matrix - tactical to effective severity mapping
        severity_matrix = {
            (Severity.CRITICAL, HeaderQuality.EXCELLENT): Severity.INFO,
            (Severity.CRITICAL, HeaderQuality.GOOD): Severity.LOW,
            (Severity.CRITICAL, HeaderQuality.WEAK): Severity.HIGH,
            (Severity.HIGH, HeaderQuality.EXCELLENT): Severity.INFO,
            (Severity.HIGH, HeaderQuality.GOOD): Severity.LOW,
            (Severity.HIGH, HeaderQuality.WEAK): Severity.MEDIUM,
            (Severity.MEDIUM, HeaderQuality.EXCELLENT): Severity.INFO,
            (Severity.MEDIUM, HeaderQuality.GOOD): Severity.INFO,
            (Severity.MEDIUM, HeaderQuality.WEAK): Severity.LOW,
            (Severity.LOW, HeaderQuality.EXCELLENT): Severity.INFO,
            (Severity.LOW, HeaderQuality.GOOD): Severity.INFO,
            (Severity.LOW, HeaderQuality.WEAK): Severity.INFO,
            (Severity.INFO, HeaderQuality.EXCELLENT): Severity.INFO,
            (Severity.INFO, HeaderQuality.GOOD): Severity.INFO,
            (Severity.INFO, HeaderQuality.WEAK): Severity.INFO,
        }

        return severity_matrix.get((expected, quality), expected)

    def _simple_validate(
        self, header_name: str, value: str
    ) -> tuple[HeaderQuality, list[str], list[str], set]:
        """Simple validation for headers without dedicated analyzers."""
        issues = []
        recommendations = []
        issue_types = set()
        value_lower = value.lower()

        if header_name == "x-frame-options":
            if value_lower in ("deny", "sameorigin"):
                quality = HeaderQuality.EXCELLENT
            elif value_lower.startswith("allow-from"):
                quality = HeaderQuality.WEAK
                issues.append("ALLOW-FROM is deprecated and not widely supported")
                recommendations.append("Use CSP frame-ancestors instead")
                issue_types.add("deprecated")
            else:
                quality = HeaderQuality.WEAK
                issues.append(f"Invalid value: '{value}'")
                issue_types.add("invalid")

        elif header_name == "x-content-type-options":
            if value_lower == "nosniff":
                quality = HeaderQuality.EXCELLENT
            else:
                quality = HeaderQuality.WEAK
                issues.append(f"Expected 'nosniff', found '{value}'")
                recommendations.append("Set to 'nosniff' to prevent MIME sniffing")
                issue_types.add("invalid")

        elif header_name == "x-xss-protection":
            if value_lower == "0":
                quality = HeaderQuality.EXCELLENT
            else:
                quality = HeaderQuality.WEAK
                issues.append("Set to '0' to disable legacy XSS filter")
                recommendations.append("Modern browsers use CSP; XSS filter can cause issues")
                issue_types.add("legacy")

        else:
            quality = HeaderQuality.GOOD

        return quality, issues, recommendations, issue_types

    def _quality_to_score(self, quality: HeaderQuality, max_score: float) -> float:
        """Convert quality assessment to score. The grade calculation."""
        multipliers = {
            HeaderQuality.EXCELLENT: 1.0,
            HeaderQuality.GOOD: 0.75,
            HeaderQuality.WEAK: 0.5,
            HeaderQuality.DANGEROUS: 0.0,
            HeaderQuality.MISSING: 0.0,
        }
        return max_score * multipliers.get(quality, 0.0)

    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to maximum possible score. Weight distribution."""
        scores = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 20.0,
            Severity.MEDIUM: 10.0,
            Severity.LOW: 5.0,
            Severity.INFO: 1.0,
        }
        return scores.get(severity, 0.0)

    def _get_missing_recommendation(self, header_name: str) -> str:
        """Get recommendation for missing header. The tactical guidance."""
        recommendations = {
            "strict-transport-security": "Add Strict-Transport-Security (HSTS) with min max-age=31536000; includeSubDomains",
            "content-security-policy": "Implement Content-Security-Policy (CSP) starting with default-src 'self'",
            "x-frame-options": "Add X-Frame-Options: DENY or SAMEORIGIN",
            "x-content-type-options": "Add X-Content-Type-Options: nosniff",
            "referrer-policy": "Add Referrer-Policy: strict-origin-when-cross-origin",
            "permissions-policy": "Define Permissions-Policy to restrict features",
            "cross-origin-embedder-policy": "Add Cross-Origin-Embedder-Policy: require-corp",
            "cross-origin-opener-policy": "Add Cross-Origin-Opener-Policy: same-origin",
            "cross-origin-resource-policy": "Add Cross-Origin-Resource-Policy: same-origin",
            "x-xss-protection": "Add X-XSS-Protection: 0 (disables legacy filter)",
        }
        return recommendations.get(header_name, f"Configure {header_name} header")

    def _analyze_redirect_chain(self, chain: list[RedirectHop]) -> list[str]:
        """Analyze redirect chain for security concerns. Follow the breadcrumbs."""
        warnings = []

        schemes = [hop.scheme for hop in chain]

        # Check for protocol downgrades - the cardinal sin
        if "http" in schemes:
            https_index = next((i for i, s in enumerate(schemes) if s == "https"), None)
            http_indices = [i for i, s in enumerate(schemes) if s == "http"]

            if https_index is not None and http_indices:
                if any(i > https_index for i in http_indices):
                    warnings.append("HTTPS downgrade detected in redirect chain")
                else:
                    warnings.append(f"Initial request over HTTP (redirects: {len(chain)-1})")

        # Excessive redirects - performance and potential loop concerns
        if len(chain) > 3:
            warnings.append(f"Excessive redirects: {len(chain)} hops")

        # Check for cross-domain redirects
        domains = [urlparse(hop.url).netloc for hop in chain]
        if len(set(domains)) > 1:
            warnings.append(f"Cross-domain redirects detected: {' -> '.join(domains)}")

        return warnings
