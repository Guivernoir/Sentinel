# Security Policy

## Our Commitment

Sentinel is a security analysis tool. We take the security of the tool itself seriously, because a compromised security analyzer is worse than no analyzer at all.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅ Yes    |
| < 1.0   | ❌ No     |

Security updates are provided for the current major version.

## Known Security Considerations

### 1. Certificate Validation

Sentinel validates SSL/TLS certificates by default using `httpx`. This is the correct and secure behavior.

**Do not disable certificate validation in production.**

### 2. Information in Analysis Reports

Sentinel's analysis reports contain:

- Full URLs including paths and query parameters
- Server response headers (may contain sensitive information)
- Technology stack information
- Server configuration details

**⚠️ Review reports before sharing publicly** - they may contain sensitive information about your infrastructure.

### 3. SSRF (Server-Side Request Forgery) Considerations

Sentinel makes HTTP requests to user-specified URLs. Be aware that:

- **Do not** allow untrusted users to specify arbitrary URLs
- **Do not** run Sentinel with access to sensitive internal networks without restrictions
- **Consider** network segmentation and egress filtering
- **Use** the `--timeout` flag to prevent long-running requests

**Example safe usage:**

```bash
# Run with timeout limit
sentinel analyze example.com --timeout 10

# Don't allow untrusted input
sentinel analyze "$USER_INPUT"  # ❌ DANGEROUS

# Validate input first
if [[ "$URL" =~ ^https://example\.com ]]; then
    sentinel analyze "$URL"  # ✅ SAFER
fi
```

### 4. Dependency Security

Sentinel relies on:

- `httpx` - Async HTTP client
- `rich` - Terminal rendering
- `typer` - CLI framework
- `pytest` and dev tools

We monitor these dependencies for security advisories. To check for vulnerabilities:

```bash
# Check for known vulnerabilities
pip-audit

# Update dependencies
pip install --upgrade sentinel-security-analyzer
```

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

**Option 1: GitHub Security Advisories (Preferred)**

1. Go to the repository "Security" tab
2. Click "Report a vulnerability"
3. Fill out the private security advisory form

**Option 2: Email**

- Contact the maintainer through GitHub profile email
- Include detailed vulnerability information
- Encrypt sensitive details if possible

### What to Include

- **Description**: Clear explanation of the vulnerability
- **Steps to Reproduce**: Detailed reproduction steps
- **Impact**: Potential security impact
- **Affected Versions**: Which versions are vulnerable
- **Suggested Fix**: If you have one (optional)
- **Your Contact**: How we can reach you for follow-up

### Response Timeline

- **Initial Response**: Within 72 hours
- **Status Update**: Within 1 week
- **Fix Timeline**:
  - Critical: 48-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next planned release

### What to Expect

1. **Acknowledgment**: We'll confirm receipt of your report
2. **Validation**: We'll investigate and assess the vulnerability
3. **Communication**: We'll keep you updated on progress
4. **Disclosure**: We'll coordinate public disclosure with you
5. **Credit**: We'll credit you in the security advisory (with your permission)

## Security Best Practices for Users

### Installation Security

```bash
# Always install from official sources
pip install sentinel-security-analyzer

# Verify package
pip show sentinel-security-analyzer

# Use virtual environments (isolation)
python -m venv .venv
source .venv/bin/activate
pip install sentinel-security-analyzer
```

### Safe Usage Patterns

```bash
# Set reasonable timeouts
sentinel analyze example.com --timeout 10

# Be cautious with untrusted domains
sentinel analyze suspicious-site.com --no-redirect

# Don't analyze internal services from untrusted networks
sentinel analyze internal.corp.com  # ⚠️ Consider network isolation
```

### Output Security

```python
# Sanitize reports before sharing
report = await analyzer.analyze(url)

# Remove sensitive headers before logging/sharing
safe_headers = {
    k: v for k, v in report.headers.items()
    if k.lower() not in (
        'authorization',
        'cookie',
        'x-api-key',
        'set-cookie'
    )
}
```

## Vulnerability Disclosure Policy

### Our Approach

- **Coordinated Disclosure**: We work with security researchers
- **Responsible Timeline**: 90 days for non-critical issues
- **Public Credit**: We acknowledge security researchers (with permission)
- **Security Advisories**: Published via GitHub Security Advisories

### Scope

**In Scope:**

- Remote code execution
- Authentication/authorization bypass
- Information disclosure (unintended)
- Denial of service vulnerabilities
- Command injection
- SSRF vulnerabilities
- Path traversal
- Unsafe deserialization

**Out of Scope:**

- Social engineering attacks
- Physical access attacks
- Issues requiring local system access
- Known issues already documented
- Issues in third-party dependencies (report to upstream)
- Rate limiting on public APIs

## Security Features

### Current Implementation

**Input Validation**

- URL normalization and validation
- Timeout enforcement (default: 10 seconds)
- Redirect loop prevention (max: 10 hops)
- Header value sanitization

**Safe Defaults**

- Certificate validation enabled (cannot be disabled)
- Reasonable timeout values
- Limited redirect following
- No data persistence

**Error Handling**

- Graceful failure on invalid input
- No stack trace information disclosure
- Proper exception handling throughout

**Type Safety**

- Comprehensive type hints
- Static type checking with mypy
- Runtime validation where needed

## Security Checklist for Contributors

When contributing code, ensure:

- [ ] No hardcoded credentials or secrets
- [ ] Input validation for all user-supplied data
- [ ] Proper error handling (no information leakage in errors)
- [ ] No unsafe deserialization
- [ ] No command injection vectors
- [ ] No path traversal vulnerabilities
- [ ] Dependencies are up to date
- [ ] Security-relevant changes are documented
- [ ] Tests cover security-relevant functionality
- [ ] No `eval()`, `exec()`, or similar dangerous functions
- [ ] Certificate validation not disabled

## Cryptographic Considerations

**Note**: Sentinel is an analysis tool, not a cryptographic implementation.

- We rely on `httpx` for TLS/SSL validation
- We do not implement custom cryptography
- We follow Python security best practices
- Certificate validation is **always** enabled

## Security Research & Testing

If you're security testing Sentinel:

**Encouraged:**

- Fuzzing the CLI with unusual inputs
- Testing with malformed HTTP responses
- Analyzing the code for vulnerabilities
- Checking dependencies for known issues

**Please Report:**

- Any command injection possibilities
- SSRF vectors
- Information disclosure issues
- Any way to bypass certificate validation

**Testing Environment:**

```bash
# Set up isolated testing environment
python -m venv test-venv
source test-venv/bin/activate
pip install sentinel-security-analyzer

# Test with various inputs
sentinel analyze "https://example.com"
sentinel analyze "http://localhost"
sentinel analyze "file:///etc/passwd"  # Should fail safely
```

## Incident Response

If you believe Sentinel contributed to a security incident:

1. **Document everything**: Logs, commands, outputs
2. **Isolate affected systems** if needed
3. **Contact us immediately** via security advisory
4. **Preserve evidence** for investigation
5. **Follow your incident response plan**

## Contact

- **Security Issues**: Use GitHub Security Advisories (preferred)
- **General Questions**: Open a public issue on GitHub
- **Maintainer**: Contact via GitHub profile

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

_No vulnerabilities reported yet. Be the first to help improve Sentinel's security!_

Once vulnerabilities are reported and fixed, contributors will be listed here (with permission).

## Resources

### Security References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [NIST Vulnerability Disclosure](https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity/vulnerability-disclosure-policy-template)

### Dependency Security

- [httpx Security](https://www.python-httpx.org/)
- [pip-audit](https://github.com/pypa/pip-audit) - Scan for known vulnerabilities
- [Safety](https://pyup.io/safety/) - Check Python dependencies

---

**Last Updated**: January 8, 2026  
**Version**: 1.0

_Security is not a feature, it's a foundation. We treat every report seriously and work to make Sentinel a trustworthy tool in your security toolkit._
