# Sentinel Security Header Analyzer

> Deterministic, explainable HTTP security header policy evaluation for engineers who need to understand *why*.

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Core Coverage](https://img.shields.io/badge/core%20coverage-95%25-brightgreen.svg)](https://github.com/Guivernoir/sentinel)
[![Tests](https://img.shields.io/badge/tests-154%20passing-brightgreen.svg)](https://github.com/Guivernoir/sentinel)

Sentinel analyzes HTTP security headers against a strict defense-in-depth security model. Unlike binary pass/fail scanners, it provides nuanced quality assessment, issue categorization, and actionable recommendations based on an opinionated but transparent security philosophy.

## What Makes Sentinel Different

**Explainability Over Simplicity**
- Issues categorized by type (structural, unsafe, wildcard, downgrade)
- Quality grades beyond pass/fail (EXCELLENT → GOOD → WEAK → DANGEROUS)
- Actionable recommendations tied to specific problems

**Deterministic & Testable**
- Same input → same output, always
- 154 tests covering edge cases and real-world scenarios
- Core analysis logic: 95%+ test coverage

**Opinionated But Transparent**
- Encodes a strict AppSec security stance
- Severity weights and thresholds are explicit
- Philosophy: defense-in-depth > minimum compliance

**Built for Engineers**
- Parseable JSON output (planned)
- Programmatic API for integration
- Rich terminal UI for interactive use

## What Sentinel Measures (And Doesn't)

### ✅ What We Analyze

**HTTP Header Configuration** - The defense-in-depth layer provided by response headers:
- Presence and quality of security headers
- Policy syntax and semantics (CSP, HSTS, etc.)
- Misconfigurations that create attack surface
- Information disclosure through header values

### ❌ What We Don't Measure

**Effective Security Posture** - Sentinel cannot see:
- Internal routing and security layers
- Origin-specific policies applied upstream
- Browser-level mitigations
- WAF rules and protections
- Application-level security controls

**Important:** A low Sentinel score indicates **header-based defense gaps**, not necessarily exploitable vulnerabilities. Organizations may have compensating controls Sentinel cannot observe.

## Real-World Example: Header Analysis vs. Security Posture

Here's what analyzing a major site reveals about **header-based defense-in-depth**:

```bash
$ sentinel analyze google.com

╭────────────────────────── Sentinel Analysis Report ──────────────────────────╮
│ Target: https://www.google.com/                                              │
│ Status: 200                                                                  │
│ Score: 9.0/96.0 (9.4%)                                                       │
│ Assessment: VULNERABLE (header-based defense)                                │
│ Redirects: 1                                                                 │
╰──────────────────────────────────────────────────────────────────────────────╯

                            Security Header Analysis                            
╭────────────────────────┬──┬──────┬──┬────────────────────────────────────────╮
│ Header                 │  │ Qual │  │ Analysis                               │
├────────────────────────┼──┼──────┼──┼────────────────────────────────────────┤
│ strict-transport-secu… │  │ MISS │  │ HSTS not present in response           │
│ content-security-poli… │  │ MISS │  │ No CSP header-based XSS protection     │
│ x-frame-options        │  │ EXCL │  │ —                                      │
│ x-content-type-options │  │ MISS │  │ MIME type sniffing not prevented       │
│ referrer-policy        │  │ MISS │  │ No referrer control header             │
│ permissions-policy     │  │ MISS │  │ No feature policy restrictions         │
│ server                 │  │ DANG │  │ Reveals: "gws" (information leakage)   │
╰────────────────────────┴──┴──────┴──┴────────────────────────────────────────╯
```

**What This Tells Us:**
- Header-based defense-in-depth is minimal
- Missing standard security headers (HSTS, CSP)
- Relies on other security layers not visible to header analysis

**What This Doesn't Tell Us:**
- Whether the site is actually vulnerable
- What upstream security controls exist
- How Chrome's built-in protections apply
- Whether APIs and backends have different policies

**Key Insight:** Large organizations often implement security controls at layers Sentinel cannot observe. Missing headers indicate increased reliance on other security mechanisms, not necessarily exploitable vulnerabilities.

## Installation

### From Source

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quick Start

```bash
# Analyze header-based defense posture
sentinel analyze example.com

# Detailed output with issue explanations
sentinel analyze example.com --verbose

# Custom timeout for slow servers
sentinel analyze example.com --timeout 30

# Analyze without following redirects
sentinel analyze example.com --no-redirect
```

## Usage Examples

### Command Line Interface

```bash
# Basic analysis
sentinel analyze example.com

# Analyze with timeout
sentinel analyze slow-server.com --timeout 60

# Analyze HTTP explicitly (not recommended for production)
sentinel analyze http://example.com --no-redirect

# Verbose mode shows all header details and reasoning
sentinel analyze example.com --verbose
```

### Programmatic Usage

```python
import asyncio
from sentinel.analyzer import SecurityHeadersAnalyzer

async def analyze_headers():
    analyzer = SecurityHeadersAnalyzer(
        timeout=10,
        follow_redirects=True,
        max_redirects=10
    )

    report = await analyzer.analyze("https://example.com")

    # Access structured data
    print(f"Score: {report.total_score}/{report.max_score}")
    print(f"Assessment: {report.status_code}")
    
    # Examine specific headers
    for analysis in report.analyses:
        if not analysis.present:
            print(f"Missing: {analysis.name}")
        elif analysis.quality.value == "dangerous":
            print(f"Dangerous: {analysis.name} - {analysis.issues}")

asyncio.run(analyze_headers())
```

### Testing Individual Policies

```python
from sentinel.csp import CSPAnalyzer
from sentinel.hsts import HSTSAnalyzer
from sentinel.models import HeaderQuality

# Analyze a Content Security Policy
quality, issues, recommendations, issue_types = CSPAnalyzer.analyze(
    "default-src 'self'; script-src 'unsafe-inline' *"
)

print(f"Quality: {quality}")  # HeaderQuality.DANGEROUS
print(f"Issues: {issues}")     # Specific problems identified
print(f"Types: {issue_types}") # {ISSUE_TYPE_UNSAFE, ISSUE_TYPE_WILDCARD}
```

## Analyzed Headers

| Header                         | Severity | Purpose                                | Coverage |
| ------------------------------ | -------- | -------------------------------------- | -------- |
| `Strict-Transport-Security`    | HIGH     | Forces HTTPS connections               | 100%     |
| `Content-Security-Policy`      | HIGH     | Prevents XSS and injection attacks     | 98%      |
| `X-Frame-Options`              | MEDIUM   | Clickjacking protection                | 100%     |
| `X-Content-Type-Options`       | MEDIUM   | MIME sniffing prevention               | 100%     |
| `Referrer-Policy`              | MEDIUM   | Controls referrer information leakage  | 100%     |
| `Permissions-Policy`           | MEDIUM   | Restricts browser feature access       | 95%      |
| `Cross-Origin-Embedder-Policy` | LOW      | Resource isolation                     | 100%     |
| `Cross-Origin-Opener-Policy`   | LOW      | Process isolation                      | 100%     |
| `Cross-Origin-Resource-Policy` | LOW      | Resource access control                | 100%     |
| `X-XSS-Protection`             | INFO     | Legacy XSS filter (should be disabled) | 100%     |

### Information Disclosure Detection

Sentinel also identifies headers that expose technology stack information:

| Header               | Penalty | Information Revealed         |
| -------------------- | ------- | ---------------------------- |
| `Server`             | 2.0 pts | Web server software          |
| `X-Powered-By`       | 3.0 pts | Framework/language stack     |
| `X-AspNet-Version`   | 2.0 pts | ASP.NET version              |
| `X-AspNetMvc-Version`| 2.0 pts | MVC framework version        |
| `X-Generator`        | 2.0 pts | CMS/generator information    |

## Scoring Philosophy (Transparent & Opinionated)

### This Is Not "Objective"

Sentinel's scoring embodies **opinionated security priorities**:
- Defense-in-depth over minimum compliance
- Strict > permissive when in doubt
- Information disclosure matters
- Partial correctness < absence for critical headers

**If you disagree with these priorities**, Sentinel may not match your security model. That's intentional - we'd rather be consistently strict than universally agreeable.

### Quality Assessment

**Header Quality Levels:**
- **EXCELLENT** (100%): Best-practice configuration
- **GOOD** (75%): Solid with minor improvements possible
- **WEAK** (50%): Present but poorly configured
- **DANGEROUS** (0%): Configuration creates vulnerabilities
- **MISSING** (0%): Header absent when expected

### Severity Weights (Hardcoded Philosophy)

```python
# Maximum points per severity
Severity.HIGH     → 20.0 points  # HSTS, CSP - critical defenses
Severity.MEDIUM   → 10.0 points  # X-Frame-Options, etc. - important controls
Severity.LOW      →  5.0 points  # Cross-Origin - defense-in-depth
Severity.INFO     →  1.0 points  # X-XSS-Protection - deprecated
```

**Total possible: 96 points** (2×HIGH + 5×MEDIUM + 3×LOW + 1×INFO)

### Overall Assessment Thresholds

| Score Range | Assessment | Meaning                                |
| ----------- | ---------- | -------------------------------------- |
| 85%+        | STRONG     | Best-practice defense-in-depth         |
| 70-84%      | ADEQUATE   | Solid foundation, minor gaps           |
| 50-69%      | WEAK       | Significant improvements needed        |
| <50%        | VULNERABLE | Critical header-based defense gaps     |

**Note:** These thresholds reflect a strict AppSec stance. A 50% score doesn't mean "half secure" - it means "header-based defenses need significant work."

## Configuration Examples

### Nginx - Strong Header Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # Security headers (STRONG configuration by Sentinel standards)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header X-XSS-Protection "0" always;

    # Remove information disclosure
    server_tokens off;
    more_clear_headers 'Server';
    more_clear_headers 'X-Powered-By';
}
```

**Expected Sentinel Score: ~90%** (STRONG)

## Architecture & Design

```
sentinel/
├── models.py              # Data structures (Severity, Quality, Reports)
├── exceptions.py          # Custom exception hierarchy
├── analyzer.py           # Main orchestration (84% coverage)
├── hsts.py              # HSTS analyzer (100% coverage)
├── csp.py               # CSP analyzer (98% coverage)
├── coop.py              # Cross-Origin analyzers (100% coverage)
├── permissions_policy.py # Permissions-Policy (95% coverage)
├── referrer_policy.py   # Referrer-Policy (100% coverage)
├── renderer.py          # Terminal output (integration tests needed)
└── cli.py               # CLI interface (integration tests needed)
```

### Design Principles

**1. Core Logic Correctness Over UI Coverage**
- Analyzers: 95%+ test coverage
- Orchestration: 84% coverage
- CLI/Renderer: Integration tests planned

Why? Core logic bugs silently produce wrong security assessments. UI bugs are obvious.

**2. Issue Taxonomy Over Binary Results**
```python
# CSP issues categorized by nature
ISSUE_TYPE_STRUCTURAL = "structural"  # Missing directives
ISSUE_TYPE_UNSAFE = "unsafe"          # unsafe-inline, unsafe-eval
ISSUE_TYPE_WILDCARD = "wildcard"      # Wildcard sources
ISSUE_TYPE_DOWNGRADE = "downgrade"    # HTTP in HTTPS context
```

This enables precise severity calculation and targeted recommendations.

**3. Deterministic & Reproducible**
- Same input → same output
- No randomness, no external calls during analysis
- Testable with standard unit tests

## Testing

### Coverage Breakdown

```
Core Analysis (What Matters):
├── hsts.py               100% (13 tests)
├── csp.py                 98% (37 tests)
├── coop.py               100% (27 tests)
├── referrer_policy.py    100% (22 tests)
├── permissions_policy.py  95% (20 tests)
├── models.py             100% (15 tests)
└── exceptions.py         100%

Integration:
├── analyzer.py            84% (20 tests) - some error paths untested
├── cli.py                  0% (integration tests planned)
└── renderer.py             0% (integration tests planned)

Total: 154 tests passing, ~75% overall coverage
```

**Philosophy:** We prioritize coverage where bugs have the highest impact (parsing logic, policy evaluation). CLI/UI tests are planned but lower priority than correctness.

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov

# Core analyzers only
pytest tests/test_csp.py tests/test_hsts.py tests/test_coop.py

# Specific test
pytest tests/test_csp.py::TestCSPAnalysis::test_unsafe_inline_detected -v
```

## Known Limitations & Roadmap

### Current Limitations

**Scope:**
- Header analysis only (no page content scanning)
- Single-URL analysis (no site crawling)
- No historical tracking
- Terminal output only (JSON export planned)

**Coverage Gaps:**
- CLI integration tests (0% → planned 80%)
- Renderer tests (0% → planned 80%)
- Some edge cases in redirect handling

### Planned Improvements

- [ ] JSON output format
- [ ] CLI integration tests
- [ ] Renderer unit tests
- [ ] Configurable severity weights (advanced users)
- [ ] Batch analysis mode
- [ ] CI/CD integration guide
- [ ] Custom rule definitions

**Not Planned (Scope Creep):**
- Historical tracking / dashboards → use dedicated tools
- Site crawling → use dedicated scanners
- Vulnerability exploitation → not a pentesting tool

### Positioning: What Sentinel Is

✅ **A deterministic header policy evaluator**
- Explainable assessments
- Reproducible results
- Testable analysis logic

✅ **A library that happens to have a CLI**
- Import `SecurityHeadersAnalyzer` in your code
- Use programmatically for automation
- CLI is a convenience, not the primary interface

❌ **Not a complete security scanner**
- Use ZAP, Burp, or Nuclei for comprehensive testing
- Sentinel is one tool in a security toolkit

❌ **Not a vulnerability discovery tool**
- Reports misconfigurations, not exploits
- Shows attack surface, not proof of compromise

## Development

### Setup

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Code Quality

```bash
# Format
black sentinel tests

# Lint
ruff check sentinel tests

# Type check
mypy sentinel

# Test
pytest --cov

# All checks
make all  # or: black . && ruff check . && mypy . && pytest
```

## Contributing

Contributions welcome. Priority areas:

1. **CLI integration tests** - bring coverage to 80%+
2. **Renderer tests** - validate output formatting
3. **JSON export** - machine-readable output
4. **Edge case tests** - unusual header configurations

Requirements:
- All tests pass
- Core analyzer coverage maintained at 95%+
- Code formatted (black), linted (ruff), type-checked (mypy)
- New features include tests

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

**Key Points:**
- Sentinel makes HTTP requests to user-specified URLs (SSRF considerations)
- Analysis reports may contain sensitive headers (don't share blindly)
- Certificate validation is always enabled (no unsafe mode)

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

Built with:
- [httpx](https://www.python-httpx.org/) - Modern async HTTP
- [rich](https://rich.readthedocs.io/) - Terminal formatting
- [typer](https://typer.tiangolo.com/) - CLI framework
- [pytest](https://pytest.org/) - Testing

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [HSTS Preload List](https://hstspreload.org/)

---

**Built for engineers who need deterministic, explainable security policy evaluation.**

Not trying to be everything. Just trying to be correct.
