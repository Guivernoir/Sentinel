# Sentinel Test Suite

> Comprehensive test coverage for tactical security analysis.

## Overview

The test suite validates all components of Sentinel Security Header Analyzer, from individual header analyzers to full integration workflows. With 154 passing tests and 75% overall coverage, the core analysis functionality is thoroughly validated.

## Test Statistics

```bash
======================== 154 passed in 4.03s ========================

Coverage by Module:
Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------
sentinel/analyzer.py               166     26    84%   138-140, 155-170, 177-187, 234, 239, 390
sentinel/csp.py                     94      2    98%   89, 91
sentinel/coop.py                    90      0   100%
sentinel/hsts.py                    60      0   100%
sentinel/permissions_policy.py      60      3    95%   60-61, 103
sentinel/referrer_policy.py         50      0   100%
sentinel/models.py                  45      0   100%
sentinel/exceptions.py               8      0   100%
sentinel/base.py                     6      6     0%   6-24
sentinel/cli.py                     55     55     0%   6-123
sentinel/renderer.py                83     83     0%   6-180
--------------------------------------------------------------
TOTAL                              705    173    75%
```

**Coverage Status:**

- ✅ **Core Analyzers**: 95-100% coverage
- ✅ **Models & Exceptions**: 100% coverage
- ⚠️ **Main Analyzer**: 84% coverage (integration workflows)
- ❌ **CLI & Renderer**: 0% coverage (needs integration tests)

## Test Structure

```
tests/
├── __init__.py                    # Test package initialization
├── conftest.py                    # Shared fixtures and configuration
├── test_models.py                 # Data structure tests (15 tests, 100%)
├── test_hsts.py                  # HSTS analyzer tests (13 tests, 100%)
├── test_csp.py                   # CSP analyzer tests (37 tests, 98%)
├── test_coop.py                  # Cross-origin tests (27 tests, 100%)
├── test_permissions_policy.py    # Permissions-Policy tests (20 tests, 95%)
├── test_referrer_policy.py       # Referrer-Policy tests (22 tests, 100%)
└── test_analyzer.py              # Integration tests (20 tests, 84%)
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov

# Run with verbose output
pytest -v

# Generate HTML coverage report
pytest --cov --cov-report=html
open htmlcov/index.html
```

### Advanced Usage

```bash
# Run specific test file
pytest tests/test_csp.py

# Run specific test class
pytest tests/test_csp.py::TestCSPAnalysis

# Run specific test
pytest tests/test_csp.py::TestCSPAnalysis::test_empty_csp_is_dangerous

# Run tests matching pattern
pytest -k "test_excellent"

# Stop on first failure
pytest -x

# Show local variables on failure
pytest -l

# Run with debugging
pytest --pdb

# Parallel execution (requires pytest-xdist)
pytest -n auto
```

## Test Coverage by Module

### Fully Covered (100%)

**models.py** - Data structures

- ✅ All enums (Severity, HeaderQuality)
- ✅ All dataclasses (HeaderAnalysis, SecurityReport, RedirectHop)
- ✅ Default values and field factories

**hsts.py** - HSTS Analyzer (13 tests)

- ✅ Excellent configurations
- ✅ Max-age validation (minimum, recommended)
- ✅ includeSubDomains detection
- ✅ Preload validation
- ✅ Case insensitivity
- ✅ Whitespace handling
- ✅ Invalid values
- ✅ Edge cases (max-age=0, missing directives)

**coop.py** - Cross-Origin Policies (27 tests)

- ✅ COOP analyzer (same-origin, same-origin-allow-popups, unsafe-none)
- ✅ COEP analyzer (require-corp, credentialless)
- ✅ CORP analyzer (same-origin, same-site, cross-origin)
- ✅ Invalid policy detection
- ✅ Case insensitivity

**referrer_policy.py** - Referrer Policy (22 tests)

- ✅ All policy values (no-referrer, strict-origin, etc.)
- ✅ Quality assessment (EXCELLENT, GOOD, WEAK)
- ✅ Multiple policy handling (last wins)
- ✅ Trailing comma handling
- ✅ Recommendations for weak policies

**exceptions.py** - Custom Exceptions

- ✅ Exception hierarchy
- ✅ Exception messages
- ✅ Exception inheritance

### Near-Complete Coverage

**csp.py** - CSP Analyzer (37 tests, 98% coverage)

- ✅ Directive parsing
- ✅ Multiple directive handling
- ✅ Unsafe keyword detection (unsafe-inline, unsafe-eval)
- ✅ Wildcard source detection
- ✅ HTTP downgrade detection
- ✅ Data URI in script-src
- ✅ Deprecated directive detection
- ✅ Quality assessment (EXCELLENT → DANGEROUS)
- ✅ Nonce and hash validation
- ✅ Complex policy validation
- ⚠️ 2 edge case branches not covered

**permissions_policy.py** - Permissions Policy (20 tests, 95% coverage)

- ✅ Feature parsing
- ✅ Allowlist validation
- ✅ Self/none/wildcard handling
- ✅ Origin validation
- ✅ Quality assessment
- ⚠️ 3 minor branches not covered

**analyzer.py** - Main Orchestrator (20 tests, 84% coverage)

- ✅ URL normalization
- ✅ Redirect chain following
- ✅ Header analysis orchestration
- ✅ Score calculation
- ✅ Information disclosure detection
- ✅ Severity calculation matrix
- ⚠️ Some error handling paths not covered
- ⚠️ Some edge cases in redirect handling

### Not Covered (Need Integration Tests)

**cli.py** - Command Line Interface (0% coverage)

- ❌ Argument parsing
- ❌ Command execution
- ❌ Error handling
- ❌ Output formatting

**renderer.py** - Terminal Output (0% coverage)

- ❌ Report rendering
- ❌ Color formatting
- ❌ Table generation
- ❌ Verbose mode

**base.py** - Protocol Definition (0% coverage)

- ❌ Protocol interfaces
- ❌ (Protocols don't require runtime coverage)

## Test Examples

### Example 1: Simple Header Validation

```python
def test_hsts_excellent_configuration(self):
    """Test perfectly configured HSTS."""
    quality, issues, recs, types = HSTSAnalyzer.analyze(
        "max-age=31536000; includeSubDomains"
    )

    assert quality == HeaderQuality.EXCELLENT
    assert len(issues) == 0
```

### Example 2: Issue Detection

```python
def test_csp_detects_unsafe_inline(self):
    """Test detection of unsafe-inline in CSP."""
    quality, issues, recs, types = CSPAnalyzer.analyze(
        "default-src 'self'; script-src 'unsafe-inline'"
    )

    assert quality in (HeaderQuality.WEAK, HeaderQuality.DANGEROUS)
    assert any("unsafe-inline" in issue.lower() for issue in issues)
    assert CSPAnalyzer.ISSUE_TYPE_UNSAFE in types
    assert len(recs) > 0
```

### Example 3: Edge Case Testing

```python
def test_trailing_comma_handling(self):
    """Test handling of trailing comma in referrer policy."""
    quality, issues, _, _ = ReferrerPolicyAnalyzer.analyze(
        "no-referrer,"
    )

    # Should parse correctly despite trailing comma
    assert quality == HeaderQuality.EXCELLENT
```

### Example 4: Complex Policy Validation

```python
def test_complex_valid_csp(self):
    """Test complex but valid CSP."""
    quality, issues, recs, types = CSPAnalyzer.analyze(
        "default-src 'self'; "
        "script-src 'self' https://cdn.example.com 'nonce-random'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.googleapis.com; "
        "connect-src 'self' https://api.example.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Has unsafe-inline in style-src but that's common and acceptable
    assert quality in (HeaderQuality.GOOD, HeaderQuality.WEAK)
```

## Test Organization

### Test Class Structure

```python
class TestCSPParser:
    """Test CSP parsing functionality."""
    # Tests for parse_directives() method

class TestCSPAnalysis:
    """Test CSP analysis functionality."""
    # Tests for analyze() method and quality assessment

class TestCSPEdgeCases:
    """Test CSP edge cases and corner cases."""
    # Unusual inputs, malformed headers, etc.
```

### Test Naming Conventions

- **Classes**: `TestFeatureName` or `TestComponentName`
- **Methods**: `test_behavior_description`
- **Descriptive**: Name explains what's being tested

Examples:

- `test_empty_csp_is_dangerous`
- `test_unsafe_inline_detected`
- `test_multiple_policies_last_wins`

## Critical Test Scenarios

### Security Issue Detection

These tests ensure we catch real vulnerabilities:

```python
# CSP - Unsafe practices
test_unsafe_inline_detected()
test_unsafe_eval_detected()
test_wildcard_sources_detected()
test_http_sources_detected()
test_data_uri_in_script_src()

# HSTS - Weak configuration
test_short_max_age_below_minimum()
test_max_age_zero()  # Disables HSTS!
test_invalid_max_age()

# Referrer Policy - Information leakage
test_unsafe_url_weak()
test_origin_weak()
```

### Quality Assessment

Tests that verify our scoring system:

```python
test_excellent_strict_csp()
test_good_quality_minor_issues()
test_single_wildcard_weak()
test_multiple_issues_dangerous()
```

### Edge Cases

Tests for unusual but valid inputs:

```python
test_whitespace_handling()
test_case_insensitive()
test_empty_directives_ignored()
test_trailing_semicolon()
test_duplicate_directives_first_wins()
test_very_long_csp()
```

## Coverage Gaps (Areas for Improvement)

### Priority 1: CLI Testing

```python
# Needed tests:
- test_analyze_command_success()
- test_analyze_command_with_timeout()
- test_analyze_command_no_redirect()
- test_analyze_command_verbose()
- test_analyze_invalid_url()
- test_analyze_timeout_error()
- test_analyze_connection_error()
```

### Priority 2: Renderer Testing

```python
# Needed tests:
- test_render_report_basic()
- test_render_report_verbose()
- test_render_with_issues()
- test_render_with_recommendations()
- test_render_score_display()
- test_render_color_coding()
```

### Priority 3: Integration Testing

```python
# Needed tests:
- test_full_analysis_workflow()
- test_redirect_chain_analysis()
- test_https_enforcement_detection()
- test_information_disclosure_detection()
- test_batch_analysis()  # Future feature
```

## Contributing Tests

### Test Requirements

Before submitting:

- [ ] All new code has corresponding tests
- [ ] Tests follow naming conventions
- [ ] Tests include docstrings explaining purpose
- [ ] Edge cases are covered
- [ ] Test coverage maintained or improved
- [ ] All tests pass (`pytest`)
- [ ] Code formatted (`black`)
- [ ] No linting errors (`ruff`)

### Writing Good Tests

**DO:**

```python
def test_specific_behavior(self):
    """Test that X happens when Y condition occurs."""
    # Arrange
    input_data = "test input"

    # Act
    result = function_under_test(input_data)

    # Assert
    assert result.quality == HeaderQuality.EXCELLENT
    assert len(result.issues) == 0
```

**DON'T:**

```python
def test_stuff(self):
    # No docstring
    result = function(input)
    assert result  # Vague assertion
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run tests with coverage
        run: |
          pytest --cov --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

## Test Fixtures

### Available Fixtures (conftest.py)

```python
@pytest.fixture
def sample_headers():
    """Sample HTTP headers for testing."""
    return {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY"
    }

@pytest.fixture
def sample_csp_dangerous():
    """CSP with multiple critical issues."""
    return "default-src 'self'; script-src 'unsafe-inline' *"
```

## Troubleshooting

### Common Issues

**Import Errors**

```bash
# Ensure virtual environment is active
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

**Async Test Failures**

```bash
# Install pytest-asyncio
pip install pytest-asyncio

# Verify pyproject.toml has asyncio_mode = "auto"
```

**Coverage Not Generated**

```bash
# Install pytest-cov
pip install pytest-cov

# Run with explicit source
pytest --cov=sentinel --cov-report=html
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)

---

**Current Status: 154 tests, 75% coverage**

**Goal: 180+ tests, 85%+ coverage** (requires CLI and renderer tests)
