# Sentinel Security Header Analyzer - Development Makefile
# Because automation is the difference between tactical and tedious.

.PHONY: help install install-dev test test-verbose test-coverage lint format type-check clean run docs build all quality

# Default target - show available commands
help:
	@echo "Sentinel Security Analyzer - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install         Install production dependencies"
	@echo "  make install-dev     Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make run URL=<url>   Run analyzer on specified URL"
	@echo "  make run-verbose     Run with verbose output"
	@echo ""
	@echo "Testing:"
	@echo "  make test            Run test suite"
	@echo "  make test-verbose    Run tests with verbose output"
	@echo "  make test-coverage   Run tests with coverage report"
	@echo "  make test-watch      Run tests in watch mode"
	@echo ""
	@echo "Code Quality:"
	@echo "  make format          Format code with black"
	@echo "  make lint            Run ruff linter"
	@echo "  make type-check      Run mypy type checker"
	@echo "  make quality         Run all quality checks"
	@echo "  make all             Format, lint, type-check, and test"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean           Remove generated files"
	@echo "  make docs            Build documentation"
	@echo "  make build           Build distribution packages"
	@echo ""

# Installation targets
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# Development targets
run:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL not specified. Usage: make run URL=example.com"; \
		exit 1; \
	fi
	python cli.py analyze $(URL)

run-verbose:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL not specified. Usage: make run-verbose URL=example.com"; \
		exit 1; \
	fi
	python cli.py analyze $(URL) --verbose

# Testing targets
test:
	pytest

test-verbose:
	pytest -v

test-coverage:
	pytest --cov --cov-report=term-missing --cov-report=html

test-watch:
	pytest-watch

# Code quality targets
format:
	@echo "Formatting code with black..."
	black .
	@echo "✓ Code formatted"

lint:
	@echo "Running ruff linter..."
	ruff check .
	@echo "✓ Linting complete"

type-check:
	@echo "Running mypy type checker..."
	mypy .
	@echo "✓ Type checking complete"

# Combined quality check
quality: format lint type-check
	@echo ""
	@echo "========================================="
	@echo "All quality checks passed! ✓"
	@echo "========================================="

# Run everything
all: quality test
	@echo ""
	@echo "========================================="
	@echo "All checks passed! Ready for deployment."
	@echo "========================================="

# Cleanup targets
clean:
	@echo "Cleaning generated files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleanup complete"

# Documentation
docs:
	@echo "Building documentation..."
	mkdocs build
	@echo "✓ Documentation built in site/"

# Build distribution
build: clean
	@echo "Building distribution packages..."
	python -m build
	@echo "✓ Distribution packages created in dist/"

# Development workflow shortcuts
check: quality test
	@echo "Pre-commit checks passed ✓"

# Quick security test on common sites
test-real:
	@echo "Testing real sites (this takes ~30 seconds)..."
	@python cli.py analyze github.com
	@echo ""
	@python cli.py analyze google.com
	@echo ""
	@python cli.py analyze cloudflare.com

# CI/CD helper
ci: install-dev quality test
	@echo "CI checks complete ✓"