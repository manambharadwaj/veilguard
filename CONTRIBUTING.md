# Contributing to VeilGuard

Thank you for your interest in improving VeilGuard! This document covers the
development workflow.

## Development Setup

```bash
git clone https://github.com/manambharadwaj/veilguard.git
cd veilguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11 or later.

## Code Style

- **Formatter/linter**: [Ruff](https://docs.astral.sh/ruff/) — config in
  `pyproject.toml`
- **Type checking**: [mypy](https://mypy-lang.org/) with
  `disallow_untyped_defs = true`
- **Line length**: 120 characters
- **Docstrings**: Google style on all public classes and functions
- **Imports**: sorted by `isort` rules via Ruff

Run before committing:

```bash
ruff check src/ tests/
mypy src/
pytest -v
```

## Test Conventions

- Tests live in `tests/` and mirror source module names
  (`test_scan.py` for `scan.py`, etc.)
- Use `tempfile.TemporaryDirectory()` for filesystem isolation
- Use `unittest.mock` for external dependencies (PID files, home dir, etc.)
- Parametrize pattern tests with `@pytest.mark.parametrize`
- All 55 credential patterns must have at least one positive match test

## Adding a Credential Pattern

1. Add the pattern to `CREDENTIAL_PATTERNS` in `src/veilguard/patterns.py`
2. Add a positive-match test case in `tests/test_patterns.py`
3. Add a benchmark sample in `benchmarks/generate_corpus.py`
4. Regenerate the corpus: `python benchmarks/generate_corpus.py`
5. Run the benchmark: `python benchmarks/evaluate.py`

## Pull Request Process

1. Fork the repository and create a feature branch
2. Ensure all checks pass: `ruff check`, `mypy src/`, `pytest -v`
3. Write or update tests for your changes
4. Open a PR against `main` with a clear description
5. One approval required before merge

## Reporting Issues

- **Bugs**: Open a GitHub issue with reproduction steps
- **Security**: See [SECURITY.md](SECURITY.md) — do not use public issues
- **Features**: Open a GitHub issue describing the use case
