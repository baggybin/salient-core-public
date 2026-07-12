# Contributing to salient-core

Thank you for your interest in contributing! This document covers the basics.

## This repo is the upstream source of truth for the kernel

`salient-core` is the kernel; the private `salient` app is a downstream security
*skin* migrating to depend on this package. **Kernel changes land here first** —
including fixes discovered while working in `salient`. Keep the public API stable
(guarded by `tests/test_public_api.py`) and expose new capabilities through the
Protocol contracts in `salient_core/protocols.py` and the runtime `set_*`
registration seams rather than baking a consumer's domain specifics into the
kernel. Since the public release is paused and there are
no external consumers yet, breaking-but-additive kernel changes are cheap now —
prefer landing them before publish.

## Development setup

```bash
git clone https://github.com/baggybin/salient-core.git
cd salient-core
pip install -e ".[dev]"
pre-commit install
```

## Code style

- **Python ≥3.11** — use modern syntax (`Self`, `LiteralString`, exception groups).
- **`ruff check` + `ruff format`** — the formatter runs in CI and pre-commit.
  No manual formatting needed.
- **`mypy`** — the configuration in `pyproject.toml` is the gate (relaxed from
  strict while extracted modules are annotated incrementally); it runs in CI
  and must pass. Type annotations are required for all public APIs; tests are
  exempt.
- **100-char line length** (advisory, enforced by formatter).

## Tests

```bash
pytest tests/ -q                          # fast unit tests
pytest tests/ --cov=salient_core          # with coverage (interim ≥30% gate;
                                          # rising to 80% as the kernel fills out)
```

Every PR must pass the full CI gate: ruff, mypy, pytest with coverage.

## Commit style

Conventional commits preferred: `feat(bus):`, `fix(safeguards):`, `docs:`,
`refactor(scope):`, `test:`. Keep commits atomic; one logical change per
commit.

## Signing

Signed commits (GPG or SSH) are required for all contributions to the public
release.

## DCO

By submitting a pull request, you certify that you have the right to submit
the work under the Apache 2.0 license (Developer Certificate of Origin).
