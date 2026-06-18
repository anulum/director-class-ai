# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — developer task runner
.DEFAULT_GOAL := help
PY ?= python

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

test: ## Run tests with the 100% coverage gate
	$(PY) -m pytest

lint: ## Check style (ruff check + format --check)
	$(PY) -m ruff check director_class_ai tests benchmarks tools
	$(PY) -m ruff format --check director_class_ai tests benchmarks tools

fmt: ## Auto-fix style
	$(PY) -m ruff check --fix director_class_ai tests benchmarks tools
	$(PY) -m ruff format director_class_ai tests benchmarks tools

types: ## Strict type-check
	$(PY) -m mypy --strict director_class_ai

sast: ## SAST scan (bandit + semgrep via uvx)
	$(PY) -m bandit -r director_class_ai -ll
	uvx semgrep scan --config p/python --config p/security-audit director_class_ai

spdx: ## Verify SPDX headers
	$(PY) tools/check_spdx.py

build: ## Build sdist + wheel
	$(PY) -m build --sdist --wheel

bench: ## Run the action-plane benchmark
	$(PY) -m benchmarks.action_plane

bench-evidence: ## Run action benchmark with evidence-grade metadata
	$(PY) -m benchmarks.action_evidence

redteam: ## Run the adversarial red-team benchmark
	$(PY) -m benchmarks.adversarial_red_team

preflight: spdx lint types test ## Full local gate before commit
	@echo "preflight OK"
