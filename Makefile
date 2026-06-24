# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — developer task runner
.DEFAULT_GOAL := help
PY ?= python
.PHONY: help test lint fmt types sast spdx docs build bench bench-evidence import-external redteam repository-readiness phase4-intake preflight

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

test: ## Run tests with the 100% coverage gate
	$(PY) -m pytest

lint: ## Check style (ruff check + format --check)
	$(PY) -m ruff check director_class_ai tests benchmarks tools demos
	$(PY) -m ruff format --check director_class_ai tests benchmarks tools demos

fmt: ## Auto-fix style
	$(PY) -m ruff check --fix director_class_ai tests benchmarks tools demos
	$(PY) -m ruff format director_class_ai tests benchmarks tools demos

types: ## Strict type-check
	$(PY) -m mypy --strict director_class_ai

sast: ## SAST scan (bandit + semgrep via uvx)
	$(PY) -m bandit -r director_class_ai -ll
	uvx semgrep scan --config p/python --config p/security-audit director_class_ai

spdx: ## Verify SPDX headers
	$(PY) tools/check_spdx.py

docs: ## Validate public docs, demos, and notebook entry points
	$(PY) tools/check_documentation_surface.py
	$(PY) demos/action_checkpoint.py >/tmp/director-class-action-demo.json

build: ## Build sdist + wheel
	$(PY) -m build --sdist --wheel

bench: ## Run the action-plane benchmark
	$(PY) -m benchmarks.action_plane

bench-evidence: ## Run action benchmark with evidence-grade metadata
	$(PY) -m benchmarks.action_evidence

import-external: ## Import reviewed external JSONL: make import-external SURFACE=... INPUT=...
	@test -n "$(SURFACE)" || (echo "SURFACE is required" && exit 2)
	@test -n "$(INPUT)" || (echo "INPUT is required" && exit 2)
	$(PY) tools/import_external_action_surface.py --surface "$(SURFACE)" --input-jsonl "$(INPUT)"

redteam: ## Run the adversarial red-team benchmark
	$(PY) -m benchmarks.adversarial_red_team

repository-readiness: ## Validate repository-readiness gates (license, Makefile, surface)
	$(PY) tools/check_repository_readiness.py

phase4-intake: ## Validate phase-4 task intake
	$(PY) tools/check_phase4_task_intake.py

preflight: spdx docs lint types test repository-readiness phase4-intake ## Full local gate before commit
	@echo "preflight OK"
