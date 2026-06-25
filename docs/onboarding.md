# Onboarding

Use this guide from a clean checkout on the Samsung ext4 working drive. It keeps
execution dry-run by default and uses only redacted outputs.

## 1. Create an Environment

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

For wheel validation:

```bash
python -m build --sdist --wheel
python -m venv /tmp/director-class-smoke
/tmp/director-class-smoke/bin/pip install target/wheels/*.whl
/tmp/director-class-smoke/bin/python -c "import director_class_ai as d; print(d.__version__)"
```

## 2. Run the First Guard

```bash
director-class-guard --surface shell -- printf ok
director-class-guard --surface shell -- rm -rf /
```

The first command should route to `allow` and remain dry-run. The second command
should not execute; it should route to human approval or block depending on the
signals and provenance.

## 3. Use the Python Middleware

```python
from director_class_ai.sdk import ToolReviewMiddleware, ToolReviewRequest

middleware = ToolReviewMiddleware.default()
decision = middleware.review(
    ToolReviewRequest(
        tool_name="shell.run",
        arguments={"command": "rm -rf /"},
        action="rm -rf /",
        provenance="user",
    )
)
assert decision.executed is False
assert decision.permitted is False
```

## 4. Verify the Repo

```bash
make preflight
```

`make preflight` runs the SPDX, test-quality, boundary-evidence, godfile,
documentation, lint, strict-typing, readiness, and intake gates locally before a
commit. Run focused tests for touched modules locally; GitHub Actions owns the
full test and coverage gate.

## 5. Read the Boundaries

Read [evidence.md](evidence.md) before sharing benchmark numbers. The committed
results are useful local functional evidence; they are not comparative benchmark
claims.
