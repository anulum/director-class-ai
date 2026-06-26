# Demos

Every demo keeps raw action text out of exported evidence and uses dry-run unless
the command is explicitly permitted and execution is requested.

## Command Checkpoint

```bash
python demos/action_checkpoint.py
```

The script reviews one safe command and one destructive command through the same
command-guard surface shipped as `director-class-guard`. It prints route,
permit, execution, digest, and detector-firing metadata.

## Command-Line Guard

```bash
director-class-guard --surface kubernetes -- kubectl get pods
director-class-guard --surface shell -- rm -rf /
director-class-guard --surface shell --execute -- printf guard-ok
```

The `--execute` form still calls the executor only after the Governor permits the
request.

## Python Middleware

```python
from director_class_ai.sdk import (
    ToolExecutionResult,
    ToolReviewMiddleware,
    ToolReviewRequest,
)


def executor(request: ToolReviewRequest) -> ToolExecutionResult:
    return ToolExecutionResult({"status": "ok"}, exit_code=0)


middleware = ToolReviewMiddleware.default(
    approval_store="runtime/approvals.json",
    audit_log="runtime/audit.jsonl",
    policy_profile="sdk-demo",
    executor=executor,
)
decision = middleware.run(
    ToolReviewRequest(
        "fs.read",
        {"path": "README.md"},
        provenance="user",
        dry_run=False,
    )
)
assert decision.route == "allow"
assert decision.executed is True
```

## MCP Gateway

```bash
director-class-mcp-gateway --host 127.0.0.1 --port 8765
```

Remote bindings fail closed unless an operator key is supplied through an
environment variable. Keep remote deployment behind a reviewed operator runbook.

## SIEM Export

```bash
director-class-siem-export runtime/audit.jsonl -o runtime/siem.jsonl
```

The exporter verifies the hash chain first and writes only the redacted SOC event
schema.
