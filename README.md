# Agent Code Guard

[![CI](https://github.com/alasong/agent-code-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/alasong/agent-code-guard/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/agent-code-guard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Lightweight code execution guardrails for AI agents. AST analysis, resource limits, audit logging, and violation tracking — **zero dependencies**.

> **Not a security sandbox.** Designed to prevent accidental damage from AI-generated code, not to resist determined attackers.

## Features

| Feature | Description |
|---------|-------------|
| **AST Static Analysis** | Detect forbidden imports, builtins, and dangerous attribute access before execution |
| **Restricted Builtins** | Safe subset of ~35 builtins (math, types, iteration); no `exec`/`eval`/`open` |
| **Resource Limits** | CPU timeout via `SIGALRM`, memory limits via `RLIMIT_AS` |
| **Violation Tracking** | Graded violations (low/medium/high/critical) with context |
| **Audit Trail** | Complete execution log with JSON/CSV/Text export and statistics |
| **Zero Dependencies** | Pure stdlib; `pydantic` optional for result models |

## Installation

```bash
pip install agent-code-guard
```

## Quick Start

```python
from agent_code_guard import CodeGuard

guard = CodeGuard(time_limit=2.0)

# Safe execution
result = guard.execute("result = sum(range(100))", agent_id="agent_1")
print(result.success, result.output)  # True 4950

# Blocked import
result = guard.execute("import os; result = os.getcwd()", agent_id="agent_2")
print(result.blocked, result.error)  # True "Execution blocked: 1 critical violations"

# Audit statistics
stats = guard.get_statistics()
print(stats["audit_stats"]["success_rate"])  # 0.5
```

## Architecture

```
CodeGuard
├── ViolationDetector    # AST pre-execution analysis
│   ├── Forbidden import detection (os, subprocess, socket, ...)
│   ├── Forbidden builtin detection (exec, eval, compile, ...)
│   └── Dangerous attribute detection (__subclasses__, __mro__, ...)
├── CodeGuard Executor   # Restricted execution
│   ├── Safe builtins (~35 allowed functions)
│   ├── CPU timeout (SIGALRM)
│   ├── Memory limit (RLIMIT_AS)
│   └── Thread-safe counting
└── AuditLog             # Execution history
    ├── JSON / CSV / Text export
    ├── Query by agent, action, result
    └── Success/failure statistics
```

## API Reference

### CodeGuard

Main entry point for guarded execution.

```python
guard = CodeGuard(
    cpu_limit=1.0,           # CPU time limit (seconds)
    memory_limit=100*1024*1024,  # Memory limit (bytes)
    time_limit=5.0,          # Wall-clock limit (seconds)
)

result = guard.execute(code, context={"x": 10}, agent_id="my-agent")
```

### ExecutionResult

```python
result.success           # bool
result.output            # value of 'result' or 'output' variable
result.error             # error message if failed
result.blocked           # True if blocked by pre-execution analysis
result.violations        # list of violation messages
result.resource_usage    # ResourceUsage(cpu_time, memory_bytes, wall_time)
```

### ViolationDetector

Standalone AST analysis and resource monitoring.

```python
from agent_code_guard import ViolationDetector

detector = ViolationDetector()
violations = detector.analyze_code("import os; eval('1+1')")
for v in violations:
    print(f"[{v.severity}] {v.violation_type}: {v.message}")
```

### AuditLog

Complete execution history with export capabilities.

```python
log = guard.get_audit_log()

# Query
entries = log.query("agent_1", start_time, end_time)
failures = log.query_by_result("failure")

# Export
print(log.export("json"))
print(log.export("csv"))
print(log.export("text"))

# Statistics
print(log.get_statistics())
# {"total_executions": 10, "successful": 7, "failed": 2, "blocked": 1, ...}
```

## What This Is Not

This is **not** a security sandbox. It cannot prevent:

- Determined code execution escapes (Python's `exec` with crafted bytecodes)
- Side-channel attacks
- Resource exhaustion via C extensions

For production-grade isolation, use Docker containers, seccomp, or gVisor.

## What This Is For

| Scenario | Why |
|----------|-----|
| **AI Agent Code Execution** | Run LLM-generated code with guardrails and full audit trail |
| **Education / Prototyping** | Simple code execution limits for teaching platforms |
| **Plugin Systems** | Isolate unknown plugin code from the host process |

## Competitive Positioning

| | **Agent Code Guard** | E2B Sandbox | RestrictedPython |
|---|:---:|:---:|:---:|
| **Isolation** | Process (soft) | VM/Container (hard) | Syntax rewrite (soft) |
| **Startup** | ~ms | ~seconds | ~ms |
| **Dependencies** | **0** | Cloud SDK | 1 |
| **Audit Log** | **Built-in** | Built-in | None |
| **Local Run** | ✅ | ❌ | ✅ |
| **Security** | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |

See [docs/analysis/竞品比对报告-20260410.md](docs/analysis/竞品比对报告-20260410.md) for the full competitive analysis.

## Development

```bash
git clone https://github.com/alasong/agent-code-guard.git
cd agent-code-guard
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/
```

## License

MIT
