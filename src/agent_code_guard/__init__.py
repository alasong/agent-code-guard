"""
agent-code-guard: Lightweight code execution guardrails for AI agents.

Features:
- AST static analysis for forbidden imports and operations
- Resource-limited execution with timeout and memory limits
- Violation detection and grading (low/medium/high/critical)
- Complete audit trail with JSON/CSV/Text export

Not a security sandbox — designed as guardrails for AI agent code execution.
Zero external dependencies (pydantic optional for result models).

Example:
    >>> from agent_code_guard import CodeGuard
    >>> guard = CodeGuard(time_limit=2.0)
    >>> result = guard.execute("print('hello')", agent_id="test")
    >>> result.success
    True
"""

from agent_code_guard.analyzer import Violation, ViolationDetector
from agent_code_guard.audit import AuditLog, LogEntry
from agent_code_guard.executor import CodeGuard, ExecutionResult

__version__ = "0.1.0"

__all__ = [
    # Core
    "CodeGuard",
    "ExecutionResult",
    # Analysis
    "ViolationDetector",
    "Violation",
    # Audit
    "AuditLog",
    "LogEntry",
]
