"""Violation detection for code execution guardrails."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_code_guard.constants import (
    DANGEROUS_ATTRIBUTES,
    FORBIDDEN_BUILTINS,
    FORBIDDEN_MODULES,
)


@dataclass
class Violation:
    """Security violation record."""

    violation_type: str  # e.g., "forbidden_import", "timeout", "memory_exceeded"
    severity: str  # "low", "medium", "high", "critical"
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict[str, Any] = field(default_factory=dict)


class ViolationDetector:
    """
    Detects code violations via AST analysis and resource monitoring.

    Usage:
        detector = ViolationDetector()
        violations = detector.analyze_code("import os")
        for v in violations:
            print(f"[{v.severity}] {v.message}")
    """

    def __init__(self) -> None:
        self._violations: list[Violation] = []
        self._resource_limits: dict[str, float] = {
            "cpu": 1.0,
            "memory": 100 * 1024 * 1024,  # 100MB
            "time": 5.0,
        }

    def analyze_code(self, code: str) -> list[Violation]:
        """Analyze code for forbidden operations using AST."""
        violations: list[Violation] = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                # Check imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name.split(".")[0]
                        if module_name in FORBIDDEN_MODULES:
                            violations.append(Violation(
                                violation_type="forbidden_import",
                                severity="critical",
                                message=f"Forbidden import: {alias.name}",
                                context={"module": alias.name},
                            ))

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_name = node.module.split(".")[0]
                        if module_name in FORBIDDEN_MODULES:
                            violations.append(Violation(
                                violation_type="forbidden_import",
                                severity="critical",
                                message=f"Forbidden import from: {node.module}",
                                context={"module": node.module},
                            ))

                # Check function calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in FORBIDDEN_BUILTINS:
                            violations.append(Violation(
                                violation_type="forbidden_builtin",
                                severity="critical",
                                message=f"Forbidden builtin call: {func_name}",
                                context={"function": func_name},
                            ))

                # Check dangerous attribute access
                elif isinstance(node, ast.Attribute):
                    if node.attr in DANGEROUS_ATTRIBUTES:
                        violations.append(Violation(
                            violation_type="dangerous_attribute",
                            severity="high",
                            message=f"Dangerous attribute access: {node.attr}",
                            context={"attribute": node.attr},
                        ))

        except SyntaxError as e:
            violations.append(Violation(
                violation_type="syntax_error",
                severity="medium",
                message=f"Syntax error: {e.msg}",
                context={"line": e.lineno, "offset": e.offset},
            ))

        self._violations.extend(violations)
        return violations

    def check_resource_limits(
        self, cpu_time: float, memory_bytes: int, wall_time: float,
    ) -> list[Violation]:
        """Check if resource usage exceeds limits."""
        violations: list[Violation] = []

        if cpu_time > self._resource_limits["cpu"]:
            violations.append(Violation(
                violation_type="cpu_limit_exceeded",
                severity="high",
                message=(
                    f"CPU time {cpu_time:.2f}s exceeds limit "
                    f"{self._resource_limits['cpu']}s"
                ),
                context={"actual": cpu_time, "limit": self._resource_limits["cpu"]},
            ))

        if memory_bytes > self._resource_limits["memory"]:
            violations.append(Violation(
                violation_type="memory_limit_exceeded",
                severity="high",
                message=f"Memory {memory_bytes} exceeds limit {self._resource_limits['memory']}",
                context={"actual": memory_bytes, "limit": self._resource_limits["memory"]},
            ))

        if wall_time > self._resource_limits["time"]:
            violations.append(Violation(
                violation_type="time_limit_exceeded",
                severity="high",
                message=f"Time {wall_time:.2f}s exceeds limit {self._resource_limits['time']}s",
                context={"actual": wall_time, "limit": self._resource_limits["time"]},
            ))

        self._violations.extend(violations)
        return violations

    def get_violations(self) -> list[Violation]:
        """Get all detected violations."""
        return self._violations.copy()

    def clear(self) -> None:
        """Clear all recorded violations."""
        self._violations.clear()

    def set_limits(self, cpu: float, memory: int, time: float) -> None:
        """Set resource limits for detection."""
        self._resource_limits = {"cpu": cpu, "memory": memory, "time": time}
