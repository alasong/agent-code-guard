"""Code execution with resource limits and violation detection."""

from __future__ import annotations

import builtins
import resource
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from agent_code_guard.analyzer import Violation, ViolationDetector
from agent_code_guard.audit import AuditLog
from agent_code_guard.constants import FORBIDDEN_BUILTINS, SAFE_BUILTINS


class TimeoutException(Exception):
    """Raised when execution times out."""
    pass


class MemoryLimitException(Exception):
    """Raised when memory limit is exceeded."""
    pass


@dataclass
class ResourceUsage:
    """Resource usage metrics for guarded execution."""

    cpu_time: float = 0.0
    memory_bytes: int = 0
    wall_time: float = 0.0


@dataclass
class ExecutionResult:
    """Result of guarded code execution."""

    success: bool
    output: Any = None
    error: Optional[str] = None
    resource_usage: ResourceUsage = field(default_factory=ResourceUsage)
    violations: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    blocked: bool = False


class CodeGuard:
    """
    Lightweight code execution guardrail for AI agents.

    Features:
    - AST static analysis before execution
    - Restricted builtins (no exec, eval, open, etc.)
    - Timeout enforcement via SIGALRM
    - Memory limit enforcement via RLIMIT_AS
    - Complete audit trail

    Not a security sandbox — designed to prevent accidental damage
    from AI-generated code, not malicious attacks.

    Usage:
        guard = CodeGuard(time_limit=2.0, memory_limit=50 * 1024 * 1024)
        result = guard.execute("x = 1 + 2; result = x", agent_id="agent_1")
        print(result.success, result.output)
    """

    def __init__(
        self,
        cpu_limit: float = 1.0,
        memory_limit: int = 100 * 1024 * 1024,
        time_limit: float = 5.0,
    ) -> None:
        self._cpu_limit = cpu_limit
        self._memory_limit = memory_limit
        self._time_limit = time_limit
        self._detector = ViolationDetector()
        self._audit = AuditLog()
        self._execution_count = 0
        self._lock = threading.Lock()

        self._detector.set_limits(cpu_limit, memory_limit, time_limit)

    def execute(
        self,
        code: str,
        context: Optional[dict[str, Any]] = None,
        agent_id: str = "unknown",
    ) -> ExecutionResult:
        """Execute code with guardrails."""
        start_time = datetime.now(timezone.utc)
        violations: list[str] = []
        usage = ResourceUsage()

        self._detector.clear()

        # Pre-execution analysis
        pre_violations = self._detector.analyze_code(code)
        if pre_violations:
            violations.extend([v.message for v in pre_violations])
            critical = [v for v in pre_violations if v.severity == "critical"]
            if critical:
                self._audit.log_execution(
                    agent_id=agent_id,
                    action="execute_blocked",
                    result="blocked",
                    details={"code_length": len(code)},
                    violations=violations,
                )
                return ExecutionResult(
                    success=False,
                    error=f"Execution blocked: {len(critical)} critical violations",
                    violations=violations,
                    resource_usage=usage,
                    blocked=True,
                )

        # Prepare safe execution context
        safe_builtins = self._create_safe_builtins()
        safe_globals = {"__builtins__": safe_builtins}

        if context:
            for key, value in context.items():
                if key not in FORBIDDEN_BUILTINS and not key.startswith("_"):
                    safe_globals[key] = value

        output = None
        error = None
        success = False

        try:
            with self._resource_context():
                compiled = compile(code, "<agent-code-guard>", "exec")
                exec_locals: dict[str, Any] = {}
                exec(compiled, safe_globals, exec_locals)
                output = exec_locals.get("result", exec_locals.get("output"))
                success = True

        except TimeoutException:
            error = f"Execution timed out after {self._time_limit}s"
            violations.append(error)

        except MemoryLimitException:
            error = f"Memory limit exceeded ({self._memory_limit} bytes)"
            violations.append(error)

        except SyntaxError as e:
            error = f"Syntax error: {e.msg} at line {e.lineno}"
            violations.append(error)

        except Exception as e:
            error = f"Execution error: {type(e).__name__}: {e}"
            violations.append(error)

        end_time = datetime.now(timezone.utc)
        usage.wall_time = (end_time - start_time).total_seconds()
        usage.cpu_time = usage.wall_time

        resource_violations = self._detector.check_resource_limits(
            usage.cpu_time, usage.memory_bytes, usage.wall_time,
        )
        violations.extend([v.message for v in resource_violations])

        result_status = "success" if success else "failure"
        self._audit.log_execution(
            agent_id=agent_id,
            action="execute_code",
            result=result_status,
            details={"code_length": len(code), "wall_time": usage.wall_time},
            violations=violations,
        )

        with self._lock:
            self._execution_count += 1

        return ExecutionResult(
            success=success,
            output=output,
            error=error,
            resource_usage=usage,
            violations=violations,
            execution_time=usage.wall_time,
        )

    def set_resource_limits(self, cpu: float, memory: int, time: float) -> None:
        """Set resource limits."""
        self._cpu_limit = cpu
        self._memory_limit = memory
        self._time_limit = time
        self._detector.set_limits(cpu, memory, time)

    def check_violations(self) -> list[Violation]:
        """Get detected violations."""
        return self._detector.get_violations()

    def reset(self) -> None:
        """Reset violations and counters. Audit log is preserved."""
        self._detector.clear()

    def get_audit_log(self) -> AuditLog:
        """Get the audit log instance."""
        return self._audit

    def get_statistics(self) -> dict[str, Any]:
        """Get execution statistics."""
        log_stats = self._audit.get_statistics()
        return {
            "total_executions": self._execution_count,
            "audit_stats": log_stats,
            "current_limits": {
                "cpu": self._cpu_limit,
                "memory": self._memory_limit,
                "time": self._time_limit,
            },
        }

    @contextmanager
    def _resource_context(self):
        """Context manager for resource limits (Unix only)."""
        old_handler = None

        def timeout_handler(signum, frame):
            raise TimeoutException(f"Execution timed out after {self._time_limit}s")

        try:
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, self._time_limit)

            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            try:
                resource.setrlimit(resource.RLIMIT_AS, (self._memory_limit, hard))
            except (ValueError, resource.error):
                pass

            yield

        finally:
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
            signal.setitimer(signal.ITIMER_REAL, 0)

            try:
                resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
            except (ValueError, resource.error):
                pass

    @staticmethod
    def _create_safe_builtins() -> dict[str, Any]:
        """Create a safe builtins dictionary."""
        safe = {}
        for name in SAFE_BUILTINS:
            if hasattr(builtins, name):
                safe[name] = getattr(builtins, name)
        return safe
