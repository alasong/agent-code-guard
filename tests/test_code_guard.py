"""Tests for agent-code-guard."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_code_guard import (
    AuditLog,
    CodeGuard,
    ExecutionResult,
    ViolationDetector,
)

# --- ViolationDetector ---


class TestViolationDetector:
    def test_forbidden_import(self):
        detector = ViolationDetector()
        violations = detector.analyze_code("import os")
        assert len(violations) == 1
        assert violations[0].severity == "critical"
        assert "os" in violations[0].message

    def test_forbidden_builtin(self):
        detector = ViolationDetector()
        violations = detector.analyze_code("eval('1+1')")
        assert len(violations) == 1
        assert violations[0].violation_type == "forbidden_builtin"

    def test_dangerous_attribute(self):
        detector = ViolationDetector()
        violations = detector.analyze_code("().__class__.__bases__")
        assert any(v.violation_type == "dangerous_attribute" for v in violations)

    def test_safe_code(self):
        detector = ViolationDetector()
        violations = detector.analyze_code("x = 1 + 2; result = x")
        assert len(violations) == 0

    def test_syntax_error(self):
        detector = ViolationDetector()
        violations = detector.analyze_code("def foo(")
        assert any(v.violation_type == "syntax_error" for v in violations)

    def test_resource_limits(self):
        detector = ViolationDetector()
        detector.set_limits(cpu=1.0, memory=1024, time=1.0)
        violations = detector.check_resource_limits(
            cpu_time=2.0, memory_bytes=2048, wall_time=0.5,
        )
        assert len(violations) == 2  # cpu + memory exceeded
        assert not any(v.violation_type == "time_limit_exceeded" for v in violations)

    def test_clear(self):
        detector = ViolationDetector()
        detector.analyze_code("import os")
        assert len(detector.get_violations()) == 1
        detector.clear()
        assert len(detector.get_violations()) == 0


# --- AuditLog ---


class TestAuditLog:
    def test_log_and_query(self):
        log = AuditLog()
        log.log_execution("agent_1", "execute_code", "success")
        log.log_execution("agent_2", "execute_code", "failure")

        assert log.get_statistics()["total_executions"] == 2
        assert log.get_statistics()["successful"] == 1

    def test_query_by_agent(self):
        log = AuditLog()
        log.log_execution("agent_1", "run", "success")
        log.log_execution("agent_2", "run", "success")

        now = datetime.now(timezone.utc)
        results = log.query("agent_1", now - timedelta(hours=1), now + timedelta(hours=1))
        assert len(results) == 1
        assert results[0].agent_id == "agent_1"

    def test_export_json(self):
        log = AuditLog()
        log.log_execution("a1", "test", "ok", details={"key": "val"})
        data = json.loads(log.export("json"))
        assert len(data) == 1
        assert data[0]["agent_id"] == "a1"

    def test_export_csv(self):
        log = AuditLog()
        log.log_execution("a1", "test", "ok")
        csv_text = log.export("csv")
        assert "a1,test,ok" in csv_text

    def test_export_text(self):
        log = AuditLog()
        log.log_execution("a1", "test", "ok", violations=["v1"])
        text = log.export("text")
        assert "a1" in text
        assert "v1" in text

    def test_export_invalid_format(self):
        log = AuditLog()
        with pytest.raises(ValueError):
            log.export("xml")

    def test_max_entries(self):
        log = AuditLog(max_entries=3)
        for i in range(5):
            log.log_execution("a1", "test", "ok")
        assert len(log._entries) == 3

    def test_clear(self):
        log = AuditLog()
        log.log_execution("a1", "test", "ok")
        log.clear()
        assert log.get_statistics()["total_executions"] == 0


# --- CodeGuard ---


class TestCodeGuard:
    def test_simple_execution(self):
        guard = CodeGuard()
        result = guard.execute("result = 1 + 2", agent_id="test")
        assert result.success
        assert result.output == 3
        assert not result.blocked

    def test_blocked_import(self):
        guard = CodeGuard()
        result = guard.execute("import os; result = 'hacked'", agent_id="test")
        assert not result.success
        assert result.blocked
        assert "blocked" in result.error

    def test_blocked_eval(self):
        guard = CodeGuard()
        result = guard.execute("result = eval('1+1')", agent_id="test")
        assert not result.success
        assert result.blocked

    def test_safe_context(self):
        guard = CodeGuard()
        result = guard.execute(
            "result = x * 2",
            context={"x": 10},
            agent_id="test",
        )
        assert result.success
        assert result.output == 20

    def test_blocked_context_key(self):
        guard = CodeGuard()
        result = guard.execute(
            "result = 1",
            context={"__import__": lambda x: None},
            agent_id="test",
        )
        # Should still succeed but __import__ is not injected
        assert result.success

    def test_timeout(self):
        import time as stdlib_time
        guard = CodeGuard(time_limit=0.1)
        result = guard.execute(
            "sleep(5)",
            context={"sleep": stdlib_time.sleep},
            agent_id="test",
        )
        assert not result.success
        assert "timed out" in result.error

    def test_syntax_error(self):
        guard = CodeGuard()
        result = guard.execute("def foo(", agent_id="test")
        assert not result.success
        assert "Syntax error" in result.error

    def test_runtime_error(self):
        guard = CodeGuard()
        result = guard.execute("x = 1 / 0", agent_id="test")
        assert not result.success
        assert "ZeroDivisionError" in result.error

    def test_safe_builtins(self):
        guard = CodeGuard()
        # Verify safe builtins work
        result = guard.execute("result = len([1, 2, 3])", agent_id="test")
        assert result.success
        assert result.output == 3

    def test_safe_iteration(self):
        guard = CodeGuard()
        result = guard.execute(
            "result = sum(range(10))",
            agent_id="test",
        )
        assert result.success
        assert result.output == 45

    def test_statistics(self):
        guard = CodeGuard()
        guard.execute("result = 1", agent_id="a1")
        guard.execute("import os", agent_id="a1")
        stats = guard.get_statistics()
        assert stats["total_executions"] == 1  # blocked executions don't count
        assert stats["audit_stats"]["successful"] == 1
        assert stats["audit_stats"]["blocked"] == 1

    def test_resource_limits_update(self):
        guard = CodeGuard()
        guard.set_resource_limits(cpu=2.0, memory=200 * 1024 * 1024, time=10.0)
        limits = guard.get_statistics()["current_limits"]
        assert limits["cpu"] == 2.0
        assert limits["time"] == 10.0

    def test_reset(self):
        guard = CodeGuard()
        guard.execute("import os", agent_id="test")
        guard.check_violations()
        guard.reset()
        assert len(guard.check_violations()) == 0

    def test_audit_log_access(self):
        guard = CodeGuard()
        log = guard.get_audit_log()
        assert isinstance(log, AuditLog)

    def test_execution_result_fields(self):
        guard = CodeGuard()
        result = guard.execute("result = 42", agent_id="test")
        assert isinstance(result, ExecutionResult)
        assert result.execution_time >= 0
        assert isinstance(result.resource_usage.cpu_time, float)
