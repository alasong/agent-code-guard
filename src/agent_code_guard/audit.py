"""Audit log for code execution history."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class LogEntry:
    """Audit log entry for code execution."""

    agent_id: str
    action: str
    result: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)
    violations: list[str] = field(default_factory=list)


class AuditLog:
    """
    Audit log for code execution history.

    Features:
    - Execution logging with agent attribution
    - Query by agent, action type, or result
    - Export to JSON, CSV, or text
    - Statistics on success/failure rates

    Usage:
        log = AuditLog()
        log.log_execution("agent_1", "execute_code", "success")
        stats = log.get_statistics()
    """

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: list[LogEntry] = []
        self._max_entries = max_entries

    def log_execution(
        self,
        agent_id: str,
        action: str,
        result: str,
        details: Optional[dict[str, Any]] = None,
        violations: Optional[list[str]] = None,
    ) -> LogEntry:
        """Log a code execution."""
        entry = LogEntry(
            agent_id=agent_id,
            action=action,
            result=result,
            details=details or {},
            violations=violations or [],
        )

        self._entries.append(entry)

        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries:]

        return entry

    def query(
        self,
        agent_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[LogEntry]:
        """Query log entries for a specific agent and time range."""
        return [
            entry for entry in self._entries
            if entry.agent_id == agent_id
            and entry.timestamp >= start_time
            and entry.timestamp <= end_time
        ]

    def query_by_action(self, action: str, limit: int = 100) -> list[LogEntry]:
        """Query log entries by action type."""
        entries = [e for e in self._entries if e.action == action]
        return entries[-limit:]

    def query_by_result(self, result: str, limit: int = 100) -> list[LogEntry]:
        """Query log entries by result status."""
        entries = [e for e in self._entries if e.result == result]
        return entries[-limit:]

    def export(self, format: str = "json") -> str:
        """Export log entries in specified format (json, csv, text)."""
        if format == "json":
            return json.dumps(
                [self._entry_to_dict(e) for e in self._entries],
                default=str,
                indent=2,
            )

        if format == "csv":
            lines = ["agent_id,action,result,timestamp,violations"]
            for entry in self._entries:
                violations_str = ";".join(entry.violations)
                lines.append(
                    f"{entry.agent_id},{entry.action},{entry.result},"
                    f"{entry.timestamp.isoformat()},{violations_str}"
                )
            return "\n".join(lines)

        if format == "text":
            lines = []
            for entry in self._entries:
                lines.append(
                    f"[{entry.timestamp.isoformat()}] "
                    f"Agent={entry.agent_id} "
                    f"Action={entry.action} "
                    f"Result={entry.result}"
                )
                if entry.violations:
                    lines.append(f"  Violations: {', '.join(entry.violations)}")
            return "\n".join(lines)

        raise ValueError(f"Unknown export format: {format}")

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about logged executions."""
        total = len(self._entries)
        successes = sum(1 for e in self._entries if e.result == "success")
        failures = sum(1 for e in self._entries if e.result == "failure")
        timeouts = sum(1 for e in self._entries if e.result == "timeout")
        blocked = sum(1 for e in self._entries if e.result == "blocked")
        violations_total = sum(len(e.violations) for e in self._entries)

        return {
            "total_executions": total,
            "successful": successes,
            "failed": failures,
            "timed_out": timeouts,
            "blocked": blocked,
            "total_violations": violations_total,
            "success_rate": successes / total if total > 0 else 0.0,
        }

    def clear(self) -> None:
        """Clear all log entries."""
        self._entries.clear()

    @staticmethod
    def _entry_to_dict(entry: LogEntry) -> dict[str, Any]:
        return {
            "agent_id": entry.agent_id,
            "action": entry.action,
            "result": entry.result,
            "timestamp": entry.timestamp.isoformat(),
            "details": entry.details,
            "violations": entry.violations,
        }
