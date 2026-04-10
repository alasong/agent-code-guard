"""Example: Agent code execution guardrails."""

from agent_code_guard import CodeGuard, ViolationDetector


def main():
    print("=== Agent Code Guard Demo ===\n")

    guard = CodeGuard(time_limit=2.0)

    # --- Safe execution ---
    print("1. Safe code execution:")
    result = guard.execute("result = sum(range(100))", agent_id="agent_1")
    print(f"   success={result.success}, output={result.output}")

    # --- Context passing ---
    print("\n2. Execution with context:")
    result = guard.execute(
        "result = x * y + z",
        context={"x": 3, "y": 7, "z": 1},
        agent_id="agent_1",
    )
    print(f"   success={result.success}, output={result.output}")

    # --- Blocked import ---
    print("\n3. Blocked import (os):")
    result = guard.execute("import os; result = os.getcwd()", agent_id="agent_2")
    print(f"   success={result.success}, blocked={result.blocked}")
    print(f"   error: {result.error}")

    # --- Blocked eval ---
    print("\n4. Blocked eval:")
    result = guard.execute("result = eval('1+1')", agent_id="agent_2")
    print(f"   success={result.success}, blocked={result.blocked}")

    # --- Syntax error ---
    print("\n5. Syntax error:")
    result = guard.execute("def foo(", agent_id="agent_3")
    print(f"   success={result.success}, error: {result.error}")

    # --- Timeout ---
    print("\n6. Timeout (0.1s limit):")
    import time as _time
    guard_timeout = CodeGuard(time_limit=0.1)
    result = guard_timeout.execute(
        "sleep(5)",
        context={"sleep": _time.sleep},
        agent_id="agent_4",
    )
    print(f"   success={result.success}, error: {result.error}")

    # --- Audit log ---
    print("\n7. Audit statistics:")
    stats = guard.get_statistics()
    print(f"   Total executions: {stats['total_executions']}")
    print(f"   Success rate: {stats['audit_stats']['success_rate']:.0%}")
    print(f"   Blocked: {stats['audit_stats']['blocked']}")

    # --- Violation detection ---
    print("\n8. Pre-execution analysis:")
    code = (
        "import os\n"
        "x = eval('1+1')\n"
        "result = x\n"
    )
    detector = ViolationDetector()
    violations = detector.analyze_code(code)
    print(f"   Code analyzed: {len(code)} chars")
    print(f"   Violations found: {len(violations)}")
    for v in violations:
        print(f"   [{v.severity}] {v.message}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
