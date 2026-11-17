import json
from dataclasses import asdict
from pathlib import Path

from sentinel.models import CheckResult


def print_terminal(results: list[CheckResult]) -> None:
    print("\n========== SENTINEL LINUX AUDIT ==========\n")

    for result in results:
        print(f"[{result.status.value}] {result.check_id} - {result.title}")
        print(f"  Severity: {result.severity.value}")
        print(f"  Message: {result.message}")

        if result.evidence:
            print(f"  Evidence: {', '.join(result.evidence)}")

        if result.remediation:
            print(f"  Remediation: {result.remediation}")

        print()

    total = len(results)
    passed = sum(r.status.value == "PASS" for r in results)
    failed = sum(r.status.value == "FAIL" for r in results)
    skipped = sum(r.status.value == "SKIP" for r in results)
    errors = sum(r.status.value == "ERROR" for r in results)

    print("--------------- SUMMARY ----------------")
    print(f"Total checks: {total}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")
    print(f"Skipped:      {skipped}")
    print(f"Errors:       {errors}")
    print("=========================================\n")

def write_json(results: list[CheckResult], output_path: str) -> None:
    data = [asdict(result) for result in results]

    Path(output_path).write_text(
        json.dumps(data, indent=4),
        encoding="utf-8",
    )