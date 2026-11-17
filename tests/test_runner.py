import sentinel.checks.files
import sentinel.runner as runner_module

from sentinel.runner import run_checks
from sentinel.models import Status


def test_runner_executes_file_02(tmp_path, monkeypatch):
    # Simulate root privileges for this test only.
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    # Create a temporary directory with a clean file.
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("safe")
    clean_file.chmod(0o644)

    # Create a temporary policy.
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        f"""
version: 1
checks:
  FILE-02:
    scan_paths:
      - {tmp_path}
"""
    )

    # Execute checks using the temporary policy.
    results = run_checks(policy_path=policy_file)

    file_02 = next(
        result for result in results
        if result.check_id == "FILE-02"
    )

    assert file_02.status == Status.PASS
    assert file_02.check_id == "FILE-02"


def test_runner_executes_file_03(tmp_path, monkeypatch):
    # Simulate root privileges.
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    # Create a clean temporary file.
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("safe")
    clean_file.chmod(0o755)

    # Create a temporary policy.
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        f"""
version: 1
checks:
  FILE-03:
    scan_paths:
      - {tmp_path}
    allowed: []
"""
    )

    results = run_checks(policy_path=policy_file)

    file_03 = next(
        result for result in results
        if result.check_id == "FILE-03"
    )

    assert file_03.status == Status.PASS
    assert file_03.check_id == "FILE-03"