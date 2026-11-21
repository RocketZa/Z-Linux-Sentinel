import os
from sentinel.policy import load_policy
from sentinel.models import CheckResult, Status
from sentinel.registry import REGISTRY


def run_checks(cfg=None, policy_path=None) -> list[CheckResult]:
    results = []
    policy = load_policy(policy_path) if policy_path else load_policy()
    enabled_checks = policy["checks"]

    for check in REGISTRY.values():
        check_config = enabled_checks.get(check.id, False)
        if check_config is False:
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    module=check.module,
                    severity=check.severity,
                    status=Status.SKIP,
                    message="Disabled by policy",
                    remediation=check.remediation,
                )
            )
            continue

        # Skip checks that require root privileges.
        if check.requires_root and os.geteuid() != 0:
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    module=check.module,
                    severity=check.severity,
                    status=Status.SKIP,
                    message="Requires root privileges",
                    remediation=check.remediation,
                )
            )
            continue

        try:
            check_cfg = check_config if isinstance(check_config, dict) else cfg
            result = check.func(check_cfg)

            results.append(result)

        except PermissionError as exc:
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    module=check.module,
                    severity=check.severity,
                    status=Status.ERROR,
                    message=f"Permission error: {exc}",
                    remediation=check.remediation,
                )
            )

        except Exception as exc:
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    module=check.module,
                    severity=check.severity,
                    status=Status.ERROR,
                    message=f"Unexpected error: {exc}",
                    remediation=check.remediation,
                )
            )

    return results


def test_runner_executes_ssh_03(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    monkeypatch.setattr(
        "sentinel.checks.ssh.validate_sshd_config",
        lambda: (True, "SSH configuration syntax is valid"),
    )

    monkeypatch.setattr(
        "sentinel.checks.ssh.get_sshd_config",
        lambda: {"permitemptypasswords": "no"},
    )

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
version: 1
checks:
  SSH-03: true
"""
    )

    results = run_checks(policy_path=policy_file)

    ssh_result = next(
        result for result in results if result.check_id == "SSH-03"
    )

    assert ssh_result.status == Status.PASS