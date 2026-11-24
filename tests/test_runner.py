import sentinel.checks.files
import sentinel.runner as runner_module
import sentinel.checks.ssh
from sentinel.runner import run_checks
from sentinel.models import Status
import sentinel.checks.network as network_module


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


def test_runner_executes_ssh_01(monkeypatch, tmp_path):
    import sentinel.runner as runner_module
    import sentinel.checks.ssh as ssh_module

    # Simulate root privileges.
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    # Mock effective SSH configuration.
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitrootlogin": "no"},
    )

    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        """
version: 1
checks:
  SSH-01: true
"""
    )

    results = run_checks(policy_path=policy_file)

    ssh_01 = next(
        result for result in results
        if result.check_id == "SSH-01"
    )

    assert ssh_01.status == Status.PASS
    assert ssh_01.check_id == "SSH-01"


def test_runner_executes_ssh_02(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    monkeypatch.setattr(
        "sentinel.checks.ssh.get_sshd_config",
        lambda: {"passwordauthentication": "no"},
    )

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
version: 1
checks:
  SSH-02: true
"""
    )

    results = run_checks(policy_path=policy_file)

    ssh_result = next(
        result for result in results if result.check_id == "SSH-02"
    )

    assert ssh_result.status == Status.PASS



def test_runner_executes_net_01_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    listeners = [
        {
            "protocol": "udp",
            "state": "UNCONN",
            "address": "0.0.0.0",
            "port": 5353,
            "process": "avahi-daemon",
        }
    ]

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        lambda: listeners,
    )

    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        """
version: 1
checks:
  NET-01:
    allowed_listeners:
      - protocol: udp
        address: 0.0.0.0
        port: 5353
"""
    )

    results = run_checks(policy_path=policy_file)

    net_01 = next(
        result for result in results
        if result.check_id == "NET-01"
    )

    assert net_01.status == Status.PASS
    assert net_01.check_id == "NET-01"


def test_runner_executes_net_01_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_module.os, "geteuid", lambda: 0)

    listeners = [
        {
            "protocol": "tcp",
            "state": "LISTEN",
            "address": "192.168.1.10",
            "port": 8080,
            "process": "unknown",
        }
    ]

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        lambda: listeners,
    )

    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(
        """
version: 1
checks:
  NET-01:
    allowed_listeners: []
"""
    )

    results = run_checks(policy_path=policy_file)

    net_01 = next(
        result for result in results
        if result.check_id == "NET-01"
    )

    assert net_01.status == Status.FAIL
    assert net_01.check_id == "NET-01"
