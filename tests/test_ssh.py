
import subprocess
import pytest

import sentinel.checks.ssh as ssh_module
from sentinel.checks.ssh import (
    evaluate_root_login,
    evaluate_password_authentication,
    get_sshd_config,
)
from sentinel.models import Status


def test_root_login_disabled_passes():
    config = {"permitrootlogin": "no"}

    status, message, evidence = evaluate_root_login(config)

    assert status == Status.PASS
    assert "disabled" in message
    assert evidence == ["permitrootlogin=no"]


def test_root_login_prohibit_password_warns():
    config = {"permitrootlogin": "prohibit-password"}

    status, message, evidence = evaluate_root_login(config)

    assert status == Status.WARN
    assert "restricted" in message
    assert evidence == ["permitrootlogin=prohibit-password"]


def test_root_login_yes_fails():
    config = {"permitrootlogin": "yes"}

    status, message, evidence = evaluate_root_login(config)

    assert status == Status.FAIL
    assert "insufficiently restricted" in message


def test_root_login_missing_setting_returns_error():
    status, message, evidence = evaluate_root_login({})

    assert status == Status.ERROR
    assert message == "permitrootlogin setting not found"
    assert evidence == []


def test_get_sshd_config_parses_output(monkeypatch):
    mock_result = subprocess.CompletedProcess(
        args=["sshd", "-T"],
        returncode=0,
        stdout=(
            "permitrootlogin no\n"
            "passwordauthentication yes\n"
            "port 22\n"
        ),
        stderr="",
    )

    def mock_run(*args, **kwargs):
        return mock_result

    monkeypatch.setattr(
        "sentinel.checks.ssh.subprocess.run",
        mock_run,
    )

    config = get_sshd_config()

    assert config["permitrootlogin"] == "no"
    assert config["passwordauthentication"] == "yes"
    assert config["port"] == "22"


def test_get_sshd_config_handles_command_failure(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["sshd", "-T"],
            stderr="sshd configuration error",
        )

    monkeypatch.setattr(
        "sentinel.checks.ssh.subprocess.run",
        mock_run,
    )

    with pytest.raises(subprocess.CalledProcessError):
        get_sshd_config()


def test_ssh_root_login_check_passes(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitrootlogin": "no"},
    )

    result = ssh_module.check_ssh_root_login()

    assert result.status == Status.PASS
    assert result.check_id == "SSH-01"


def test_ssh_root_login_check_warns(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitrootlogin": "prohibit-password"},
    )

    result = ssh_module.check_ssh_root_login()

    assert result.status == Status.WARN


def test_ssh_root_login_check_fails(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitrootlogin": "yes"},
    )

    result = ssh_module.check_ssh_root_login()

    assert result.status == Status.FAIL


def test_password_authentication_disabled():
    status, message, evidence = evaluate_password_authentication(
        {"passwordauthentication": "no"}
    )

    assert status == Status.PASS
    assert message == "SSH password authentication is disabled"
    assert evidence == ["passwordauthentication=no"]


def test_password_authentication_enabled():
    status, message, evidence = evaluate_password_authentication(
        {"passwordauthentication": "yes"}
    )

    assert status == Status.FAIL
    assert message == "SSH password authentication is enabled"
    assert evidence == ["passwordauthentication=yes"]


def test_password_authentication_missing():
    status, message, evidence = evaluate_password_authentication({})

    assert status == Status.ERROR
    assert "not found or invalid" in message


def test_ssh_password_authentication_check_passes(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"passwordauthentication": "no"},
    )

    result = ssh_module.check_ssh_password_authentication()

    assert result.status == Status.PASS
    assert result.check_id == "SSH-02"


def test_ssh_password_authentication_check_fails(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"passwordauthentication": "yes"},
    )

    result = ssh_module.check_ssh_password_authentication()

    assert result.status == Status.FAIL
    assert result.check_id == "SSH-02"
