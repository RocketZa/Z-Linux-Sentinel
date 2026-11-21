
import subprocess
import pytest

import sentinel.checks.ssh as ssh_module
from sentinel.checks.ssh import (
    evaluate_root_login,
    evaluate_password_authentication,
    get_sshd_config,
    validate_sshd_config,
    evaluate_empty_passwords
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

def test_validate_sshd_config_success(monkeypatch):
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=["sshd", "-t"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "sentinel.checks.ssh.subprocess.run",
        mock_run,
    )

    valid, message = validate_sshd_config()

    assert valid is True
    assert message == "SSH configuration syntax is valid"


def test_validate_sshd_config_failure(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["sshd", "-t"],
            stderr="Bad configuration option",
        )

    monkeypatch.setattr(
        "sentinel.checks.ssh.subprocess.run",
        mock_run,
    )

    valid, message = validate_sshd_config()

    assert valid is False
    assert message == "Bad configuration option"


def test_validate_sshd_config_command_missing(monkeypatch):
    def mock_run(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        "sentinel.checks.ssh.subprocess.run",
        mock_run,
    )

    valid, message = validate_sshd_config()

    assert valid is False
    assert message == "sshd command not found"


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

def test_empty_passwords_disabled():
    status, message, evidence = evaluate_empty_passwords(
        {"permitemptypasswords": "no"}
    )

    assert status == Status.PASS
    assert message == "SSH empty-password authentication is disabled"
    assert evidence == ["permitemptypasswords=no"]


def test_empty_passwords_enabled():
    status, message, evidence = evaluate_empty_passwords(
        {"permitemptypasswords": "yes"}
    )

    assert status == Status.FAIL
    assert message == "SSH empty-password authentication is enabled"
    assert evidence == ["permitemptypasswords=yes"]


def test_empty_passwords_missing():
    status, message, evidence = evaluate_empty_passwords({})

    assert status == Status.ERROR
    assert "not found or invalid" in message


def test_ssh_config_validation_passes(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "validate_sshd_config",
        lambda: (True, "SSH configuration syntax is valid"),
    )

    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitemptypasswords": "no"},
    )

    result = ssh_module.check_ssh_config_validation()

    assert result.status == Status.PASS
    assert result.check_id == "SSH-03"


def test_ssh_config_validation_fails_on_invalid_config(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "validate_sshd_config",
        lambda: (False, "Bad configuration option"),
    )

    result = ssh_module.check_ssh_config_validation()

    assert result.status == Status.FAIL
    assert result.evidence == ["Bad configuration option"]


def test_ssh_config_validation_fails_on_empty_passwords(monkeypatch):
    monkeypatch.setattr(
        ssh_module,
        "validate_sshd_config",
        lambda: (True, "SSH configuration syntax is valid"),
    )

    monkeypatch.setattr(
        ssh_module,
        "get_sshd_config",
        lambda: {"permitemptypasswords": "yes"},
    )

    result = ssh_module.check_ssh_config_validation()

    assert result.status == Status.FAIL
    assert result.check_id == "SSH-03"