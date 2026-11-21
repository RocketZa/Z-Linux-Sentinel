import subprocess

from sentinel.models import CheckResult, Status, Severity
from sentinel.registry import check

def get_sshd_config() -> dict:
    """Retrieve effective SSH daemon configuration."""

    result = subprocess.run(
        ["sshd", "-T"],
        capture_output=True,
        text=True,
        check=True,
    )

    config = {}

    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)

        if len(parts) == 2:
            key, value = parts
            config[key.lower()] = value.strip().lower()

    return config


def validate_sshd_config() -> tuple[bool, str]:
    """Validate SSH daemon configuration syntax."""

    try:
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            text=True,
            check=True,
        )

        return True, "SSH configuration syntax is valid"

    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip() or "Unknown SSH configuration error"
        return False, error

    except FileNotFoundError:
        return False, "sshd command not found"


def evaluate_root_login(config: dict) -> tuple[Status, str, list[str]]:
    """Evaluate the effective SSH root-login setting."""

    permit_root_login = config.get("permitrootlogin")

    if permit_root_login == "no":
        return (
            Status.PASS,
            "SSH root login is disabled",
            ["permitrootlogin=no"],
        )

    if permit_root_login == "prohibit-password":
        return (
            Status.WARN,
            "SSH root login is restricted to non-password authentication",
            ["permitrootlogin=prohibit-password"],
        )

    if permit_root_login is None:
        return (
            Status.ERROR,
            "permitrootlogin setting not found",
            [],
        )

    return (
        Status.FAIL,
        f"SSH root login is insufficiently restricted: {permit_root_login}",
        [f"permitrootlogin={permit_root_login}"],
    )


def evaluate_password_authentication(
    config: dict,
) -> tuple[Status, str, list[str]]:
    """Evaluate the effective SSH password authentication setting."""

    password_authentication = config.get("passwordauthentication")

    if password_authentication == "no":
        return (
            Status.PASS,
            "SSH password authentication is disabled",
            ["passwordauthentication=no"],
        )

    if password_authentication == "yes":
        return (
            Status.FAIL,
            "SSH password authentication is enabled",
            ["passwordauthentication=yes"],
        )

    return (
        Status.ERROR,
        "passwordauthentication setting not found or invalid",
        [f"passwordauthentication={password_authentication}"],
    )


def evaluate_empty_passwords(
    config: dict,
) -> tuple[Status, str, list[str]]:
    """Evaluate whether SSH permits empty passwords."""

    permit_empty_passwords = config.get("permitemptypasswords")

    if permit_empty_passwords == "no":
        return (
            Status.PASS,
            "SSH empty-password authentication is disabled",
            ["permitemptypasswords=no"],
        )

    if permit_empty_passwords == "yes":
        return (
            Status.FAIL,
            "SSH empty-password authentication is enabled",
            ["permitemptypasswords=yes"],
        )

    return (
        Status.ERROR,
        "permitemptypasswords setting not found or invalid",
        [f"permitemptypasswords={permit_empty_passwords}"],
    )


@check(
    check_id="SSH-01",
    title="SSH root login configuration",
    module="SSH Security",
    severity=Severity.HIGH,
    requires_root=True,
    remediation=(
        "Set PermitRootLogin no in the SSH daemon configuration "
        "and reload the SSH service."
    ),
)
def check_ssh_root_login(cfg=None) -> CheckResult:
    """Audit the effective SSH root-login configuration."""

    config = get_sshd_config()
    status, message, evidence = evaluate_root_login(config)

    return CheckResult(
        check_id="SSH-01",
        title="SSH root login configuration",
        module="SSH Security",
        severity=Severity.HIGH,
        status=status,
        message=message,
        evidence=evidence,
    )

@check(
    check_id="SSH-02",
    title="SSH password authentication",
    module="SSH Security",
    severity=Severity.HIGH,
    requires_root=True,
    remediation=(
        "Set PasswordAuthentication no in the SSH daemon configuration "
        "and reload the SSH service."
    ),
)
def check_ssh_password_authentication(cfg=None):
    config = get_sshd_config()
    status, message, evidence = evaluate_password_authentication(config)

    return CheckResult(
    check_id="SSH-02",
    title="SSH password authentication",
    module="SSH Security",
    severity=Severity.HIGH,
    status=status,
    message=message,
    evidence=evidence,
)


@check(
    check_id="SSH-03",
    title="SSH configuration validation",
    module="SSH Security",
    severity=Severity.HIGH,
    requires_root=True,
    remediation=(
        "Correct SSH configuration errors and set "
        "PermitEmptyPasswords no in the SSH daemon configuration."
    ),
)
def check_ssh_config_validation(cfg=None):
    valid, validation_message = validate_sshd_config()

    if not valid:
        return CheckResult(
            check_id="SSH-03",
            title="SSH configuration validation",
            module="SSH Security",
            severity=Severity.HIGH,
            status=Status.FAIL,
            message="SSH configuration validation failed",
            evidence=[validation_message],
        )

    config = get_sshd_config()
    status, message, evidence = evaluate_empty_passwords(config)

    return CheckResult(
        check_id="SSH-03",
        title="SSH configuration validation",
        module="SSH Security",
        severity=Severity.HIGH,
        status=status,
        message=message,
        evidence=evidence,
    )