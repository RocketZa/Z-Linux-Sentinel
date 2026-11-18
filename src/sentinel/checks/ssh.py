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