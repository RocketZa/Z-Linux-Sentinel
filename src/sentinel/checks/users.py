from pathlib import Path

from sentinel.models import Severity, Status
from sentinel.registry import check
import re
def uid0_accounts(passwd_text: str) -> list[str]:
    """Return usernames of all accounts with UID 0."""
    out = []

    for line in passwd_text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue

        parts = line.split(":")

        if len(parts) >= 3 and parts[2] == "0":
            out.append(parts[0])

    return out


def admin_group_members(
    group_text: str,
    target_groups: list[str],
) -> dict[str, list[str]]:
    """Return members of the specified administrative groups."""

    members = {group: [] for group in target_groups}

    for line in group_text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue

        parts = line.split(":")

        if len(parts) != 4:
            continue

        group_name = parts[0]

        if group_name in members:
            group_users = [
                user.strip()
                for user in parts[3].split(",")
                if user.strip()
            ]

            members[group_name].extend(group_users)

    return members


@check(
    "USR-01",
    "Only root has UID 0",
    "users",
    Severity.HIGH,
    remediation="Delete the extra account or give it a normal UID.",
)
def usr_01(cfg):
    extras = [
        user
        for user in uid0_accounts(Path("/etc/passwd").read_text())
        if user != "root"
    ]

    if extras:
        return Status.FAIL, f"{len(extras)} non-root UID-0 account(s)", extras

    return Status.PASS, "Only root has UID 0", []


@check(
    "USR-02",
    "Review administrative group membership",
    "users",
    Severity.HIGH,
    remediation="Remove unapproved users from administrative groups or update the approved-user policy.",
)
def usr_02(cfg):
    if not isinstance(cfg, dict):
        return Status.ERROR, "Missing USR-02 policy configuration", []

    admin_groups = cfg["admin_groups"]
    allowed_members = cfg["allowed_members"]

    try:
        group_text = Path("/etc/group").read_text(encoding="utf-8")
    except PermissionError:
        raise

    memberships = admin_group_members(group_text, admin_groups)

    actual_members = sorted({
        user
        for group_users in memberships.values()
        for user in group_users
    })

    if not allowed_members:
        return (
            Status.WARN,
            "No approved administrative users configured; review membership",
            actual_members,
        )

    unapproved = sorted(set(actual_members) - set(allowed_members))

    if unapproved:
        return (
            Status.FAIL,
            f"{len(unapproved)} unapproved administrative group member(s)",
            unapproved,
        )

    return (
        Status.PASS,
        "All administrative group members are approved",
        actual_members,
    )


def nopasswd_all_rules(sudoers_text: str) -> list[str]:
    """Find active NOPASSWD rules that explicitly grant ALL commands."""

    findings = []
    pending = ""

    for line in sudoers_text.splitlines():
        # Remove comments and surrounding whitespace.
        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        # Join sudoers lines that end with a backslash.
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue

        line = pending + line
        pending = ""

        if re.search(r"\bNOPASSWD\s*:", line):
            # Only inspect commands covered by NOPASSWD.
            commands = re.split(
                r"\bNOPASSWD\s*:",
                line,
                maxsplit=1,
            )[1]

            # A later PASSWD tag ends the NOPASSWD section.
            commands = re.split(
                r"\bPASSWD\s*:",
                commands,
                maxsplit=1,
            )[0]

            if re.search(r"(?:^|,)\s*ALL(?:\s|,|$)", commands):
                findings.append(line)

    if pending:
        # An unfinished continuation is not a complete rule.
        pass

    return findings



@check(
    "USR-03",
    "No unrestricted passwordless sudo rules",
    "users",
    Severity.HIGH,
    requires_root=True,
    remediation="Remove or restrict NOPASSWD: ALL rules in sudoers configuration.",
)
def usr_03(cfg):
    sudoers_path = Path("/etc/sudoers")
    sudoers_dir = Path("/etc/sudoers.d")

    findings = []

    sudoers_text = sudoers_path.read_text(encoding="utf-8")
    findings.extend(nopasswd_all_rules(sudoers_text))

    if sudoers_dir.is_dir():
        for file_path in sudoers_dir.iterdir():
            if not file_path.is_file():
                continue

            if file_path.name.startswith("."):
                continue

            try:
                file_text = file_path.read_text(encoding="utf-8")
            except PermissionError:
                raise

            findings.extend(nopasswd_all_rules(file_text))

    if findings:
        return (
            Status.FAIL,
            f"{len(findings)} unrestricted NOPASSWD rule(s) detected",
            findings,
        )

    return Status.PASS, "No unrestricted NOPASSWD: ALL rules detected", []

