
import os
import stat
import pwd
import grp

from sentinel.models import CheckResult, Status, Severity
from sentinel.registry import check


FILE_BASELINE = {
    "/etc/passwd": {
        "mode": 0o644,
        "owner": "root",
        "group": "root",
    },
    "/etc/group": {
        "mode": 0o644,
        "owner": "root",
        "group": "root",
    },
    "/etc/shadow": {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    },
    "/etc/gshadow": {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    },
    "/etc/sudoers": {
        "mode": 0o440,
        "owner": "root",
        "group": "root",
    },
}


def mode_is_not_looser(actual_mode: int, expected_mode: int) -> bool:
    """Return True if actual permissions are no more permissive than expected."""
    return (actual_mode & ~expected_mode) == 0


def ownership_matches(
    actual_owner: str,
    actual_group: str,
    expected_owner: str,
    expected_group: str,
) -> bool:
    """Return True if actual owner and group match the expected values."""
    return (
        actual_owner == expected_owner
        and actual_group == expected_group
    )


def get_file_metadata(path: str) -> dict:
    """Return the permissions, owner, and group of a file."""
    file_stat = os.stat(path)

    return {
        "mode": stat.S_IMODE(file_stat.st_mode),
        "owner": pwd.getpwuid(file_stat.st_uid).pw_name,
        "group": grp.getgrgid(file_stat.st_gid).gr_name,
    }


def evaluate_metadata(actual: dict, expected: dict) -> dict:
    """Compare supplied file metadata against its expected baseline."""
    permissions_ok = mode_is_not_looser(
        actual["mode"], expected["mode"]
    )

    ownership_ok = ownership_matches(
        actual["owner"],
        actual["group"],
        expected["owner"],
        expected["group"],
    )

    return {
        "actual": actual,
        "expected": expected,
        "permissions_ok": permissions_ok,
        "ownership_ok": ownership_ok,
        "passed": permissions_ok and ownership_ok,
    }


def evaluate_file(path: str, expected: dict) -> dict:
    """Read a file's metadata and evaluate it against its baseline."""
    try:
        actual = get_file_metadata(path)
    except (FileNotFoundError, PermissionError) as exc:
        return {
            "path": path,
            "error": str(exc),
            "passed": False,
        }

    result = evaluate_metadata(actual, expected)

    return {
        "path": path,
        **result,
    }


@check(
    check_id="FILE-01",
    title="Critical system file permissions and ownership",
    module="File Security",
    severity=Severity.HIGH,
    requires_root=True,
    remediation=(
        "Review the listed files and restore their expected "
        "ownership and permissions."
    ),
)
def check_critical_file_permissions(cfg=None) -> CheckResult:
    """Audit permissions and ownership of critical system files."""

    evidence = []
    failures = []

    for path, expected in FILE_BASELINE.items():
        result = evaluate_file(path, expected)

        if "error" in result:
            failures.append(path)
            evidence.append(
                f"{path}: Unable to inspect file: {result['error']}"
            )
            continue

        actual = result["actual"]

        evidence.append(
            f"{path}: mode={oct(actual['mode'])}, "
            f"owner={actual['owner']}, group={actual['group']}"
        )

        if not result["permissions_ok"]:
            failures.append(path)
            evidence.append(
                f"{path}: Permissions are more permissive than expected "
                f"({oct(actual['mode'])}; expected no more permissive than "
                f"{oct(expected['mode'])})"
            )

        if not result["ownership_ok"]:
            failures.append(path)
            evidence.append(
                f"{path}: Ownership mismatch "
                f"(actual {actual['owner']}:{actual['group']}; "
                f"expected {expected['owner']}:{expected['group']})"
            )

    if failures:
        return CheckResult(
            check_id="FILE-01",
            title="Critical system file permissions and ownership",
            module="File Security",
            severity=Severity.HIGH,
            status=Status.FAIL,
            message=(
                f"Found security issues in "
                f"{len(set(failures))} critical file(s)"
            ),
            evidence=evidence,
        )

    return CheckResult(
        check_id="FILE-01",
        title="Critical system file permissions and ownership",
        module="File Security",
        severity=Severity.HIGH,
        status=Status.PASS,
        message=(
            "All critical system files meet the expected "
            "permissions and ownership baseline"
        ),
        evidence=evidence,
    )
