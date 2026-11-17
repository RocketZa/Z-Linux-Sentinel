import os
import stat
import pwd
import grp

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

def evaluate_file(path: str, expected: dict) -> dict:
    """Compare a file's actual metadata against its expected baseline."""
    actual = get_file_metadata(path)

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
        "path": path,
        "actual": actual,
        "expected": expected,
        "permissions_ok": permissions_ok,
        "ownership_ok": ownership_ok,
        "passed": permissions_ok and ownership_ok,
    }