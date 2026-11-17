from sentinel.checks.files import mode_is_not_looser, ownership_matches
from sentinel.checks.files import evaluate_metadata
from sentinel.checks.files import evaluate_file
from sentinel.checks.files import check_critical_file_permissions
from sentinel.models import Status


# Permission tests

def test_exact_permissions_pass():
    assert mode_is_not_looser(0o640, 0o640)


def test_more_restrictive_permissions_pass():
    assert mode_is_not_looser(0o600, 0o640)


def test_more_permissive_permissions_fail():
    assert not mode_is_not_looser(0o644, 0o640)


# Ownership tests

def test_correct_ownership_passes():
    assert ownership_matches("root", "shadow", "root", "shadow")


def test_incorrect_owner_fails():
    assert not ownership_matches("deeznutz", "shadow", "root", "shadow")


def test_incorrect_group_fails():
    assert not ownership_matches("root", "root", "root", "shadow")

from sentinel.checks.files import get_file_metadata


def test_get_shadow_metadata():
    metadata = get_file_metadata("/etc/shadow")

    assert metadata["mode"] == 0o640
    assert metadata["owner"] == "root"
    assert metadata["group"] == "shadow"


def test_get_passwd_metadata():
    metadata = get_file_metadata("/etc/passwd")

    assert metadata["mode"] == 0o644
    assert metadata["owner"] == "root"
    assert metadata["group"] == "root"


def test_correct_metadata_passes():
    actual = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }
    expected = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }

    result = evaluate_metadata(actual, expected)

    assert result["passed"] is True
    assert result["permissions_ok"] is True
    assert result["ownership_ok"] is True


def test_more_restrictive_permissions_pass():
    actual = {
        "mode": 0o600,
        "owner": "root",
        "group": "shadow",
    }
    expected = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }

    result = evaluate_metadata(actual, expected)

    assert result["passed"] is True


def test_incorrect_ownership_fails():
    actual = {
        "mode": 0o640,
        "owner": "root",
        "group": "root",
    }
    expected = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }

    result = evaluate_metadata(actual, expected)

    assert result["passed"] is False
    assert result["permissions_ok"] is True
    assert result["ownership_ok"] is False


def test_more_permissive_permissions_fail():
    actual = {
        "mode": 0o644,
        "owner": "root",
        "group": "shadow",
    }
    expected = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }

    result = evaluate_metadata(actual, expected)

    assert result["passed"] is False
    assert result["permissions_ok"] is False


def test_incorrect_owner_fails():
    actual = {
        "mode": 0o640,
        "owner": "nobody",
        "group": "shadow",
    }
    expected = {
        "mode": 0o640,
        "owner": "root",
        "group": "shadow",
    }

    result = evaluate_metadata(actual, expected)

    assert result["passed"] is False
    assert result["ownership_ok"] is False


def test_missing_file_returns_error():
    result = evaluate_file(
        "/tmp/sentinel-nonexistent-file",
        {
            "mode": 0o640,
            "owner": "root",
            "group": "shadow",
        },
    )

    assert result["passed"] is False
    assert "error" in result
    assert result["path"] == "/tmp/sentinel-nonexistent-file"


def test_file_check_returns_check_result():
    result = check_critical_file_permissions()

    assert result.check_id == "FILE-01"
    assert result.status in (Status.PASS, Status.FAIL)
    assert len(result.evidence) > 0