from sentinel.checks.files import mode_is_not_looser, ownership_matches


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