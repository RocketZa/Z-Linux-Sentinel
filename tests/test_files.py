from sentinel.checks.files import scan_directory
import stat
from sentinel.checks.files import scan_privileged_binaries, check_world_writable, privileged_binary_issue, check_privileged_binaries


from sentinel.checks.files import (
    check_critical_file_permissions,
    evaluate_file,
    evaluate_metadata,
    get_file_metadata,
    mode_is_not_looser,
    ownership_matches,
    world_writable_issue,
)
from sentinel.models import Status


# FILE-01: Permission tests

def test_exact_permissions_pass():
    assert mode_is_not_looser(0o640, 0o640)


def test_more_restrictive_permissions_pass():
    assert mode_is_not_looser(0o600, 0o640)


def test_more_permissive_permissions_fail():
    assert not mode_is_not_looser(0o644, 0o640)


# FILE-01: Ownership tests

def test_correct_ownership_passes():
    assert ownership_matches("root", "shadow", "root", "shadow")


def test_incorrect_owner_fails():
    assert not ownership_matches("deeznutz", "shadow", "root", "shadow")


def test_incorrect_group_fails():
    assert not ownership_matches("root", "root", "root", "shadow")


# FILE-01: File metadata tests

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
    path = "/tmp/sentinel-nonexistent-file"

    result = evaluate_file(
        path,
        {
            "mode": 0o640,
            "owner": "root",
            "group": "shadow",
        },
    )

    assert result["passed"] is False
    assert "error" in result
    assert result["path"] == path


def test_file_check_returns_check_result():
    result = check_critical_file_permissions()

    assert result.check_id == "FILE-01"
    assert result.status in (Status.PASS, Status.FAIL)
    assert len(result.evidence) > 0


# FILE-02: World-writable permission tests

def test_normal_file_is_not_flagged():
    assert world_writable_issue(0o644) is None


def test_world_writable_file_is_flagged():
    assert world_writable_issue(0o666) == "World-writable file"


def test_sticky_world_writable_directory_passes():
    mode = stat.S_IFDIR | 0o1777

    assert world_writable_issue(mode) is None


def test_world_writable_directory_without_sticky_bit_fails():
    mode = stat.S_IFDIR | 0o777

    assert world_writable_issue(mode) == (
        "World-writable directory without sticky bit"
    )


def test_scan_directory_finds_world_writable_file(tmp_path):
    test_file = tmp_path / "unsafe.txt"
    test_file.write_text("test")
    test_file.chmod(0o666)

    findings = scan_directory(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["path"] == str(test_file)
    assert findings[0]["issue"] == "World-writable file"



def test_scan_directory_allows_sticky_world_writable_directory(tmp_path):
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    shared_dir.chmod(0o1777)

    findings = scan_directory(str(tmp_path))

    assert not any(
        finding.get("path") == str(shared_dir)
        for finding in findings
    )


def test_scan_directory_flags_world_writable_directory_without_sticky_bit(
    tmp_path,
):
    unsafe_dir = tmp_path / "unsafe"
    unsafe_dir.mkdir()
    unsafe_dir.chmod(0o777)

    findings = scan_directory(str(tmp_path))

    assert any(
        finding.get("path") == str(unsafe_dir)
        and finding.get("issue") == "World-writable directory without sticky bit"
        for finding in findings
    )



def test_scan_directory_does_not_follow_symlinks(tmp_path):
    target_file = tmp_path / "target.txt"
    target_file.write_text("test")
    target_file.chmod(0o666)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()

    symlink = scan_dir / "linked.txt"
    symlink.symlink_to(target_file)

    findings = scan_directory(str(scan_dir))

    assert not any(
        finding.get("path") == str(symlink)
        for finding in findings
    )



def test_scan_directory_records_walk_errors(tmp_path, monkeypatch):
    import sentinel.checks.files as files_module

    def fake_walk(path, **kwargs):
        kwargs["onerror"](PermissionError("Permission denied"))
        return iter([])

    monkeypatch.setattr(files_module.os, "walk", fake_walk)

    findings = scan_directory(str(tmp_path))

    assert len(findings) == 1
    assert "error" in findings[0]
    assert "Permission denied" in findings[0]["error"]



# FILE-02: Registered check tests

def test_world_writable_check_passes(tmp_path):
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("safe")
    clean_file.chmod(0o644)

    result = check_world_writable({
        "scan_paths": [str(tmp_path)],
    })

    assert result.check_id == "FILE-02"
    assert result.status == Status.PASS


def test_world_writable_check_fails(tmp_path):
    unsafe_file = tmp_path / "unsafe.txt"
    unsafe_file.write_text("unsafe")
    unsafe_file.chmod(0o666)

    result = check_world_writable({
        "scan_paths": [str(tmp_path)],
    })

    assert result.check_id == "FILE-02"
    assert result.status == Status.FAIL
    assert any("unsafe.txt" in item for item in result.evidence)


def test_world_writable_check_reports_scan_errors(tmp_path):
    result = check_world_writable({
        "scan_paths": [str(tmp_path / "nonexistent")],
    })

    assert result.check_id == "FILE-02"
    assert result.status == Status.ERROR



def test_world_writable_check_missing_config_returns_error():
    result = check_world_writable()

    assert result.status == Status.ERROR
    assert result.message == "Invalid or missing scan_paths configuration"


def test_world_writable_check_empty_scan_paths_returns_error():
    result = check_world_writable({"scan_paths": []})

    assert result.status == Status.ERROR
    assert result.message == "Invalid or missing scan_paths configuration"

def test_normal_file_is_not_flagged_as_privileged():
    assert privileged_binary_issue("/usr/bin/example", 0o755, []) is None


def test_unapproved_suid_file_is_flagged():
    mode = stat.S_ISUID | 0o755
    assert privileged_binary_issue(
        "/tmp/example", mode, []
    ) == "Unapproved SUID binary"


def test_unapproved_sgid_file_is_flagged():
    mode = stat.S_ISGID | 0o755
    assert privileged_binary_issue(
        "/tmp/example", mode, []
    ) == "Unapproved SGID binary"


def test_unapproved_suid_sgid_file_is_flagged():
    mode = stat.S_ISUID | stat.S_ISGID | 0o755
    assert privileged_binary_issue(
        "/tmp/example", mode, []
    ) == "Unapproved SUID/SGID binary"


def test_approved_privileged_file_is_not_flagged():
    mode = stat.S_ISUID | 0o755
    assert privileged_binary_issue(
        "/usr/bin/sudo", mode, ["/usr/bin/sudo"]
    ) is None


def test_scanner_finds_unapproved_suid_file(tmp_path):
    test_file = tmp_path / "test_suid"
    test_file.write_text("test")
    test_file.chmod(0o4755)

    findings = scan_privileged_binaries(str(tmp_path), [])

    assert len(findings) == 1
    assert findings[0]["path"] == str(test_file)
    assert findings[0]["issue"] == "Unapproved SUID binary"


def test_scanner_ignores_approved_suid_file(tmp_path):
    test_file = tmp_path / "approved_suid"
    test_file.write_text("test")
    test_file.chmod(0o4755)

    findings = scan_privileged_binaries(
        str(tmp_path), [str(test_file)]
    )

    assert findings == []


def test_scanner_finds_unapproved_sgid_file(tmp_path):
    test_file = tmp_path / "test_sgid"
    test_file.write_text("test")
    test_file.chmod(0o2755)

    findings = scan_privileged_binaries(str(tmp_path), [])

    assert len(findings) == 1
    assert findings[0]["issue"] == "Unapproved SGID binary"


def test_scanner_does_not_follow_symlinks(tmp_path):
    target = tmp_path / "target"
    target.write_text("test")
    target.chmod(0o4755)

    link = tmp_path / "link"
    link.symlink_to(target)

    findings = scan_privileged_binaries(str(tmp_path), [])

    assert len(findings) == 1
    assert findings[0]["path"] == str(target)


def test_privileged_binary_check_passes(tmp_path):
    test_file = tmp_path / "normal_file"
    test_file.write_text("safe")
    test_file.chmod(0o755)

    cfg = {
        "scan_paths": [str(tmp_path)],
        "allowed": [],
    }

    result = check_privileged_binaries(cfg)

    assert result.status == Status.PASS
    assert result.check_id == "FILE-03"


def test_privileged_binary_check_fails(tmp_path):
    test_file = tmp_path / "unapproved_suid"
    test_file.write_text("test")
    test_file.chmod(0o4755)

    cfg = {
        "scan_paths": [str(tmp_path)],
        "allowed": [],
    }

    result = check_privileged_binaries(cfg)

    assert result.status == Status.FAIL
    assert result.check_id == "FILE-03"
    assert any("unapproved_suid" in item for item in result.evidence)


def test_privileged_binary_check_reports_invalid_path(tmp_path):
    cfg = {
        "scan_paths": [str(tmp_path / "missing")],
        "allowed": [],
    }

    result = check_privileged_binaries(cfg)

    assert result.status == Status.ERROR


def test_privileged_binary_check_rejects_missing_config():
    result = check_privileged_binaries()

    assert result.status == Status.ERROR
    assert result.message == "Invalid or missing scan_paths configuration"


def test_privileged_binary_check_rejects_invalid_allowlist(tmp_path):
    cfg = {
        "scan_paths": [str(tmp_path)],
        "allowed": "not-a-list",
    }

    result = check_privileged_binaries(cfg)

    assert result.status == Status.ERROR
    assert result.message == "Invalid or missing allowed configuration"