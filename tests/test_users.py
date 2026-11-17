from sentinel.checks.users import admin_group_members
from sentinel.checks.users import uid0_accounts
from sentinel.checks.users import nopasswd_all_rules


def test_detects_uid0_accounts():
    text = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "toor:x:0:0::/root:/bin/bash\n"
        "bob:x:1000:1000::/home/bob:/bin/bash\n"
    )

    assert uid0_accounts(text) == ["root", "toor"]
def test_handles_blank_comments_and_malformed_lines():
    text = (
        "\n"
        "# This is a comment\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "invalid:entry\n"
        "bob:x:1000:1000::/home/bob:/bin/bash\n"
    )

    assert uid0_accounts(text) == ["root"]


def test_extracts_admin_group_members():
    group_text = (
        "sudo:x:27:alice,bob\n"
        "admin:x:1001:charlie\n"
        "users:x:100:alice"
    )

    result = admin_group_members(group_text, ["sudo", "admin"])

    assert result == {
        "sudo": ["alice", "bob"],
        "admin": ["charlie"],
    }


def test_handles_empty_groups_and_malformed_lines():
    group_text = (
        "# Comment\n"
        "sudo:x:27:\n"
        "admin:x:1001:bob\n"
        "malformed:entry\n"
    )

    result = admin_group_members(group_text, ["sudo", "admin"])

    assert result == {
        "sudo": [],
        "admin": ["bob"],
    }


def test_detects_nopasswd_all():
    sudoers_text = (
        "deeznutz ALL=(ALL) NOPASSWD: ALL\n"
    )

    result = nopasswd_all_rules(sudoers_text)

    assert len(result) == 1


def test_ignores_comments_and_specific_commands():
    sudoers_text = (
        "# deeznutz ALL=(ALL) NOPASSWD: ALL\n"
        "alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"
    )

    result = nopasswd_all_rules(sudoers_text)

    assert result == []


def test_detects_all_after_specific_nopasswd_command():
    sudoers_text = (
        "bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl, ALL\n"
    )

    result = nopasswd_all_rules(sudoers_text)

    assert len(result) == 1
