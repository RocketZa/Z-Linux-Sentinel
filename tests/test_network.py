
import pytest
import subprocess
import sentinel.checks.network as network_module
from sentinel.checks.network import is_non_loopback_address
from sentinel.checks.network import parse_ss_output


@pytest.mark.parametrize(
    "address, expected",
    [
        ("127.0.0.1", False),
        ("127.0.0.53", False),
        ("127.0.0.53%lo", False),
        ("::1", False),
        ("0.0.0.0", True),
        ("::", True),
        ("192.168.1.10", True),
        ("10.0.0.5", True),
    ],
)
def test_is_non_loopback_address(address, expected):
    assert is_non_loopback_address(address) is expected


def test_parse_ss_output():
    output = (
        "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
        "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n"
        "tcp LISTEN 0 511 [::1]:631 [::]:*\n"
        "tcp ESTAB 0 0 127.0.0.1:5000 127.0.0.1:6000\n"
    )

    listeners = parse_ss_output(output)

    assert len(listeners) == 3

    assert listeners[0] == {
        "protocol": "udp",
        "state": "UNCONN",
        "address": "0.0.0.0",
        "port": 5353,
        "process": None,
    }

    assert listeners[1]["protocol"] == "tcp"
    assert listeners[1]["address"] == "127.0.0.1"
    assert listeners[1]["port"] == 631

    assert listeners[2]["address"] == "::1"
    assert listeners[2]["port"] == 631


def test_parse_ss_output_extracts_process():
    output = (
        'tcp LISTEN 0 511 127.0.0.1:42693 '
        '0.0.0.0:* users:(("code",pid=7296,fd=42))\n'
    )

    listeners = parse_ss_output(output)

    assert len(listeners) == 1
    assert listeners[0]["process"] == 'users:(("code",pid=7296,fd=42))'


def test_get_listening_sockets(monkeypatch):
    mock_result = subprocess.CompletedProcess(
        args=["ss", "-tulnpH"],
        returncode=0,
        stdout=(
            "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
            "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n"
        ),
        stderr="",
    )

    def mock_run(*args, **kwargs):
        return mock_result

    monkeypatch.setattr(
        network_module.subprocess,
        "run",
        mock_run,
    )

    listeners = network_module.get_listening_sockets()

    assert len(listeners) == 2
    assert listeners[0]["port"] == 5353
    assert listeners[1]["port"] == 631


def test_get_listening_sockets_command_failure(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["ss", "-tulnpH"],
            stderr="Operation not permitted",
        )

    monkeypatch.setattr(
        network_module.subprocess,
        "run",
        mock_run,
    )

    with pytest.raises(subprocess.CalledProcessError):
        network_module.get_listening_sockets()


def test_find_unapproved_listeners():
    listeners = [
        {"protocol": "udp", "address": "0.0.0.0", "port": 5353},
        {"protocol": "tcp", "address": "192.168.1.10", "port": 8080},
        {"protocol": "tcp", "address": "127.0.0.1", "port": 631},
    ]

    allowed = [
        {"protocol": "udp", "address": "0.0.0.0", "port": 5353},
    ]

    result = network_module.find_unapproved_listeners(listeners, allowed)

    assert result == [
        {"protocol": "tcp", "address": "192.168.1.10", "port": 8080}
    ]


def test_find_unapproved_listeners_empty_allowlist():
    listeners = [
        {"protocol": "udp", "address": "0.0.0.0", "port": 5353},
    ]

    result = network_module.find_unapproved_listeners(listeners, [])

    assert len(result) == 1


def test_find_unapproved_listeners_ignores_loopback():
    listeners = [
        {"protocol": "tcp", "address": "127.0.0.1", "port": 8080},
    ]

    result = network_module.find_unapproved_listeners(listeners, [])

    assert result == []



def test_check_network_listeners_pass(monkeypatch):
    listeners = [
        {
            "protocol": "udp",
            "state": "UNCONN",
            "address": "0.0.0.0",
            "port": 5353,
            "process": "avahi-daemon",
        }
    ]

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        lambda: listeners,
    )

    cfg = {
        "allowed_listeners": [
            {"protocol": "udp", "address": "0.0.0.0", "port": 5353}
        ]
    }

    result = network_module.check_network_listeners(cfg)

    assert result.status == network_module.Status.PASS
    assert result.check_id == "NET-01"


def test_check_network_listeners_fail(monkeypatch):
    listeners = [
        {
            "protocol": "tcp",
            "state": "LISTEN",
            "address": "192.168.1.10",
            "port": 8080,
            "process": "unknown",
        }
    ]

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        lambda: listeners,
    )

    cfg = {"allowed_listeners": []}

    result = network_module.check_network_listeners(cfg)

    assert result.status == network_module.Status.FAIL
    assert result.check_id == "NET-01"
    assert len(result.evidence) == 1
    assert "192.168.1.10:8080" in result.evidence[0]


def test_check_network_listeners_error(monkeypatch):
    def mock_get_listening_sockets():
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["ss", "-tulnpH"],
            stderr="Operation not permitted",
        )

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        mock_get_listening_sockets,
    )

    result = network_module.check_network_listeners(
        {"allowed_listeners": []}
    )

    assert result.status == network_module.Status.ERROR
    assert result.check_id == "NET-01"
    assert "Operation not permitted" in result.evidence[0]


def test_check_network_listeners_ignores_loopback(monkeypatch):
    listeners = [
        {
            "protocol": "tcp",
            "state": "LISTEN",
            "address": "127.0.0.1",
            "port": 631,
            "process": "cupsd",
        }
    ]

    monkeypatch.setattr(
        network_module,
        "get_listening_sockets",
        lambda: listeners,
    )

    result = network_module.check_network_listeners(
        {"allowed_listeners": []}
    )

    assert result.status == network_module.Status.PASS
