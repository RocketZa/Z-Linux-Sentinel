import ipaddress
import subprocess
from sentinel.models import CheckResult, Status, Severity
from sentinel.registry import check

def is_non_loopback_address(address: str) -> bool:
    """Return whether an IP address is not loopback."""

    # Remove IPv6 interface scope, e.g. %lo
    address = address.split("%", maxsplit=1)[0]

    # Wildcard addresses listen on all interfaces.
    if address in ("0.0.0.0", "::", "*"):
        return True

    return not ipaddress.ip_address(address).is_loopback


def parse_ss_output(output: str) -> list[dict]:
    """Parse listening TCP and UDP sockets from ss output."""

    listeners = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0].lower()
        state = parts[1].upper()

        if protocol not in ("tcp", "udp"):
            continue

        if protocol == "tcp" and state != "LISTEN":
            continue

        if protocol == "udp" and state != "UNCONN":
            continue

        local_address = parts[4]

        # Handle IPv4 and bracketed IPv6 addresses.
        if local_address.startswith("["):
            address, port = local_address.rsplit(":", maxsplit=1)
            address = address.strip("[]")
        else:
            address, port = local_address.rsplit(":", maxsplit=1)

        listeners.append(
            {
                "protocol": protocol,
                "state": state,
                "address": address,
                "port": int(port),
                "process": " ".join(parts[6:]) if len(parts) > 6 else None,
            }
        )

    return listeners


def get_listening_sockets() -> list[dict]:
    """Retrieve and parse active TCP and UDP listeners."""

    result = subprocess.run(
        ["ss", "-tulnpH"],
        capture_output=True,
        text=True,
        check=True,
    )

    return parse_ss_output(result.stdout)


def find_unapproved_listeners(
    listeners: list[dict],
    allowed: list[dict],
) -> list[dict]:
    """Find non-loopback listeners not present in the allowlist."""

    unapproved = []

    allowed_sockets = {
        (
            item["protocol"],
            item["address"],
            item["port"],
        )
        for item in allowed
    }

    for listener in listeners:
        if not is_non_loopback_address(listener["address"]):
            continue

        socket_identity = (
            listener["protocol"],
            listener["address"],
            listener["port"],
        )

        if socket_identity not in allowed_sockets:
            unapproved.append(listener)

    return unapproved



@check(
    check_id="NET-01",
    title="Unapproved network listeners",
    module="Network Security",
    severity=Severity.HIGH,
    requires_root=True,
    remediation=(
        "Review unapproved network listeners, identify their services, "
        "and stop or restrict unnecessary services. Update the allowlist "
        "only for listeners that have been explicitly approved."
    ),
)
def check_network_listeners(cfg=None) -> CheckResult:
    """Audit non-loopback network listeners against the policy allowlist."""

    try:
        listeners = get_listening_sockets()

    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        error = getattr(exc, "stderr", None)
        message = error.strip() if error else str(exc)

        return CheckResult(
            check_id="NET-01",
            title="Unapproved network listeners",
            module="Network Security",
            severity=Severity.HIGH,
            status=Status.ERROR,
            message="Unable to retrieve network listeners",
            evidence=[message],
        )

    allowed = cfg.get("allowed_listeners", []) if cfg else []

    unapproved = find_unapproved_listeners(listeners, allowed)

    if unapproved:
        evidence = [
            (
                f"{item['protocol']} {item['address']}:{item['port']} "
                f"process={item['process'] or 'unknown'}"
            )
            for item in unapproved
        ]

        return CheckResult(
            check_id="NET-01",
            title="Unapproved network listeners",
            module="Network Security",
            severity=Severity.HIGH,
            status=Status.FAIL,
            message=f"Found {len(unapproved)} unapproved non-loopback listener(s)",
            evidence=evidence,
        )

    return CheckResult(
        check_id="NET-01",
        title="Unapproved network listeners",
        module="Network Security",
        severity=Severity.HIGH,
        status=Status.PASS,
        message="All non-loopback network listeners are approved",
        evidence=[
            f"Inspected {len(listeners)} listening socket(s)",
        ],
    )
