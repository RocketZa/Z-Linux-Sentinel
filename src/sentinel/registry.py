from dataclasses import dataclass
from typing import Callable

from sentinel.models import Severity


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    module: str
    severity: Severity
    requires_root: bool = False
    remediation: str = ""
    func: Callable = None


REGISTRY: dict[str, Check] = {}


def check(
    check_id: str,
    title: str,
    module: str,
    severity: Severity,
    requires_root: bool = False,
    remediation: str = "",
):
    def decorator(func: Callable):
        if check_id in REGISTRY:
            raise ValueError(f"Duplicate check ID: {check_id}")

        REGISTRY[check_id] = Check(
            id=check_id,
            title=title,
            module=module,
            severity=severity,
            requires_root=requires_root,
            remediation=remediation,
            func=func,
        )

        return func

    return decorator