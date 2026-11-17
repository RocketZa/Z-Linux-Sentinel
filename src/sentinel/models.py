from dataclasses import dataclass, field
from enum import Enum

class Status(str, Enum):
    PASS = "PASS"; FAIL = "FAIL"; WARN = "WARN"; SKIP = "SKIP"; ERROR = "ERROR"

class Severity(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"

@dataclass
class CheckResult:
    check_id: str; title: str; module: str
    severity: Severity; status: Status; message: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
