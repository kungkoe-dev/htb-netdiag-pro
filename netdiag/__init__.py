"""
netdiag - Principal Network Engineer Diagnostic & Cable Troubleshooter
OSI Layer 1 to Layer 7 Automated Network Analyzer
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    layer: str
    name: str
    status: CheckStatus
    summary: str
    details: str = ""
    recommendation: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InterfaceDiagReport:
    interface: str
    if_type: str  # "ethernet", "wifi", "virtual"
    mac_address: str = ""
    driver: str = ""
    checks: List[CheckResult] = field(default_factory=list)
    root_causes: List[str] = field(default_factory=list)
    action_plan: List[str] = field(default_factory=list)
    overall_status: CheckStatus = CheckStatus.INFO
    raw_context: Dict[str, Any] = field(default_factory=dict)

    def add_check(self, check: CheckResult) -> None:
        self.checks.append(check)
