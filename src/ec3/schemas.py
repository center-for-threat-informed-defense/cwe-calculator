"""Utility classes used to configure the REST Server's API schema.

Utility classes define the input and output schemas for each REST API endpoint.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

from enum import Enum

from pydantic import BaseModel


class CweScore(BaseModel):
    """CWE Score Result"""

    projected_cvss: float = 6.633333333333334
    cwe: int = 121
    count: int = 3
    min_cvss_base_score: float = 5.5
    max_cvss_base_score: float = 7.2
    avg_cvss_base_score: float = 6.63333333333333
    std_dev_cvss_base_score: float = 0.981495457622364
    cve_records: list[str] = ["CVE-2023-6340", "CVE-2024-1003", "CVE-2024-1004"]


class ExploitCodeMaturity(str, Enum):
    """CVSS 3.1 Exploit Code Maturity (E)"""

    X = "X"
    H = "H"
    F = "F"
    P = "P"
    U = "U"


class RemediationLevel(str, Enum):
    """CVSS 3.1 Remediation Level (RL)"""

    X = "X"
    U = "U"
    W = "W"
    T = "T"
    O = "O"  # noqa: E741


class ReportConfidence(str, Enum):
    """CVSS 3.1 Report Confidence (RC)"""

    X = "X"
    C = "C"
    R = "R"
    U = "U"


class ConfidentialityRequirement(str, Enum):
    """CVSS 3.1 Confidentiality Requirement (CR)"""

    X = "X"
    H = "H"
    M = "M"
    L = "L"


class IntegrityRequirement(str, Enum):
    """CVSS 3.1 Integrity Requirement (IR)"""

    X = "X"
    H = "H"
    M = "M"
    L = "L"


class AvailabilityRequirement(str, Enum):
    """CVSS 3.1 Availability Requirement (AR)"""

    X = "X"
    H = "H"
    M = "M"
    L = "L"


class ModifiedAttackVector(str, Enum):
    """CVSS 3.1 Modified Attack Vector (MAV)"""

    X = "X"
    N = "N"
    A = "A"
    L = "L"
    P = "P"


class ModifiedAttackComplexity(str, Enum):
    """CVSS 3.1 Modified Attack Complexity (MAC)"""

    X = "X"
    L = "L"
    H = "H"


class ModifiedPrivilegesRequired(str, Enum):
    """CVSS 3.1 Modified Privileges Required (MPR)"""

    X = "X"
    N = "N"
    L = "L"
    H = "H"


class ModifiedUserInteraction(str, Enum):
    """CVSS 3.1 Modified User Interaction (MUI)"""

    X = "X"
    N = "N"
    R = "R"


class ModifiedScope(str, Enum):
    """CVSS 3.1 Modified Scope (MS)"""

    X = "X"
    N = "U"
    R = "C"


class ModifiedConfidentiality(str, Enum):
    """CVSS 3.1 Modified Confidentiality (MC)"""

    X = "X"
    H = "H"
    L = "L"
    N = "N"


class ModifiedIntegrity(str, Enum):
    """CVSS 3.1 Modified Integrity (MI)"""

    X = "X"
    H = "H"
    L = "L"
    N = "N"


class ModifiedAvailability(str, Enum):
    """CVSS 3.1 Modified Availability (MA)"""

    X = "X"
    H = "H"
    L = "L"
    N = "N"
