"""Core data model for GAMBIT: what a finding is and how severe it can be."""

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that HIGH > MED > LOW > INFO, which makes sorting easy."""

    INFO = 1
    LOW = 2
    MED = 3
    HIGH = 4


@dataclass
class Finding:
    """One thing a module found on a target."""

    severity: Severity
    host: str
    title: str
    evidence: str
    why: str
    next_step: str

    def to_dict(self) -> dict:
        """Plain dict for JSON export, with severity as a name like "HIGH"."""
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
