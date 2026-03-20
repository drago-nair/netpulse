from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    detector: str
    severity: Severity
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    extra: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "severity": self.severity.value,
            "message": self.message,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "extra": self.extra
        }

    def __str__(self) -> str:
        src = f" src={self.src_ip}" if self.src_ip else ""
        return f"[{self.severity.value}] {self.detector}{src} — {self.message}"