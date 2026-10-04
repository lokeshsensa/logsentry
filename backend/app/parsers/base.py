from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ParsedEvent:
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    event_type: Optional[str]  # AUTH_FAILURE, AUTH_SUCCESS, HTTP_REQUEST, PRIVILEGE_EVENT, SCAN_PROBE, etc.
    method: Optional[str]
    endpoint: Optional[str]
    status_code: Optional[int]
    protocol: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    process: Optional[str]
    message: Optional[str]
    raw_log: str
    severity: str = "INFORMATIONAL"
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "event_type": self.event_type,
            "method": self.method,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "process": self.process,
            "message": self.message,
            "raw_log": self.raw_log,
            "severity": self.severity,
            "line_number": self.line_number,
        }

class BaseLogParser(ABC):
    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Name of the parser"""
        pass

    @abstractmethod
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Test whether this parser can process the given sample lines"""
        pass

    @abstractmethod
    def parse_line(self, line: str, line_number: int = 1) -> Optional[ParsedEvent]:
        """
        Parse a single raw line into a normalized ParsedEvent.
        Returns None or raises ValueError if line cannot be parsed.
        """
        pass
