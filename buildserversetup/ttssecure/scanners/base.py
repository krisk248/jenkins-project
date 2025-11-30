"""
Base scanner class for ttssecure.

All scanner implementations inherit from BaseScanner.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        value_upper = value.upper()
        for sev in cls:
            if sev.value == value_upper:
                return sev
        return cls.INFO


@dataclass
class Finding:
    """Represents a single security finding."""

    # Required fields
    rule_id: str
    title: str
    severity: Severity
    scanner: str

    # Location information
    file_path: str = ""
    line_number: int = 0
    column: int = 0
    end_line: int = 0

    # Details
    description: str = ""
    recommendation: str = ""
    code_snippet: str = ""

    # Metadata
    cwe_id: str = ""
    cve_id: str = ""
    owasp_category: str = ""
    confidence: str = ""

    # Raw data for reference
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "scanner": self.scanner,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "end_line": self.end_line,
            "description": self.description,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet[:200] if self.code_snippet else "",
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "owasp_category": self.owasp_category,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Result of a scanner execution."""

    scanner_name: str
    success: bool
    duration: float

    # Findings
    findings: List[Finding] = field(default_factory=list)

    # Statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Metadata
    scanner_version: str = ""
    error_message: str = ""
    raw_output_path: str = ""

    def __post_init__(self):
        """Calculate statistics from findings."""
        self._calculate_stats()

    def _calculate_stats(self):
        """Calculate severity counts from findings."""
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "success": self.success,
            "duration": self.duration,
            "scanner_version": self.scanner_version,
            "error_message": self.error_message,
            "statistics": {
                "total": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.

    Implement this class to add new scanner support.
    """

    # Scanner identification
    name: str = "base"
    display_name: str = "Base Scanner"
    tool_command: str = ""

    # Default timeout (10 minutes)
    default_timeout: int = 600

    def __init__(
        self,
        timeout: int = None,
        config: str = "auto",
        severity_filter: str = "CRITICAL,HIGH,MEDIUM,LOW",
        max_findings: int = 100,
        include_paths: List[str] = None,
        exclude_paths: List[str] = None
    ):
        """
        Initialize scanner.

        Args:
            timeout: Scan timeout in seconds
            config: Scanner-specific configuration
            severity_filter: Comma-separated severity levels to include
            max_findings: Maximum findings to return
            include_paths: Only scan these paths (relative to source)
            exclude_paths: Skip these paths
        """
        self.timeout = timeout or self.default_timeout
        self.config = config
        self.severity_filter = severity_filter.split(",")
        self.max_findings = max_findings
        self.include_paths = include_paths or []
        self.exclude_paths = exclude_paths or []

    @abstractmethod
    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute the security scan.

        Args:
            source_path: Path to source code to scan
            output_dir: Directory to write raw output

        Returns:
            ScanResult with findings
        """
        pass

    @abstractmethod
    def parse_output(self, output: str) -> List[Finding]:
        """
        Parse scanner output into findings.

        Args:
            output: Raw scanner output (usually JSON)

        Returns:
            List of Finding objects
        """
        pass

    def is_installed(self) -> bool:
        """Check if the scanner tool is installed."""
        from utils.process import check_tool_installed
        return check_tool_installed(self.tool_command)

    def get_version(self) -> Optional[str]:
        """Get scanner tool version."""
        from utils.process import get_tool_version
        return get_tool_version(self.tool_command)

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Filter findings by severity and limit count.

        Args:
            findings: List of all findings

        Returns:
            Filtered list of findings
        """
        # Filter by severity
        filtered = [
            f for f in findings
            if f.severity.value in self.severity_filter
        ]

        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        filtered.sort(key=lambda f: severity_order.get(f.severity, 5))

        # Limit count
        return filtered[:self.max_findings]

    def _create_error_result(self, error_message: str, duration: float) -> ScanResult:
        """Create a ScanResult for error cases."""
        return ScanResult(
            scanner_name=self.name,
            success=False,
            duration=duration,
            error_message=error_message,
            scanner_version=self.get_version() or "unknown",
        )
