"""
Results aggregator for ttssecure.

Combines results from all scanners into a unified report structure.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any

from scanners.base import ScanResult, Finding, Severity


@dataclass
class Statistics:
    """Aggregated statistics across all scanners."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    findings_by_scanner: Dict[str, int] = field(default_factory=dict)
    scanners_run: int = 0
    scanners_failed: int = 0
    total_duration: float = 0.0

    @property
    def risk_score(self) -> float:
        """
        Calculate risk score.

        Formula: (critical*4 + high*2 + medium*1) / 10
        """
        score = (self.critical_count * 4 + self.high_count * 2 + self.medium_count * 1) / 10
        return round(score, 2)

    @property
    def risk_level(self) -> str:
        """Determine risk level from score."""
        if self.risk_score >= 7:
            return "CRITICAL"
        elif self.risk_score >= 5:
            return "HIGH"
        elif self.risk_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class AggregatedResults:
    """Aggregated results from all scanners."""

    # Metadata
    report_id: str
    project_name: str
    component_name: str
    git_url: str
    git_branch: str
    qa_url: str
    build_number: str
    scan_timestamp: datetime

    # Contact info
    developer_team: str = ""
    developer_contact: str = ""
    devsecops_contact: str = ""

    # Results
    scanner_results: List[ScanResult] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)
    statistics: Statistics = field(default_factory=Statistics)

    # Status
    passed_thresholds: bool = True
    threshold_violations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "metadata": {
                "report_id": self.report_id,
                "project_name": self.project_name,
                "component_name": self.component_name,
                "git_url": self.git_url,
                "git_branch": self.git_branch,
                "qa_url": self.qa_url,
                "build_number": self.build_number,
                "scan_timestamp": self.scan_timestamp.isoformat(),
                "developer_team": self.developer_team,
                "developer_contact": self.developer_contact,
                "devsecops_contact": self.devsecops_contact,
            },
            "statistics": {
                "total_findings": self.statistics.total_findings,
                "critical": self.statistics.critical_count,
                "high": self.statistics.high_count,
                "medium": self.statistics.medium_count,
                "low": self.statistics.low_count,
                "info": self.statistics.info_count,
                "risk_score": self.statistics.risk_score,
                "risk_level": self.statistics.risk_level,
                "findings_by_scanner": self.statistics.findings_by_scanner,
                "scanners_run": self.statistics.scanners_run,
                "scanners_failed": self.statistics.scanners_failed,
                "total_duration_seconds": self.statistics.total_duration,
            },
            "threshold_status": {
                "passed": self.passed_thresholds,
                "violations": self.threshold_violations,
            },
            "scanner_results": [r.to_dict() for r in self.scanner_results],
            "findings": [f.to_dict() for f in self.all_findings],  # Show ALL findings in JSON
        }


def aggregate_results(
    scan_results: List[ScanResult],
    report_id: str,
    project_name: str,
    component_name: str,
    git_url: str,
    git_branch: str,
    qa_url: str,
    build_number: str,
    developer_team: str = "",
    developer_contact: str = "",
    devsecops_contact: str = "",
) -> AggregatedResults:
    """
    Aggregate results from multiple scanners.

    Args:
        scan_results: List of ScanResult from each scanner
        report_id: Unique report identifier
        project_name: Project name
        component_name: Component name
        git_url: Git repository URL
        git_branch: Git branch scanned
        qa_url: QA environment URL
        build_number: Jenkins build number
        developer_team: Developer team name
        developer_contact: Developer contact email
        devsecops_contact: DevSecOps contact email

    Returns:
        AggregatedResults with combined data
    """
    # Collect all findings
    all_findings: List[Finding] = []
    findings_by_scanner: Dict[str, int] = {}
    total_duration = 0.0
    scanners_failed = 0

    for result in scan_results:
        all_findings.extend(result.findings)
        findings_by_scanner[result.scanner_name] = len(result.findings)
        total_duration += result.duration

        if not result.success:
            scanners_failed += 1

    # Sort findings by severity
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    # Calculate statistics
    statistics = Statistics(
        total_findings=len(all_findings),
        critical_count=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in all_findings if f.severity == Severity.HIGH),
        medium_count=sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
        low_count=sum(1 for f in all_findings if f.severity == Severity.LOW),
        info_count=sum(1 for f in all_findings if f.severity == Severity.INFO),
        findings_by_scanner=findings_by_scanner,
        scanners_run=len(scan_results),
        scanners_failed=scanners_failed,
        total_duration=total_duration,
    )

    return AggregatedResults(
        report_id=report_id,
        project_name=project_name,
        component_name=component_name,
        git_url=git_url,
        git_branch=git_branch,
        qa_url=qa_url,
        build_number=build_number,
        scan_timestamp=datetime.now(),
        developer_team=developer_team,
        developer_contact=developer_contact,
        devsecops_contact=devsecops_contact,
        scanner_results=scan_results,
        all_findings=all_findings,
        statistics=statistics,
    )


def check_thresholds(
    results: AggregatedResults,
    max_critical: int = 0,
    max_high: int = 10,
    max_medium: int = 50,
    max_low: int = 100,
    fail_on_secrets: bool = True
) -> AggregatedResults:
    """
    Check if results exceed configured thresholds.

    Args:
        results: Aggregated results
        max_critical: Maximum allowed critical findings
        max_high: Maximum allowed high findings
        max_medium: Maximum allowed medium findings
        max_low: Maximum allowed low findings
        fail_on_secrets: Whether to fail on any secret findings

    Returns:
        Updated AggregatedResults with threshold status
    """
    violations = []
    stats = results.statistics

    if stats.critical_count > max_critical:
        violations.append(f"CRITICAL: {stats.critical_count} > {max_critical}")

    if stats.high_count > max_high:
        violations.append(f"HIGH: {stats.high_count} > {max_high}")

    if stats.medium_count > max_medium:
        violations.append(f"MEDIUM: {stats.medium_count} > {max_medium}")

    if stats.low_count > max_low:
        violations.append(f"LOW: {stats.low_count} > {max_low}")

    # Check for secrets
    if fail_on_secrets:
        secret_count = sum(
            1 for f in results.all_findings
            if "secret" in f.rule_id.lower() or f.scanner == "trufflehog"
        )
        if secret_count > 0:
            violations.append(f"SECRETS: {secret_count} secrets detected")

    results.passed_thresholds = len(violations) == 0
    results.threshold_violations = violations

    return results
