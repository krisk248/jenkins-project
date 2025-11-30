"""
OWASP Dependency-Check scanner implementation for ttssecure.

OWASP Dependency-Check identifies project dependencies and checks
if there are any known, publicly disclosed vulnerabilities (CVEs).
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from .base import BaseScanner, ScanResult, Finding, Severity
from ..utils.process import run_with_retry, check_tool_installed
from ..utils.logger import get_logger


class OWASPDependencyScanner(BaseScanner):
    """OWASP Dependency-Check scanner implementation."""

    name = "owasp_dependency"
    display_name = "OWASP Dependency-Check"
    tool_command = "dependency-check"

    # Alternative commands to check
    alternative_commands = [
        "dependency-check",
        "dependency-check.sh",
        "/opt/dependency-check/bin/dependency-check.sh"
    ]

    def is_installed(self) -> bool:
        """Check if OWASP Dependency-Check is installed."""
        for cmd in self.alternative_commands:
            if check_tool_installed(cmd):
                self.tool_command = cmd
                return True

            # Check if full path exists
            if Path(cmd).exists():
                self.tool_command = cmd
                return True

        return False

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute OWASP Dependency-Check scan.

        Args:
            source_path: Path to source code
            output_dir: Directory to write raw output

        Returns:
            ScanResult with findings
        """
        logger = get_logger()
        start_time = time.time()

        # Check if installed
        if not self.is_installed():
            return self._create_error_result(
                "OWASP Dependency-Check is not installed. "
                "Download from: https://owasp.org/www-project-dependency-check/",
                time.time() - start_time
            )

        # Prepare output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        command = [
            self.tool_command,
            "--project", source_path.name,
            "--scan", str(source_path),
            "--format", "JSON",
            "--out", str(output_dir),
            "--noupdate",  # Skip update on each run (update separately)
        ]

        logger.info(f"[{self.name}] Running: {' '.join(command)}")
        logger.info(f"[{self.name}] Note: First run may be slow due to CVE database download")

        # Execute with extended timeout (first run can be slow)
        result, attempts = run_with_retry(
            command,
            cwd=source_path,
            timeout=self.timeout * 2,  # Double timeout for this scanner
            max_retries=1
        )

        duration = time.time() - start_time

        # Find output file
        output_file = self._find_output_file(output_dir)
        if not output_file:
            logger.error(f"[{self.name}] No output file generated")
            return self._create_error_result(
                f"No output file found: {result.stderr[:200]}",
                duration
            )

        # Parse output
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                output_data = json.load(f)
            findings = self.parse_output(output_data)
        except Exception as e:
            logger.error(f"[{self.name}] Failed to parse output: {e}")
            return self._create_error_result(f"Parse error: {e}", duration)

        # Filter findings
        filtered_findings = self.filter_findings(findings)

        return ScanResult(
            scanner_name=self.name,
            success=True,
            duration=duration,
            findings=filtered_findings,
            scanner_version=self.get_version() or "unknown",
            raw_output_path=str(output_file)
        )

    def _find_output_file(self, output_dir: Path) -> Optional[Path]:
        """Find the JSON output file from Dependency-Check."""
        # Look for dependency-check-report.json
        candidates = [
            output_dir / "dependency-check-report.json",
            output_dir / "report.json",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        # Search for any JSON file
        json_files = list(output_dir.glob("*.json"))
        if json_files:
            return json_files[0]

        return None

    def parse_output(self, output: dict) -> List[Finding]:
        """
        Parse OWASP Dependency-Check JSON output into findings.

        Args:
            output: Parsed JSON output

        Returns:
            List of Finding objects
        """
        findings = []

        dependencies = output.get("dependencies", [])

        for dep in dependencies:
            vulnerabilities = dep.get("vulnerabilities", [])

            if not vulnerabilities:
                continue

            file_path = dep.get("filePath", dep.get("fileName", ""))
            package_name = dep.get("fileName", "unknown")

            for vuln in vulnerabilities:
                finding = self._parse_vulnerability(vuln, file_path, package_name)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_vulnerability(
        self,
        vuln: dict,
        file_path: str,
        package_name: str
    ) -> Finding:
        """Parse a single vulnerability."""
        # Get CVE ID
        cve_id = vuln.get("name", "unknown")

        # Get severity from CVSS
        severity = self._get_severity(vuln)

        # Get description
        description = vuln.get("description", "")

        # Build recommendation
        recommendation = self._build_recommendation(vuln, package_name)

        # Get CWE IDs
        cwes = vuln.get("cwes", [])
        cwe_id = cwes[0] if cwes else ""

        return Finding(
            rule_id=cve_id,
            title=f"{cve_id}: Vulnerability in {package_name}",
            severity=severity,
            scanner=self.name,
            file_path=file_path,
            line_number=0,
            description=description[:500] if description else f"Known vulnerability in {package_name}",
            recommendation=recommendation,
            cve_id=cve_id,
            cwe_id=str(cwe_id),
            raw_data={
                "package": package_name,
                "cvssv3": vuln.get("cvssv3", {}),
                "cvssv2": vuln.get("cvssv2", {}),
                "references": vuln.get("references", [])[:5],  # Limit references
            }
        )

    def _get_severity(self, vuln: dict) -> Severity:
        """Determine severity from CVSS scores."""
        # Try CVSS v3 first
        cvssv3 = vuln.get("cvssv3", {})
        if cvssv3:
            base_severity = cvssv3.get("baseSeverity", "").upper()
            if base_severity:
                return Severity.from_string(base_severity)

            base_score = cvssv3.get("baseScore", 0)
            return self._score_to_severity(base_score)

        # Fall back to CVSS v2
        cvssv2 = vuln.get("cvssv2", {})
        if cvssv2:
            base_score = cvssv2.get("score", 0)
            return self._score_to_severity(base_score)

        # Default to MEDIUM if no CVSS
        return Severity.MEDIUM

    def _score_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _build_recommendation(self, vuln: dict, package_name: str) -> str:
        """Build recommendation for vulnerability."""
        parts = [f"Update {package_name} to a patched version."]

        # Add reference links
        references = vuln.get("references", [])
        if references:
            first_ref = references[0].get("url", "")
            if first_ref:
                parts.append(f"See: {first_ref}")

        return " ".join(parts)
