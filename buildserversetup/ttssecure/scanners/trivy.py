"""
Trivy scanner implementation for ttssecure.

Trivy is a comprehensive vulnerability scanner for containers, filesystems,
Git repositories, and configurations.
"""

import json
import time
from pathlib import Path
from typing import List

from scanners.base import BaseScanner, ScanResult, Finding, Severity
from utils.process import run_with_retry
from utils.logger import get_logger


class TrivyScanner(BaseScanner):
    """Trivy vulnerability scanner implementation."""

    name = "trivy"
    display_name = "Trivy Vulnerability Scanner"
    tool_command = "trivy"

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute Trivy scan.

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
                "Trivy is not installed",
                time.time() - start_time
            )

        # Prepare output file
        output_file = output_dir / "trivy.json"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        command = [
            "trivy",
            "fs",
            "--format", "json",
            "--output", str(output_file),
            "--severity", self.severity_filter_str,
            "--scanners", "vuln,secret,misconfig",
            str(source_path)
        ]

        logger.info(f"[{self.name}] Running: {' '.join(command)}")

        # Execute with retry
        result, attempts = run_with_retry(
            command,
            cwd=source_path,
            timeout=self.timeout,
            max_retries=1
        )

        duration = time.time() - start_time

        if not result.success:
            logger.error(f"[{self.name}] Failed: {result.stderr[:200]}")
            return self._create_error_result(result.stderr[:500], duration)

        # Parse output
        try:
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    output_data = json.load(f)
                findings = self.parse_output(output_data)
            else:
                findings = []
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

    @property
    def severity_filter_str(self) -> str:
        """Get severity filter as comma-separated string for Trivy."""
        return ",".join(self.severity_filter)

    def parse_output(self, output: dict) -> List[Finding]:
        """
        Parse Trivy JSON output into findings.

        Args:
            output: Parsed JSON output from Trivy

        Returns:
            List of Finding objects
        """
        findings = []

        results = output.get("Results", [])

        for result in results:
            target = result.get("Target", "")

            # Parse vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                finding = Finding(
                    rule_id=vuln.get("VulnerabilityID", "unknown"),
                    title=vuln.get("Title", "Vulnerability detected"),
                    severity=Severity.from_string(vuln.get("Severity", "UNKNOWN")),
                    scanner=self.name,
                    file_path=target,
                    line_number=0,  # Trivy doesn't provide line numbers for deps
                    description=vuln.get("Description", "")[:500],
                    recommendation=self._get_recommendation(vuln),
                    cve_id=vuln.get("VulnerabilityID", ""),
                    cwe_id=",".join(vuln.get("CweIDs", [])),
                    raw_data=vuln
                )
                findings.append(finding)

            # Parse secrets
            for secret in result.get("Secrets", []):
                finding = Finding(
                    rule_id=secret.get("RuleID", "secret-detected"),
                    title=f"Secret detected: {secret.get('Category', 'unknown')}",
                    severity=Severity.HIGH,
                    scanner=self.name,
                    file_path=target,
                    line_number=secret.get("StartLine", 0),
                    end_line=secret.get("EndLine", 0),
                    description=f"Detected {secret.get('Category', 'secret')} in code",
                    recommendation="Remove hardcoded secrets and use environment variables",
                    raw_data=secret
                )
                findings.append(finding)

            # Parse misconfigurations
            for misconfig in result.get("Misconfigurations", []):
                finding = Finding(
                    rule_id=misconfig.get("ID", "unknown"),
                    title=misconfig.get("Title", "Misconfiguration detected"),
                    severity=Severity.from_string(misconfig.get("Severity", "UNKNOWN")),
                    scanner=self.name,
                    file_path=target,
                    line_number=0,
                    description=misconfig.get("Description", ""),
                    recommendation=misconfig.get("Resolution", ""),
                    raw_data=misconfig
                )
                findings.append(finding)

        return findings

    def _get_recommendation(self, vuln: dict) -> str:
        """Generate recommendation for vulnerability."""
        pkg_name = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")

        if fixed:
            return f"Upgrade {pkg_name} from {installed} to {fixed}"
        else:
            return f"No fixed version available for {pkg_name}. Consider alternative packages."
