"""
Semgrep scanner implementation for ttssecure.

Semgrep is a fast, open-source static analysis tool for finding bugs,
detecting vulnerabilities, and enforcing code standards.
"""

import json
import time
from pathlib import Path
from typing import List

from scanners.base import BaseScanner, ScanResult, Finding, Severity
from utils.process import run_with_retry
from utils.logger import get_logger


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner implementation."""

    name = "semgrep"
    display_name = "Semgrep SAST"
    tool_command = "semgrep"

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute Semgrep scan.

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
                "Semgrep is not installed",
                time.time() - start_time
            )

        # Prepare output file
        output_file = output_dir / "semgrep.json"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        command = [
            "semgrep",
            f"--config={self.config}",
            "--json",
            f"--output={output_file}",
            "--no-git-ignore",  # Scan all files
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

        if not result.success and result.return_code != 1:
            # Return code 1 means findings found, which is expected
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

    def parse_output(self, output: dict) -> List[Finding]:
        """
        Parse Semgrep JSON output into findings.

        Args:
            output: Parsed JSON output from Semgrep

        Returns:
            List of Finding objects
        """
        findings = []

        results = output.get("results", [])

        for result in results:
            # Map Semgrep severity to our severity
            semgrep_severity = result.get("extra", {}).get("severity", "INFO")
            severity = self._map_severity(semgrep_severity)

            # Extract location
            start = result.get("start", {})
            end = result.get("end", {})

            # Get metadata
            metadata = result.get("extra", {}).get("metadata", {})

            finding = Finding(
                rule_id=result.get("check_id", "unknown"),
                title=result.get("extra", {}).get("message", "Security finding"),
                severity=severity,
                scanner=self.name,
                file_path=result.get("path", ""),
                line_number=start.get("line", 0),
                column=start.get("col", 0),
                end_line=end.get("line", 0),
                description=result.get("extra", {}).get("message", ""),
                code_snippet=result.get("extra", {}).get("lines", ""),
                cwe_id=self._extract_cwe(metadata),
                owasp_category=metadata.get("owasp", ""),
                confidence=metadata.get("confidence", ""),
                raw_data=result
            )
            findings.append(finding)

        return findings

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity to standard severity."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.INFO)

    def _extract_cwe(self, metadata: dict) -> str:
        """Extract CWE ID from metadata."""
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, list) and cwe:
            return cwe[0]
        elif isinstance(cwe, str):
            return cwe
        return ""
