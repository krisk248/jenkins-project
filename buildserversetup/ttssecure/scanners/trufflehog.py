"""
TruffleHog scanner implementation for ttssecure.

TruffleHog is a tool for finding secrets in codebases
such as API keys, passwords, and tokens.
"""

import json
import time
from pathlib import Path
from typing import List

from scanners.base import BaseScanner, ScanResult, Finding, Severity
from utils.process import run_command
from utils.logger import get_logger


class TruffleHogScanner(BaseScanner):
    """TruffleHog secret scanner implementation."""

    name = "trufflehog"
    display_name = "TruffleHog Secret Scanner"
    tool_command = "trufflehog"

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute TruffleHog scan.

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
                "TruffleHog is not installed",
                time.time() - start_time
            )

        # Prepare output file
        output_file = output_dir / "trufflehog.json"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        # TruffleHog outputs JSON lines (one JSON object per line)
        command = [
            "trufflehog",
            "filesystem",
            "--json",
            "--no-verification",  # Skip verification for speed
        ]

        # Add exclude paths (TruffleHog uses --exclude-paths with file)
        # For now, we'll scan specific paths if include_paths is set
        if self.include_paths:
            for include in self.include_paths:
                include_path = source_path / include
                if include_path.exists():
                    command.append(str(include_path))
            # Fallback if no valid paths
            if len(command) == 4:
                command.append(str(source_path))
        else:
            command.append(str(source_path))

        logger.info(f"[{self.name}] Running: {' '.join(command)}")

        # Execute (no retry for TruffleHog as it's usually fast)
        result = run_command(
            command,
            cwd=source_path,
            timeout=self.timeout
        )

        duration = time.time() - start_time

        # TruffleHog returns 0 regardless of findings
        # Parse output directly from stdout
        try:
            findings = self.parse_output(result.stdout)

            # Save raw output
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump([f.to_dict() for f in findings], f, indent=2)

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

    def parse_output(self, output: str) -> List[Finding]:
        """
        Parse TruffleHog JSON lines output into findings.

        Args:
            output: Raw output from TruffleHog (JSON lines format)

        Returns:
            List of Finding objects
        """
        findings = []

        # TruffleHog outputs one JSON object per line
        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                data = json.loads(line)
                finding = self._parse_finding(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                continue

            # Limit findings
            if len(findings) >= self.max_findings:
                break

        return findings

    def _parse_finding(self, data: dict) -> Finding:
        """Parse a single TruffleHog finding."""
        source_metadata = data.get("SourceMetadata", {}).get("Data", {})
        file_info = source_metadata.get("Filesystem", {})

        # Determine file path
        file_path = file_info.get("file", "")

        # Determine line number (TruffleHog v3 format)
        line_number = file_info.get("line", 0)

        # Get detector type
        detector_type = data.get("DetectorType", "unknown")
        detector_name = data.get("DetectorName", detector_type)

        # All secrets are HIGH severity by default
        # But we can adjust based on detector type
        severity = self._determine_severity(detector_type)

        return Finding(
            rule_id=f"secret-{detector_type.lower()}",
            title=f"Secret detected: {detector_name}",
            severity=severity,
            scanner=self.name,
            file_path=file_path,
            line_number=line_number,
            description=f"Detected {detector_name} secret in source code. "
                       "Hardcoded secrets can lead to credential exposure.",
            recommendation="Remove the hardcoded secret and use environment variables "
                          "or a secrets management system.",
            confidence=data.get("Verified", False) and "HIGH" or "MEDIUM",
            raw_data={
                "detector_type": detector_type,
                "detector_name": detector_name,
                "verified": data.get("Verified", False),
                # Don't store actual secret value for security
            }
        )

    def _determine_severity(self, detector_type: str) -> Severity:
        """Determine severity based on secret type."""
        critical_types = [
            "AWS", "Azure", "GCP", "PrivateKey", "RSAPrivateKey",
            "DatabasePassword", "JWTSecret"
        ]
        high_types = [
            "GitHub", "GitLab", "Slack", "Stripe", "SendGrid",
            "Twilio", "Firebase", "Generic"
        ]

        detector_upper = detector_type.upper()

        for critical in critical_types:
            if critical.upper() in detector_upper:
                return Severity.CRITICAL

        for high in high_types:
            if high.upper() in detector_upper:
                return Severity.HIGH

        return Severity.HIGH  # Default to HIGH for unknown secrets
