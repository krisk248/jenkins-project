"""
ESLint Security scanner implementation for ttssecure.

ESLint with eslint-plugin-security finds common security issues
in JavaScript and TypeScript code.
"""

import json
import time
from pathlib import Path
from typing import List

from .base import BaseScanner, ScanResult, Finding, Severity
from ..utils.process import run_with_retry, check_tool_installed
from ..utils.logger import get_logger


class ESLintSecurityScanner(BaseScanner):
    """ESLint Security scanner implementation."""

    name = "eslint_security"
    display_name = "ESLint Security"
    tool_command = "eslint"

    # Security rule IDs to their severity
    SECURITY_RULES = {
        "security/detect-object-injection": Severity.HIGH,
        "security/detect-non-literal-regexp": Severity.MEDIUM,
        "security/detect-unsafe-regex": Severity.HIGH,
        "security/detect-buffer-noassert": Severity.MEDIUM,
        "security/detect-child-process": Severity.HIGH,
        "security/detect-disable-mustache-escape": Severity.HIGH,
        "security/detect-eval-with-expression": Severity.CRITICAL,
        "security/detect-no-csrf-before-method-override": Severity.HIGH,
        "security/detect-non-literal-fs-filename": Severity.HIGH,
        "security/detect-non-literal-require": Severity.MEDIUM,
        "security/detect-possible-timing-attacks": Severity.MEDIUM,
        "security/detect-pseudoRandomBytes": Severity.MEDIUM,
        "security/detect-new-buffer": Severity.LOW,
        "security/detect-bidi-characters": Severity.HIGH,
    }

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute ESLint security scan.

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
                "ESLint is not installed. Install with: npm install -g eslint eslint-plugin-security",
                time.time() - start_time
            )

        # Check for JS/TS files
        has_js_files = self._has_js_files(source_path)
        if not has_js_files:
            logger.info(f"[{self.name}] No JavaScript/TypeScript files found, skipping")
            return ScanResult(
                scanner_name=self.name,
                success=True,
                duration=time.time() - start_time,
                findings=[],
                scanner_version=self.get_version() or "unknown",
            )

        # Prepare output file
        output_file = output_dir / "eslint-security.json"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command with inline security config
        command = [
            "eslint",
            "--format", "json",
            "--output-file", str(output_file),
            "--no-eslintrc",  # Ignore project config
            "--plugin", "security",
            "--rule", "security/detect-object-injection: warn",
            "--rule", "security/detect-non-literal-regexp: warn",
            "--rule", "security/detect-unsafe-regex: error",
            "--rule", "security/detect-buffer-noassert: warn",
            "--rule", "security/detect-child-process: error",
            "--rule", "security/detect-disable-mustache-escape: error",
            "--rule", "security/detect-eval-with-expression: error",
            "--rule", "security/detect-no-csrf-before-method-override: error",
            "--rule", "security/detect-non-literal-fs-filename: warn",
            "--rule", "security/detect-non-literal-require: warn",
            "--rule", "security/detect-possible-timing-attacks: warn",
            "--rule", "security/detect-pseudoRandomBytes: warn",
            "--rule", "security/detect-bidi-characters: error",
            "--ext", ".js,.jsx,.ts,.tsx",
            str(source_path)
        ]

        logger.info(f"[{self.name}] Running ESLint with security plugin")

        # Execute with retry
        result, attempts = run_with_retry(
            command,
            cwd=source_path,
            timeout=self.timeout,
            max_retries=1
        )

        duration = time.time() - start_time

        # ESLint returns 1 if there are warnings/errors, which is expected
        # Only fail on return code > 1 (config error, etc.)
        if result.return_code > 1:
            logger.error(f"[{self.name}] Failed: {result.stderr[:200]}")
            return self._create_error_result(result.stderr[:500], duration)

        # Parse output
        try:
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    output_data = json.load(f)
                findings = self.parse_output(output_data)
            else:
                # ESLint might output to stdout if no findings
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

    def _has_js_files(self, source_path: Path) -> bool:
        """Check if directory contains JavaScript/TypeScript files."""
        js_extensions = [".js", ".jsx", ".ts", ".tsx"]

        for ext in js_extensions:
            if list(source_path.rglob(f"*{ext}")):
                return True

        return False

    def parse_output(self, output: list) -> List[Finding]:
        """
        Parse ESLint JSON output into findings.

        Args:
            output: Parsed JSON output from ESLint (list of file results)

        Returns:
            List of Finding objects
        """
        findings = []

        for file_result in output:
            file_path = file_result.get("filePath", "")

            for message in file_result.get("messages", []):
                rule_id = message.get("ruleId", "unknown")

                # Only include security plugin rules
                if not rule_id.startswith("security/"):
                    continue

                severity = self._get_severity(rule_id, message.get("severity", 1))

                finding = Finding(
                    rule_id=rule_id,
                    title=message.get("message", "Security issue detected"),
                    severity=severity,
                    scanner=self.name,
                    file_path=file_path,
                    line_number=message.get("line", 0),
                    column=message.get("column", 0),
                    end_line=message.get("endLine", 0),
                    description=message.get("message", ""),
                    recommendation=self._get_recommendation(rule_id),
                    cwe_id=self._get_cwe(rule_id),
                    raw_data=message
                )
                findings.append(finding)

        return findings

    def _get_severity(self, rule_id: str, eslint_severity: int) -> Severity:
        """Get severity for a rule."""
        # Check our mapping first
        if rule_id in self.SECURITY_RULES:
            return self.SECURITY_RULES[rule_id]

        # Fall back to ESLint severity
        # ESLint: 1 = warn, 2 = error
        if eslint_severity == 2:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _get_recommendation(self, rule_id: str) -> str:
        """Get recommendation for a security rule."""
        recommendations = {
            "security/detect-object-injection": "Avoid using user input directly as object keys. Validate and whitelist allowed keys.",
            "security/detect-non-literal-regexp": "Use literal regular expressions instead of dynamic ones from user input.",
            "security/detect-unsafe-regex": "The regex pattern may be vulnerable to ReDoS. Simplify the pattern.",
            "security/detect-buffer-noassert": "Use Buffer methods with assertion checks enabled.",
            "security/detect-child-process": "Avoid executing shell commands with user input. Use parameterized APIs.",
            "security/detect-disable-mustache-escape": "Do not disable HTML escaping in templates.",
            "security/detect-eval-with-expression": "Never use eval() with dynamic content. Find alternative approaches.",
            "security/detect-no-csrf-before-method-override": "Configure CSRF protection before method-override middleware.",
            "security/detect-non-literal-fs-filename": "Validate and sanitize file paths to prevent path traversal.",
            "security/detect-non-literal-require": "Use static require paths. Dynamic requires can lead to code injection.",
            "security/detect-possible-timing-attacks": "Use constant-time comparison for sensitive string comparisons.",
            "security/detect-pseudoRandomBytes": "Use crypto.randomBytes() instead of pseudoRandomBytes().",
            "security/detect-bidi-characters": "Remove bidirectional control characters that can hide malicious code.",
        }

        return recommendations.get(
            rule_id,
            "Review the security issue and apply appropriate fixes."
        )

    def _get_cwe(self, rule_id: str) -> str:
        """Get CWE ID for a security rule."""
        cwe_mapping = {
            "security/detect-object-injection": "CWE-94",
            "security/detect-unsafe-regex": "CWE-1333",
            "security/detect-child-process": "CWE-78",
            "security/detect-eval-with-expression": "CWE-94",
            "security/detect-non-literal-fs-filename": "CWE-22",
            "security/detect-possible-timing-attacks": "CWE-208",
            "security/detect-pseudoRandomBytes": "CWE-330",
            "security/detect-bidi-characters": "CWE-94",
        }

        return cwe_mapping.get(rule_id, "")
