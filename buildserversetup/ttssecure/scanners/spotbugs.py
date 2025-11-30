"""
SpotBugs scanner implementation for ttssecure.

SpotBugs (with FindSecBugs plugin) performs static analysis on Java bytecode
to find security vulnerabilities.

Note: Requires compiled .class files, so must run after Maven/Gradle build.
"""

import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from scanners.base import BaseScanner, ScanResult, Finding, Severity
from utils.process import run_with_retry, check_tool_installed
from utils.logger import get_logger


class SpotBugsScanner(BaseScanner):
    """SpotBugs/FindSecBugs Java security scanner implementation."""

    name = "spotbugs"
    display_name = "SpotBugs + FindSecBugs"
    tool_command = "spotbugs"

    # Alternative commands to check
    alternative_commands = ["spotbugs", "findbugs"]

    # Security-related bug categories
    SECURITY_CATEGORIES = [
        "SECURITY", "MALICIOUS_CODE", "MT_CORRECTNESS",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.findsecbugs_plugin = kwargs.get("findsecbugs_plugin", None)

    def is_installed(self) -> bool:
        """Check if SpotBugs is installed."""
        for cmd in self.alternative_commands:
            if check_tool_installed(cmd):
                self.tool_command = cmd
                return True
        return False

    def scan(self, source_path: Path, output_dir: Path) -> ScanResult:
        """
        Execute SpotBugs scan on compiled Java bytecode.

        Args:
            source_path: Path to source code (looks for target/classes)
            output_dir: Directory to write raw output

        Returns:
            ScanResult with findings
        """
        logger = get_logger()
        start_time = time.time()

        # Check if installed
        if not self.is_installed():
            return self._create_error_result(
                "SpotBugs is not installed. Install with: sudo apt install spotbugs",
                time.time() - start_time
            )

        # Find compiled classes
        classes_dir = self._find_classes_dir(source_path)
        if not classes_dir:
            # Skip gracefully instead of failing - project not compiled yet
            logger.warning(f"[{self.name}] No compiled classes found. Run 'mvn compile' or 'gradle build' first. Skipping...")
            return ScanResult(
                scanner_name=self.name,
                success=True,  # Mark as success (skipped) not failure
                duration=time.time() - start_time,
                findings=[],
                scanner_version=self.get_version() or "unknown",
                error_message="Skipped: No compiled classes found. Run Maven/Gradle build first."
            )

        # Prepare output file
        output_file = output_dir / "spotbugs.xml"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        command = [
            self.tool_command,
            "-textui",
            "-xml:withMessages",
            "-effort:max",
            "-low",  # Report all bugs including low priority
            f"-output", str(output_file),
        ]

        # Add FindSecBugs plugin if available
        if self.findsecbugs_plugin and Path(self.findsecbugs_plugin).exists():
            command.extend(["-pluginList", self.findsecbugs_plugin])

        command.append(str(classes_dir))

        logger.info(f"[{self.name}] Running: {' '.join(command)}")

        # Execute with retry
        result, attempts = run_with_retry(
            command,
            cwd=source_path,
            timeout=self.timeout,
            max_retries=1
        )

        duration = time.time() - start_time

        # SpotBugs returns 0 even with findings
        if not output_file.exists():
            logger.error(f"[{self.name}] No output file generated")
            return self._create_error_result(
                f"SpotBugs did not generate output: {result.stderr[:200]}",
                duration
            )

        # Parse output
        try:
            findings = self.parse_output(output_file.read_text(encoding="utf-8"))

            # Also save as JSON for consistency
            json_output = output_dir / "spotbugs.json"
            with open(json_output, "w", encoding="utf-8") as f:
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

    def _find_classes_dir(self, source_path: Path) -> Optional[Path]:
        """Find compiled classes directory."""
        # Maven default
        maven_classes = source_path / "target" / "classes"
        if maven_classes.exists():
            return maven_classes

        # Gradle default
        gradle_classes = source_path / "build" / "classes" / "java" / "main"
        if gradle_classes.exists():
            return gradle_classes

        # Alternative Gradle location
        gradle_alt = source_path / "build" / "classes"
        if gradle_alt.exists():
            return gradle_alt

        return None

    def parse_output(self, output: str) -> List[Finding]:
        """
        Parse SpotBugs XML output into findings.

        Args:
            output: Raw XML output from SpotBugs

        Returns:
            List of Finding objects
        """
        findings = []

        try:
            root = ET.fromstring(output)

            for bug_instance in root.findall(".//BugInstance"):
                finding = self._parse_bug_instance(bug_instance)
                if finding:
                    findings.append(finding)

        except ET.ParseError as e:
            get_logger().error(f"[{self.name}] XML parse error: {e}")

        return findings

    def _parse_bug_instance(self, bug_element: ET.Element) -> Optional[Finding]:
        """Parse a single BugInstance element."""
        bug_type = bug_element.get("type", "unknown")
        category = bug_element.get("category", "")
        priority = int(bug_element.get("priority", "3"))

        # Get source location
        source_line = bug_element.find("SourceLine")
        file_path = ""
        line_number = 0
        end_line = 0

        if source_line is not None:
            file_path = source_line.get("sourcepath", "")
            line_number = int(source_line.get("start", "0"))
            end_line = int(source_line.get("end", "0"))

        # Get long message
        long_message = bug_element.find("LongMessage")
        description = long_message.text if long_message is not None else ""

        # Get short message
        short_message = bug_element.find("ShortMessage")
        title = short_message.text if short_message is not None else bug_type

        return Finding(
            rule_id=bug_type,
            title=title,
            severity=self._map_priority_to_severity(priority, category),
            scanner=self.name,
            file_path=file_path,
            line_number=line_number,
            end_line=end_line,
            description=description,
            recommendation=self._get_recommendation(bug_type, category),
            cwe_id=self._get_cwe_for_bug_type(bug_type),
            raw_data={
                "type": bug_type,
                "category": category,
                "priority": priority,
            }
        )

    def _map_priority_to_severity(self, priority: int, category: str) -> Severity:
        """Map SpotBugs priority to severity."""
        # Security category gets elevated severity
        is_security = category in self.SECURITY_CATEGORIES

        if priority == 1:  # High priority
            return Severity.CRITICAL if is_security else Severity.HIGH
        elif priority == 2:  # Normal priority
            return Severity.HIGH if is_security else Severity.MEDIUM
        else:  # Low priority
            return Severity.MEDIUM if is_security else Severity.LOW

    def _get_recommendation(self, bug_type: str, category: str) -> str:
        """Get recommendation for bug type."""
        recommendations = {
            "SQL_INJECTION": "Use parameterized queries or prepared statements",
            "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER": "Sanitize user input before output",
            "PATH_TRAVERSAL_IN": "Validate and sanitize file paths",
            "COMMAND_INJECTION": "Avoid executing system commands with user input",
            "LDAP_INJECTION": "Use LDAP parameterized queries",
            "XML_DECODER": "Disable external entities in XML parsers",
            "WEAK_MESSAGE_DIGEST_MD5": "Use SHA-256 or stronger hash algorithms",
            "WEAK_MESSAGE_DIGEST_SHA1": "Use SHA-256 or stronger hash algorithms",
            "CIPHER_INTEGRITY": "Use authenticated encryption modes (GCM)",
            "PREDICTABLE_RANDOM": "Use SecureRandom for security-sensitive operations",
        }

        return recommendations.get(
            bug_type,
            f"Review and fix the {category} issue according to secure coding guidelines"
        )

    def _get_cwe_for_bug_type(self, bug_type: str) -> str:
        """Map bug type to CWE ID."""
        cwe_mapping = {
            "SQL_INJECTION": "CWE-89",
            "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER": "CWE-79",
            "PATH_TRAVERSAL_IN": "CWE-22",
            "COMMAND_INJECTION": "CWE-78",
            "LDAP_INJECTION": "CWE-90",
            "XML_DECODER": "CWE-611",
            "WEAK_MESSAGE_DIGEST_MD5": "CWE-328",
            "WEAK_MESSAGE_DIGEST_SHA1": "CWE-328",
            "CIPHER_INTEGRITY": "CWE-327",
            "PREDICTABLE_RANDOM": "CWE-330",
        }
        return cwe_mapping.get(bug_type, "")
