"""
Configuration loader for ttssecure.

Loads YAML configuration and merges with CLI arguments.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
import yaml


@dataclass
class ScannerConfig:
    """Configuration for individual scanner."""

    enabled: bool = True
    config: str = "auto"
    severity: str = "CRITICAL,HIGH,MEDIUM,LOW"
    max_findings: int = 100
    timeout: int = 600  # 10 minutes


@dataclass
class ThresholdConfig:
    """Threshold configuration for build pass/fail."""

    max_critical: int = 0
    max_high: int = 10
    max_medium: int = 50
    max_low: int = 100
    fail_on_secrets: bool = True


@dataclass
class OutputConfig:
    """Output configuration."""

    base_dir: str = "/tts/securityreports"
    archive_dir: str = "/tts/archive/security"
    retention_days: int = 30


@dataclass
class MetadataConfig:
    """Project metadata configuration."""

    developer_team: str = ""
    developer_contact: str = ""
    devsecops_contact: str = ""
    qa_url: str = ""


@dataclass
class SourceConfig:
    """Source code configuration."""

    path: str = ""
    git_url: str = ""
    default_branch: str = "main"


@dataclass
class ProjectConfig:
    """Project identification configuration."""

    name: str = ""
    component: str = ""
    project_type: str = "auto"  # auto, maven, angular, gulp


@dataclass
class NotificationConfig:
    """Notification configuration."""

    emails: List[str] = field(default_factory=list)


@dataclass
class Config:
    """Main configuration class."""

    project: ProjectConfig = field(default_factory=ProjectConfig)
    source: SourceConfig = field(default_factory=SourceConfig)
    metadata: MetadataConfig = field(default_factory=MetadataConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)

    # Scanner configurations
    scanners: Dict[str, ScannerConfig] = field(default_factory=dict)

    # CLI overrides (set at runtime)
    branch: str = ""
    build_number: str = ""
    skip_scanners: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Initialize default scanners if not set."""
        default_scanners = [
            "semgrep", "trivy", "trufflehog",
            "spotbugs", "owasp_dependency", "eslint_security"
        ]
        for scanner in default_scanners:
            if scanner not in self.scanners:
                self.scanners[scanner] = ScannerConfig()

    def get_report_id(self) -> str:
        """
        Generate unique report ID.

        Format: TTS_SEC_{PROJECT}_{QA}{BUILD}-{MMDDYY}
        """
        from datetime import datetime

        project = self.project.name.upper()
        build = self.build_number or datetime.now().strftime("%H%M%S")
        date = datetime.now().strftime("%m%d%y")

        return f"TTS_SEC_{project}_QA{build}-{date}"

    def get_output_dir(self) -> Path:
        """Get output directory for this scan."""
        return Path(self.output.base_dir) / self.project.name / self.build_number

    def get_effective_branch(self) -> str:
        """Get branch (CLI override or config default)."""
        return self.branch or self.source.default_branch

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled and not skipped."""
        if scanner_name in self.skip_scanners:
            return False

        scanner = self.scanners.get(scanner_name)
        if scanner is None:
            return False

        return scanner.enabled


def load_config(config_path: Path) -> Config:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        Config object with loaded values
    """
    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return _parse_config(data)


def _parse_config(data: Dict[str, Any]) -> Config:
    """Parse YAML data into Config object."""
    config = Config()

    # Parse project section
    if "project" in data:
        proj = data["project"]
        config.project = ProjectConfig(
            name=proj.get("name", ""),
            component=proj.get("component", ""),
            project_type=proj.get("type", "auto"),
        )

    # Parse source section
    if "source" in data:
        src = data["source"]
        config.source = SourceConfig(
            path=_expand_path(src.get("path", "")),
            git_url=src.get("git_url", ""),
            default_branch=src.get("default_branch", "main"),
        )

    # Parse metadata section
    if "metadata" in data:
        meta = data["metadata"]
        config.metadata = MetadataConfig(
            developer_team=meta.get("developer_team", ""),
            developer_contact=meta.get("developer_contact", ""),
            devsecops_contact=meta.get("devsecops_contact", ""),
            qa_url=meta.get("qa_url", ""),
        )

    # Parse output section
    if "output" in data:
        out = data["output"]
        config.output = OutputConfig(
            base_dir=_expand_path(out.get("base_dir", "/tts/securityreports")),
            archive_dir=_expand_path(out.get("archive_dir", "/tts/archive/security")),
            retention_days=out.get("retention_days", 30),
        )

    # Parse threshold section
    if "threshold" in data:
        thresh = data["threshold"]
        config.threshold = ThresholdConfig(
            max_critical=thresh.get("max_critical", 0),
            max_high=thresh.get("max_high", 10),
            max_medium=thresh.get("max_medium", 50),
            max_low=thresh.get("max_low", 100),
            fail_on_secrets=thresh.get("fail_on_secrets", True),
        )

    # Parse notifications section
    if "notifications" in data:
        notif = data["notifications"]
        config.notifications = NotificationConfig(
            emails=notif.get("emails", []),
        )

    # Parse scanners section
    if "scanners" in data:
        for scanner_name, scanner_data in data["scanners"].items():
            if isinstance(scanner_data, dict):
                config.scanners[scanner_name] = ScannerConfig(
                    enabled=scanner_data.get("enabled", True),
                    config=scanner_data.get("config", "auto"),
                    severity=scanner_data.get("severity", "CRITICAL,HIGH,MEDIUM,LOW"),
                    max_findings=scanner_data.get("max_findings", 100),
                    timeout=scanner_data.get("timeout", 600),
                )

    return config


def merge_cli_args(config: Config, args: dict) -> Config:
    """
    Merge CLI arguments into config.

    CLI arguments take precedence over config file values.

    Args:
        config: Loaded config object
        args: CLI arguments dict

    Returns:
        Updated config
    """
    if args.get("branch"):
        config.branch = args["branch"]

    if args.get("build_number"):
        config.build_number = args["build_number"]

    if args.get("skip"):
        config.skip_scanners = [s.strip() for s in args["skip"].split(",")]

    if args.get("output_dir"):
        config.output.base_dir = args["output_dir"]

    return config


def _expand_path(path: str) -> str:
    """Expand environment variables and user home in path."""
    if not path:
        return path
    return os.path.expandvars(os.path.expanduser(path))
