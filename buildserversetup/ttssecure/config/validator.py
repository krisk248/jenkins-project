"""
Configuration validator for ttssecure.

Validates configuration and reports errors.
"""

from pathlib import Path
from typing import List, Tuple

from .loader import Config


class ValidationError:
    """Represents a validation error."""

    def __init__(self, field: str, message: str, severity: str = "error"):
        self.field = field
        self.message = message
        self.severity = severity  # error, warning

    def __str__(self):
        return f"[{self.severity.upper()}] {self.field}: {self.message}"


def validate_config(config: Config) -> Tuple[bool, List[ValidationError]]:
    """
    Validate configuration.

    Args:
        config: Config object to validate

    Returns:
        Tuple of (is_valid, list of errors)
    """
    errors: List[ValidationError] = []

    # Required fields
    if not config.project.name:
        errors.append(ValidationError(
            "project.name",
            "Project name is required"
        ))

    if not config.source.path:
        errors.append(ValidationError(
            "source.path",
            "Source path is required"
        ))
    elif not Path(config.source.path).exists():
        errors.append(ValidationError(
            "source.path",
            f"Source path does not exist: {config.source.path}"
        ))

    # Validate output directories
    output_base = Path(config.output.base_dir)
    if not output_base.parent.exists():
        errors.append(ValidationError(
            "output.base_dir",
            f"Parent directory does not exist: {output_base.parent}",
            severity="warning"
        ))

    # Validate threshold values
    if config.threshold.max_critical < 0:
        errors.append(ValidationError(
            "threshold.max_critical",
            "max_critical must be >= 0"
        ))

    if config.threshold.max_high < 0:
        errors.append(ValidationError(
            "threshold.max_high",
            "max_high must be >= 0"
        ))

    # Validate retention days
    if config.output.retention_days < 1:
        errors.append(ValidationError(
            "output.retention_days",
            "retention_days must be >= 1",
            severity="warning"
        ))

    # Validate email format (basic check)
    for email in config.notifications.emails:
        if "@" not in email:
            errors.append(ValidationError(
                "notifications.emails",
                f"Invalid email format: {email}",
                severity="warning"
            ))

    # Validate project type
    valid_types = ["auto", "maven", "gradle", "angular", "gulp", "nodejs", "python"]
    if config.project.project_type not in valid_types:
        errors.append(ValidationError(
            "project.type",
            f"Invalid project type: {config.project.project_type}. "
            f"Valid types: {', '.join(valid_types)}"
        ))

    # Check if at least one scanner is enabled
    enabled_scanners = [
        name for name, scanner in config.scanners.items()
        if scanner.enabled and name not in config.skip_scanners
    ]
    if not enabled_scanners:
        errors.append(ValidationError(
            "scanners",
            "At least one scanner must be enabled"
        ))

    # Determine validity (only errors, not warnings)
    is_valid = not any(e.severity == "error" for e in errors)

    return is_valid, errors


def print_validation_errors(errors: List[ValidationError]) -> None:
    """Print validation errors to console."""
    for error in errors:
        prefix = "ERROR" if error.severity == "error" else "WARNING"
        print(f"  {prefix}: {error.field} - {error.message}")
