"""
Logging configuration for ttssecure.

Provides dual output: console (colored) and file logging.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color codes for console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",      # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]

        # Add color to levelname
        original_levelname = record.levelname
        record.levelname = f"{color}{record.levelname}{reset}"

        result = super().format(record)
        record.levelname = original_levelname
        return result


class TTSLogger:
    """Logger manager for ttssecure module."""

    _instance: Optional["TTSLogger"] = None
    _logger: Optional[logging.Logger] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def setup(
        cls,
        log_file: Optional[Path] = None,
        level: str = "INFO",
        name: str = "ttssecure"
    ) -> logging.Logger:
        """
        Set up logging with console and optional file output.

        Args:
            log_file: Path to log file. If None, only console logging.
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            name: Logger name

        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))

        # Clear existing handlers
        logger.handlers.clear()

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_format = ColoredFormatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)

        # File handler (plain text, no colors)
        if log_file:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)

        cls._logger = logger
        return logger

    @classmethod
    def get(cls, name: str = "ttssecure") -> logging.Logger:
        """Get the logger instance."""
        if cls._logger is None:
            return cls.setup(name=name)
        return cls._logger


def setup_logger(
    log_file: Optional[Path] = None,
    level: str = "INFO",
    name: str = "ttssecure"
) -> logging.Logger:
    """
    Convenience function to set up logging.

    Args:
        log_file: Path to log file
        level: Logging level
        name: Logger name

    Returns:
        Configured logger
    """
    return TTSLogger.setup(log_file=log_file, level=level, name=name)


def get_logger(name: str = "ttssecure") -> logging.Logger:
    """
    Get the logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return TTSLogger.get(name=name)


# Log message templates for consistent formatting
class LogMessages:
    """Predefined log message templates."""

    # Startup
    SCAN_START = "Starting security scan for project: {project}"
    SCAN_COMPLETE = "Security scan completed in {duration:.2f}s"

    # Scanner operations
    SCANNER_START = "[{scanner}] Starting scan..."
    SCANNER_COMPLETE = "[{scanner}] Completed in {duration:.2f}s - Found {count} findings"
    SCANNER_SKIP = "[{scanner}] Skipped - {reason}"
    SCANNER_FAIL = "[{scanner}] Failed - {error}"
    SCANNER_RETRY = "[{scanner}] Retrying (attempt {attempt})..."
    SCANNER_NOT_INSTALLED = "[{scanner}] Not installed, skipping"

    # Report generation
    REPORT_START = "Generating {format} report..."
    REPORT_COMPLETE = "Report generated: {path}"
    REPORT_FAIL = "Failed to generate {format} report: {error}"

    # Threshold checks
    THRESHOLD_PASS = "All thresholds passed"
    THRESHOLD_FAIL = "Threshold exceeded: {finding_type} ({count} > {max})"

    # Archive operations
    ARCHIVE_START = "Archiving reports older than {days} days"
    ARCHIVE_COMPLETE = "Archived {count} report(s) to {path}"
