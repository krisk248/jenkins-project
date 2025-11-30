"""
Process execution utilities for ttssecure.

Provides subprocess execution with timeout, retry logic, and error handling.
"""

import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple
import time

from .logger import get_logger


@dataclass
class CommandResult:
    """Result of a command execution."""

    success: bool
    stdout: str
    stderr: str
    return_code: int
    duration: float
    command: str


def run_command(
    command: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 600,
    capture_output: bool = True,
    env: Optional[dict] = None
) -> CommandResult:
    """
    Execute a command with timeout and capture output.

    Args:
        command: Command and arguments as list
        cwd: Working directory
        timeout: Timeout in seconds (default: 10 minutes)
        capture_output: Whether to capture stdout/stderr
        env: Environment variables to set

    Returns:
        CommandResult with execution details
    """
    logger = get_logger()
    cmd_str = " ".join(command)
    start_time = time.time()

    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            env=env
        )

        duration = time.time() - start_time

        return CommandResult(
            success=result.returncode == 0,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            return_code=result.returncode,
            duration=duration,
            command=cmd_str
        )

    except subprocess.TimeoutExpired as e:
        duration = time.time() - start_time
        logger.warning(f"Command timed out after {timeout}s: {cmd_str}")
        return CommandResult(
            success=False,
            stdout=e.stdout or "" if hasattr(e, "stdout") else "",
            stderr=f"Timeout after {timeout} seconds",
            return_code=-1,
            duration=duration,
            command=cmd_str
        )

    except FileNotFoundError:
        duration = time.time() - start_time
        logger.error(f"Command not found: {command[0]}")
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"Command not found: {command[0]}",
            return_code=-2,
            duration=duration,
            command=cmd_str
        )

    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Command failed with exception: {e}")
        return CommandResult(
            success=False,
            stdout="",
            stderr=str(e),
            return_code=-3,
            duration=duration,
            command=cmd_str
        )


def run_with_retry(
    command: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 600,
    max_retries: int = 1,
    retry_delay: float = 2.0,
    env: Optional[dict] = None
) -> Tuple[CommandResult, int]:
    """
    Execute a command with retry logic.

    Args:
        command: Command and arguments as list
        cwd: Working directory
        timeout: Timeout in seconds
        max_retries: Maximum number of retry attempts (default: 1)
        retry_delay: Delay between retries in seconds
        env: Environment variables

    Returns:
        Tuple of (CommandResult, attempts_made)
    """
    logger = get_logger()
    cmd_name = command[0] if command else "unknown"
    attempts = 0

    for attempt in range(max_retries + 1):
        attempts += 1

        if attempt > 0:
            logger.info(f"[{cmd_name}] Retrying (attempt {attempt + 1}/{max_retries + 1})...")
            time.sleep(retry_delay)

        result = run_command(command, cwd=cwd, timeout=timeout, env=env)

        if result.success:
            return result, attempts

        if attempt < max_retries:
            logger.warning(f"[{cmd_name}] Attempt {attempt + 1} failed: {result.stderr[:100]}")

    return result, attempts


def check_tool_installed(tool_name: str) -> bool:
    """
    Check if a tool is installed and available in PATH.

    Args:
        tool_name: Name of the tool/command

    Returns:
        True if tool is installed, False otherwise
    """
    return shutil.which(tool_name) is not None


def get_tool_version(tool_name: str, version_flag: str = "--version") -> Optional[str]:
    """
    Get the version of an installed tool.

    Args:
        tool_name: Name of the tool
        version_flag: Flag to get version (default: --version)

    Returns:
        Version string or None if not available
    """
    if not check_tool_installed(tool_name):
        return None

    result = run_command([tool_name, version_flag], timeout=10)

    if result.success:
        # Return first line of version output
        return result.stdout.strip().split("\n")[0]

    return None


def parse_json_output(result: CommandResult) -> Optional[dict]:
    """
    Parse JSON from command output.

    Args:
        result: CommandResult from command execution

    Returns:
        Parsed JSON dict or None if parsing fails
    """
    import json

    try:
        # Try stdout first
        if result.stdout.strip():
            return json.loads(result.stdout)

        # Some tools output to stderr
        if result.stderr.strip() and result.stderr.strip().startswith("{"):
            return json.loads(result.stderr)

        return None

    except json.JSONDecodeError:
        return None
