"""
Project type detection utilities for ttssecure.

Auto-detects project type based on configuration files.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict
import json
import re

from .logger import get_logger


@dataclass
class ProjectInfo:
    """Information about a detected project."""

    project_type: str  # maven, angular, gulp, nodejs, python, unknown
    detected_files: List[str]
    build_tool: Optional[str]
    language: str
    framework: Optional[str]
    recommended_scanners: List[str]


# Project detection configuration
PROJECT_SIGNATURES = {
    "maven": {
        "files": ["pom.xml"],
        "language": "java",
        "build_tool": "maven",
        "scanners": ["semgrep", "trivy", "trufflehog", "spotbugs", "owasp_dependency"],
    },
    "gradle": {
        "files": ["build.gradle", "build.gradle.kts"],
        "language": "java",
        "build_tool": "gradle",
        "scanners": ["semgrep", "trivy", "trufflehog", "spotbugs", "owasp_dependency"],
    },
    "angular": {
        "files": ["angular.json"],
        "language": "typescript",
        "build_tool": "npm",
        "framework": "angular",
        "scanners": ["semgrep", "trivy", "trufflehog", "eslint_security"],
    },
    "gulp": {
        "files": ["gulpfile.js", "gulpfile.babel.js", "gulpfile.ts"],
        "language": "javascript",
        "build_tool": "gulp",
        "scanners": ["semgrep", "trivy", "trufflehog", "eslint_security"],
    },
    "nodejs": {
        "files": ["package.json"],
        "language": "javascript",
        "build_tool": "npm",
        "scanners": ["semgrep", "trivy", "trufflehog", "eslint_security"],
    },
    "python": {
        "files": ["requirements.txt", "pyproject.toml", "setup.py"],
        "language": "python",
        "build_tool": "pip",
        "scanners": ["semgrep", "trivy", "trufflehog", "bandit"],
    },
}


def detect_project_type(source_path: Path) -> ProjectInfo:
    """
    Detect project type based on configuration files.

    Args:
        source_path: Path to source code directory

    Returns:
        ProjectInfo with detected project details
    """
    logger = get_logger()
    source_path = Path(source_path)

    if not source_path.exists():
        logger.warning(f"Source path does not exist: {source_path}")
        return ProjectInfo(
            project_type="unknown",
            detected_files=[],
            build_tool=None,
            language="unknown",
            framework=None,
            recommended_scanners=["semgrep", "trivy", "trufflehog"],
        )

    detected_files = []

    # Check each project type in priority order
    # Angular before nodejs (angular.json is more specific than package.json)
    priority_order = ["maven", "gradle", "angular", "gulp", "python", "nodejs"]

    for project_type in priority_order:
        config = PROJECT_SIGNATURES[project_type]

        for signature_file in config["files"]:
            check_path = source_path / signature_file

            if check_path.exists():
                detected_files.append(signature_file)
                logger.info(f"Detected project type: {project_type} (found {signature_file})")

                return ProjectInfo(
                    project_type=project_type,
                    detected_files=detected_files,
                    build_tool=config.get("build_tool"),
                    language=config["language"],
                    framework=config.get("framework"),
                    recommended_scanners=config["scanners"],
                )

    logger.warning(f"Could not detect project type for: {source_path}")
    return ProjectInfo(
        project_type="unknown",
        detected_files=[],
        build_tool=None,
        language="unknown",
        framework=None,
        recommended_scanners=["semgrep", "trivy", "trufflehog"],
    )


def get_project_metadata(source_path: Path) -> Dict:
    """
    Extract project metadata from configuration files.

    Args:
        source_path: Path to source code directory

    Returns:
        Dict with project metadata (name, version, description)
    """
    source_path = Path(source_path)
    metadata = {
        "name": source_path.name,
        "version": "unknown",
        "description": "",
    }

    # Try pom.xml (Maven)
    pom_path = source_path / "pom.xml"
    if pom_path.exists():
        metadata.update(_parse_pom_xml(pom_path))
        return metadata

    # Try package.json (Node.js/Angular/Gulp)
    package_path = source_path / "package.json"
    if package_path.exists():
        metadata.update(_parse_package_json(package_path))
        return metadata

    # Try pyproject.toml (Python)
    pyproject_path = source_path / "pyproject.toml"
    if pyproject_path.exists():
        metadata.update(_parse_pyproject_toml(pyproject_path))
        return metadata

    return metadata


def _parse_pom_xml(pom_path: Path) -> Dict:
    """Parse Maven pom.xml for project metadata."""
    try:
        content = pom_path.read_text(encoding="utf-8")

        metadata = {}

        # Extract artifactId
        match = re.search(r"<artifactId>([^<]+)</artifactId>", content)
        if match:
            metadata["name"] = match.group(1)

        # Extract version
        match = re.search(r"<version>([^<]+)</version>", content)
        if match:
            metadata["version"] = match.group(1)

        # Extract description
        match = re.search(r"<description>([^<]+)</description>", content)
        if match:
            metadata["description"] = match.group(1)

        return metadata

    except Exception:
        return {}


def _parse_package_json(package_path: Path) -> Dict:
    """Parse Node.js package.json for project metadata."""
    try:
        content = json.loads(package_path.read_text(encoding="utf-8"))

        return {
            "name": content.get("name", ""),
            "version": content.get("version", "unknown"),
            "description": content.get("description", ""),
        }

    except Exception:
        return {}


def _parse_pyproject_toml(pyproject_path: Path) -> Dict:
    """Parse Python pyproject.toml for project metadata."""
    try:
        content = pyproject_path.read_text(encoding="utf-8")
        metadata = {}

        # Simple regex parsing (avoid toml dependency)
        match = re.search(r'name\s*=\s*"([^"]+)"', content)
        if match:
            metadata["name"] = match.group(1)

        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        if match:
            metadata["version"] = match.group(1)

        match = re.search(r'description\s*=\s*"([^"]+)"', content)
        if match:
            metadata["description"] = match.group(1)

        return metadata

    except Exception:
        return {}


def get_git_info(source_path: Path) -> Dict:
    """
    Get git repository information.

    Args:
        source_path: Path to git repository

    Returns:
        Dict with git info (url, branch, commit, author)
    """
    from .process import run_command

    source_path = Path(source_path)
    git_info = {
        "url": "",
        "branch": "",
        "commit": "",
        "author": "",
    }

    # Get remote URL
    result = run_command(
        ["git", "remote", "get-url", "origin"],
        cwd=source_path,
        timeout=10
    )
    if result.success:
        git_info["url"] = result.stdout.strip()

    # Get current branch
    result = run_command(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=source_path,
        timeout=10
    )
    if result.success:
        git_info["branch"] = result.stdout.strip()

    # Get latest commit hash
    result = run_command(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=source_path,
        timeout=10
    )
    if result.success:
        git_info["commit"] = result.stdout.strip()

    # Get last commit author
    result = run_command(
        ["git", "log", "-1", "--format=%an"],
        cwd=source_path,
        timeout=10
    )
    if result.success:
        git_info["author"] = result.stdout.strip()

    return git_info
