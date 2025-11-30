"""
Archive management utilities for ttssecure.

Handles automatic archiving and cleanup of old security reports.
"""

import os
import shutil
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

from .logger import get_logger, LogMessages


def get_old_reports(
    base_dir: Path,
    retention_days: int = 30
) -> List[Path]:
    """
    Find report directories older than retention period.

    Args:
        base_dir: Base directory containing project reports
        retention_days: Number of days to retain reports

    Returns:
        List of paths to old report directories
    """
    logger = get_logger()
    base_dir = Path(base_dir)
    old_reports = []
    cutoff_date = datetime.now() - timedelta(days=retention_days)

    if not base_dir.exists():
        return old_reports

    # Structure: base_dir/PROJECT/BUILD_NUMBER/
    for project_dir in base_dir.iterdir():
        if not project_dir.is_dir():
            continue

        for build_dir in project_dir.iterdir():
            if not build_dir.is_dir():
                continue

            # Check modification time
            try:
                mtime = datetime.fromtimestamp(build_dir.stat().st_mtime)
                if mtime < cutoff_date:
                    old_reports.append(build_dir)
            except OSError as e:
                logger.warning(f"Could not stat {build_dir}: {e}")

    return old_reports


def archive_reports(
    reports: List[Path],
    archive_dir: Path,
    delete_after_archive: bool = True
) -> Tuple[int, List[str]]:
    """
    Archive old reports to compressed tar.gz files.

    Archives are organized by: archive_dir/PROJECT/YYYY-MM.tar.gz

    Args:
        reports: List of report directory paths to archive
        archive_dir: Destination directory for archives
        delete_after_archive: Whether to delete originals after archiving

    Returns:
        Tuple of (archived_count, list of archive paths created)
    """
    logger = get_logger()
    archive_dir = Path(archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)

    archived_count = 0
    archive_paths = []

    # Group reports by project and month
    # Structure: {project: {YYYY-MM: [paths]}}
    grouped: dict = {}

    for report_path in reports:
        # Extract project name from path: base_dir/PROJECT/BUILD_NUMBER
        project = report_path.parent.name

        # Get month from modification time
        mtime = datetime.fromtimestamp(report_path.stat().st_mtime)
        month_key = mtime.strftime("%Y-%m")

        if project not in grouped:
            grouped[project] = {}
        if month_key not in grouped[project]:
            grouped[project][month_key] = []

        grouped[project][month_key].append(report_path)

    # Create archives for each project/month combination
    for project, months in grouped.items():
        project_archive_dir = archive_dir / project
        project_archive_dir.mkdir(parents=True, exist_ok=True)

        for month, paths in months.items():
            archive_path = project_archive_dir / f"{month}.tar.gz"

            try:
                # Append to existing archive or create new
                mode = "a:gz" if archive_path.exists() else "w:gz"

                with tarfile.open(archive_path, mode) as tar:
                    for report_path in paths:
                        # Add directory to archive with relative path
                        arcname = f"{project}/{report_path.name}"
                        tar.add(report_path, arcname=arcname)
                        archived_count += 1

                        logger.info(f"Archived: {report_path} -> {archive_path}")

                        # Delete original if requested
                        if delete_after_archive:
                            shutil.rmtree(report_path)
                            logger.debug(f"Deleted: {report_path}")

                if str(archive_path) not in archive_paths:
                    archive_paths.append(str(archive_path))

            except Exception as e:
                logger.error(f"Failed to archive {paths}: {e}")

    return archived_count, archive_paths


def cleanup_old_archives(
    archive_dir: Path,
    max_archive_age_days: int = 365
) -> int:
    """
    Remove very old archives (over 1 year by default).

    Args:
        archive_dir: Directory containing archives
        max_archive_age_days: Maximum age for archives

    Returns:
        Number of archives deleted
    """
    logger = get_logger()
    archive_dir = Path(archive_dir)
    deleted_count = 0
    cutoff_date = datetime.now() - timedelta(days=max_archive_age_days)

    if not archive_dir.exists():
        return 0

    for archive_file in archive_dir.rglob("*.tar.gz"):
        try:
            mtime = datetime.fromtimestamp(archive_file.stat().st_mtime)
            if mtime < cutoff_date:
                archive_file.unlink()
                deleted_count += 1
                logger.info(f"Deleted old archive: {archive_file}")
        except OSError as e:
            logger.warning(f"Could not delete {archive_file}: {e}")

    return deleted_count


def run_archiver(
    reports_base_dir: Path,
    archive_dir: Path,
    retention_days: int = 30,
    delete_after_archive: bool = True
) -> dict:
    """
    Main archiver function - find and archive old reports.

    Args:
        reports_base_dir: Base directory for security reports
        archive_dir: Destination for archives
        retention_days: Days to retain reports before archiving
        delete_after_archive: Delete originals after archiving

    Returns:
        Dict with archiver statistics
    """
    logger = get_logger()
    logger.info(LogMessages.ARCHIVE_START.format(days=retention_days))

    # Find old reports
    old_reports = get_old_reports(reports_base_dir, retention_days)

    if not old_reports:
        logger.info("No reports to archive")
        return {
            "reports_found": 0,
            "archived_count": 0,
            "archive_paths": [],
        }

    logger.info(f"Found {len(old_reports)} report(s) to archive")

    # Archive them
    archived_count, archive_paths = archive_reports(
        old_reports,
        archive_dir,
        delete_after_archive
    )

    logger.info(LogMessages.ARCHIVE_COMPLETE.format(
        count=archived_count,
        path=archive_dir
    ))

    return {
        "reports_found": len(old_reports),
        "archived_count": archived_count,
        "archive_paths": archive_paths,
    }


def get_disk_usage(directory: Path) -> dict:
    """
    Get disk usage statistics for a directory.

    Args:
        directory: Path to check

    Returns:
        Dict with size information
    """
    directory = Path(directory)

    if not directory.exists():
        return {"total_bytes": 0, "total_mb": 0, "file_count": 0}

    total_bytes = 0
    file_count = 0

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            total_bytes += file_path.stat().st_size
            file_count += 1

    return {
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "file_count": file_count,
    }
