#!/usr/bin/env python3
"""
TTS Security Scanning Module - Main Entry Point

Usage:
    ttssecure.py --config project.yaml --branch develop --build-number 42

This is the main orchestrator that:
1. Loads configuration from YAML
2. Runs enabled security scanners
3. Aggregates results
4. Generates PDF, HTML, and JSON reports
5. Returns appropriate exit code based on thresholds
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import load_config, merge_cli_args, Config
from config.validator import validate_config, print_validation_errors
from utils.logger import setup_logger, get_logger, LogMessages
from utils.detector import detect_project_type, get_git_info
from scanners import SCANNER_REGISTRY
from scanners.base import ScanResult
from reports import (
    aggregate_results,
    generate_pdf_report,
    generate_html_report,
    generate_json_report,
)
from reports.aggregator import check_thresholds


# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_THRESHOLD_EXCEEDED = 2
EXIT_PARTIAL_FAILURE = 3


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="TTS Security Scanning Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with config file
  ttssecure.py --config configs/adxsip-backend.yaml

  # Scan with CLI overrides
  ttssecure.py --config configs/adxsip-backend.yaml --branch develop --build-number 42

  # Skip certain scanners
  ttssecure.py --config configs/adxsip-backend.yaml --skip trivy,spotbugs

  # Verbose output
  ttssecure.py --config configs/adxsip-backend.yaml --verbose

Exit Codes:
  0 - Success, all thresholds passed
  1 - Error (configuration, missing files, etc.)
  2 - Threshold exceeded
  3 - Partial failure (some scanners failed but report generated)
        """
    )

    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to project YAML configuration file"
    )

    parser.add_argument(
        "--branch", "-b",
        help="Git branch name (overrides config)"
    )

    parser.add_argument(
        "--build-number", "-n",
        help="Jenkins build number (default: timestamp)"
    )

    parser.add_argument(
        "--skip",
        help="Comma-separated list of scanners to skip"
    )

    parser.add_argument(
        "--output-dir", "-o",
        help="Override output directory"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be executed without running"
    )

    parser.add_argument(
        "--archive",
        action="store_true",
        help="Run archiver to compress old reports"
    )

    return parser.parse_args()


def run_scanners(config: Config, output_dir: Path) -> List[ScanResult]:
    """
    Run all enabled security scanners.

    Args:
        config: Loaded configuration
        output_dir: Directory for raw scanner outputs

    Returns:
        List of ScanResult from each scanner
    """
    logger = get_logger()
    results: List[ScanResult] = []
    source_path = Path(config.source.path)
    raw_output_dir = output_dir / "raw"
    raw_output_dir.mkdir(parents=True, exist_ok=True)

    # Detect project type if auto
    project_info = None
    if config.project.project_type == "auto":
        project_info = detect_project_type(source_path)
        logger.info(f"Detected project type: {project_info.project_type}")

    # Determine which scanners to run
    scanner_order = [
        "semgrep",
        "trivy",
        "trufflehog",
        "spotbugs",
        "owasp_dependency",
        "eslint_security",
    ]

    for scanner_name in scanner_order:
        # Check if scanner is enabled
        if not config.is_scanner_enabled(scanner_name):
            logger.info(f"[{scanner_name}] Skipped (disabled or in skip list)")
            continue

        # Check if scanner is appropriate for project type
        if project_info and scanner_name not in project_info.recommended_scanners:
            # Java-only scanners
            if scanner_name == "spotbugs" and project_info.project_type not in ["maven", "gradle"]:
                logger.info(f"[{scanner_name}] Skipped (not applicable for {project_info.project_type})")
                continue

            # JS/TS-only scanners
            if scanner_name == "eslint_security" and project_info.language not in ["javascript", "typescript"]:
                logger.info(f"[{scanner_name}] Skipped (not applicable for {project_info.language})")
                continue

        # Get scanner class and config
        scanner_class = SCANNER_REGISTRY.get(scanner_name)
        if not scanner_class:
            logger.warning(f"[{scanner_name}] Scanner not found in registry")
            continue

        scanner_config = config.scanners.get(scanner_name)

        # Create scanner instance
        scanner = scanner_class(
            timeout=scanner_config.timeout if scanner_config else 600,
            config=scanner_config.config if scanner_config else "auto",
            severity_filter=scanner_config.severity if scanner_config else "CRITICAL,HIGH,MEDIUM,LOW",
            max_findings=scanner_config.max_findings if scanner_config else 100,
            include_paths=config.source.include_paths,
            exclude_paths=config.source.exclude_paths,
        )

        # Check if installed
        if not scanner.is_installed():
            logger.warning(LogMessages.SCANNER_NOT_INSTALLED.format(scanner=scanner_name))
            continue

        # Run scanner
        logger.info(LogMessages.SCANNER_START.format(scanner=scanner_name))
        start_time = time.time()

        try:
            result = scanner.scan(source_path, raw_output_dir)
            duration = time.time() - start_time

            logger.info(LogMessages.SCANNER_COMPLETE.format(
                scanner=scanner_name,
                duration=duration,
                count=result.total_findings
            ))

            results.append(result)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(LogMessages.SCANNER_FAIL.format(
                scanner=scanner_name,
                error=str(e)
            ))

            # Add failed result
            results.append(ScanResult(
                scanner_name=scanner_name,
                success=False,
                duration=duration,
                error_message=str(e),
            ))

    return results


def main() -> int:
    """Main entry point."""
    start_time = time.time()
    args = parse_arguments()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"

    try:
        # Load configuration
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}")
            return EXIT_ERROR

        config = load_config(config_path)

        # Merge CLI arguments
        cli_args = {
            "branch": args.branch,
            "build_number": args.build_number or datetime.now().strftime("%H%M%S"),
            "skip": args.skip,
            "output_dir": args.output_dir,
        }
        config = merge_cli_args(config, cli_args)

        # Validate configuration
        is_valid, errors = validate_config(config)
        if not is_valid:
            print("Configuration validation failed:")
            print_validation_errors(errors)
            return EXIT_ERROR

        # Print warnings
        warnings = [e for e in errors if e.severity == "warning"]
        if warnings:
            print("Configuration warnings:")
            print_validation_errors(warnings)

        # Setup output directory
        output_dir = config.get_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Setup logger with file output
        log_file = output_dir / "scan.log"
        logger = setup_logger(log_file=log_file, level=log_level)

        logger.info(LogMessages.SCAN_START.format(project=config.project.name))
        logger.info(f"Configuration: {config_path}")
        logger.info(f"Output directory: {output_dir}")

        # Dry run mode
        if args.dry_run:
            logger.info("DRY RUN MODE - showing what would be executed")
            logger.info(f"Project: {config.project.name}")
            logger.info(f"Component: {config.project.component}")
            logger.info(f"Source: {config.source.path}")
            logger.info(f"Branch: {config.get_effective_branch()}")

            enabled_scanners = [
                name for name, scanner in config.scanners.items()
                if scanner.enabled and name not in config.skip_scanners
            ]
            logger.info(f"Scanners to run: {', '.join(enabled_scanners)}")
            return EXIT_SUCCESS

        # Archive mode
        if args.archive:
            from utils.archiver import run_archiver
            result = run_archiver(
                Path(config.output.base_dir),
                Path(config.output.archive_dir),
                config.output.retention_days,
            )
            logger.info(f"Archived {result['archived_count']} reports")
            return EXIT_SUCCESS

        # Get git info
        git_info = get_git_info(Path(config.source.path))
        if not config.branch:
            config.branch = git_info.get("branch", config.source.default_branch)

        # Run scanners
        scan_results = run_scanners(config, output_dir)

        # Check if any scanners ran
        if not scan_results:
            logger.error("No scanners executed successfully")
            return EXIT_ERROR

        # Aggregate results
        report_id = config.get_report_id()

        aggregated = aggregate_results(
            scan_results=scan_results,
            report_id=report_id,
            project_name=config.project.name,
            component_name=config.project.component,
            git_url=config.source.git_url or git_info.get("url", ""),
            git_branch=config.get_effective_branch(),
            qa_url=config.metadata.qa_url,
            build_number=config.build_number,
            developer_team=config.metadata.developer_team,
            developer_contact=config.metadata.developer_contact,
            devsecops_contact=config.metadata.devsecops_contact,
        )

        # Check thresholds
        aggregated = check_thresholds(
            aggregated,
            max_critical=config.threshold.max_critical,
            max_high=config.threshold.max_high,
            max_medium=config.threshold.max_medium,
            max_low=config.threshold.max_low,
            fail_on_secrets=config.threshold.fail_on_secrets,
        )

        # Generate reports
        logger.info("Generating reports...")

        # Find logo
        logo_path = Path(__file__).parent / "assets" / "logo.png"
        if not logo_path.exists():
            logo_path = None

        # Track which reports were generated successfully
        generated_reports = {}

        # PDF Report
        pdf_path = output_dir / f"{report_id}.pdf"
        try:
            generate_pdf_report(aggregated, pdf_path, logo_path)
            logger.info(LogMessages.REPORT_COMPLETE.format(path=pdf_path))
            generated_reports['PDF'] = pdf_path
        except Exception as e:
            logger.error(LogMessages.REPORT_FAIL.format(format="PDF", error=str(e)))

        # HTML Report
        html_path = output_dir / f"{report_id}.html"
        try:
            generate_html_report(aggregated, html_path, logo_path)
            logger.info(LogMessages.REPORT_COMPLETE.format(path=html_path))
            generated_reports['HTML'] = html_path
        except Exception as e:
            logger.error(LogMessages.REPORT_FAIL.format(format="HTML", error=str(e)))

        # JSON Report
        json_path = output_dir / f"{report_id}.json"
        try:
            generate_json_report(aggregated, json_path)
            logger.info(LogMessages.REPORT_COMPLETE.format(path=json_path))
            generated_reports['JSON'] = json_path
        except Exception as e:
            logger.error(LogMessages.REPORT_FAIL.format(format="JSON", error=str(e)))

        # Summary
        duration = time.time() - start_time
        logger.info(LogMessages.SCAN_COMPLETE.format(duration=duration))

        stats = aggregated.statistics
        logger.info(f"Total findings: {stats.total_findings}")
        logger.info(f"  CRITICAL: {stats.critical_count}")
        logger.info(f"  HIGH: {stats.high_count}")
        logger.info(f"  MEDIUM: {stats.medium_count}")
        logger.info(f"  LOW: {stats.low_count}")
        logger.info(f"Risk level: {stats.risk_level} (score: {stats.risk_score})")

        # Output report paths for Jenkins (only show successfully generated reports)
        print(f"\n=== REPORT PATHS ===")
        for report_type, report_path in generated_reports.items():
            print(f"{report_type}: {report_path}")
        print(f"LOG: {log_file}")
        if len(generated_reports) < 3:
            failed_reports = [r for r in ['PDF', 'HTML', 'JSON'] if r not in generated_reports]
            print(f"FAILED: {', '.join(failed_reports)}")
        print(f"===================")

        # Determine exit code
        if aggregated.statistics.scanners_failed > 0:
            logger.warning(f"{aggregated.statistics.scanners_failed} scanner(s) failed")

            # If all scanners failed, return error
            if aggregated.statistics.scanners_failed == aggregated.statistics.scanners_run:
                return EXIT_ERROR

            return EXIT_PARTIAL_FAILURE

        if not aggregated.passed_thresholds:
            logger.warning("Threshold check FAILED")
            for violation in aggregated.threshold_violations:
                logger.warning(f"  {violation}")
            return EXIT_THRESHOLD_EXCEEDED

        logger.info(LogMessages.THRESHOLD_PASS)
        return EXIT_SUCCESS

    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
