"""
JSON report generator for ttssecure.

Generates machine-readable JSON summary of scan results.
"""

import json
from pathlib import Path

from .aggregator import AggregatedResults
from ..utils.logger import get_logger


def generate_json_report(
    results: AggregatedResults,
    output_path: Path,
    pretty_print: bool = True
) -> Path:
    """
    Generate JSON summary report.

    Args:
        results: Aggregated scan results
        output_path: Path for output JSON file

    Returns:
        Path to generated JSON file
    """
    logger = get_logger()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = results.to_dict()

        with open(output_path, "w", encoding="utf-8") as f:
            if pretty_print:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)

        logger.info(f"JSON report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to generate JSON report: {e}")
        raise
