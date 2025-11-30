"""Report generation modules for ttssecure."""

from .aggregator import aggregate_results, AggregatedResults
from .pdf_generator import generate_pdf_report
from .html_generator import generate_html_report
from .json_generator import generate_json_report

__all__ = [
    "aggregate_results",
    "AggregatedResults",
    "generate_pdf_report",
    "generate_html_report",
    "generate_json_report",
]
