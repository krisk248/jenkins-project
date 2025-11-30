"""
HTML report generator for ttssecure.

Generates web-viewable HTML report with styling.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List

from .aggregator import AggregatedResults
from ..scanners.base import Finding, Severity
from ..utils.logger import get_logger


def generate_html_report(
    results: AggregatedResults,
    output_path: Path,
) -> Path:
    """
    Generate HTML report.

    Args:
        results: Aggregated scan results
        output_path: Path for output HTML file

    Returns:
        Path to generated HTML file
    """
    logger = get_logger()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        html_content = _build_html(results)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        raise


def _build_html(results: AggregatedResults) -> str:
    """Build HTML content."""
    stats = results.statistics

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {results.report_id}</title>
    <style>
        {_get_css()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="logo-section">
                <h1>TTS Security Assessment Report</h1>
            </div>
            <div class="report-id">
                <strong>Report ID:</strong> {results.report_id}
            </div>
        </header>

        <!-- Metadata Section -->
        <section class="metadata-section">
            <h2>Report Information</h2>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <label>Project:</label>
                    <span>{results.project_name}</span>
                </div>
                <div class="metadata-item">
                    <label>Component:</label>
                    <span>{results.component_name}</span>
                </div>
                <div class="metadata-item">
                    <label>Git URL:</label>
                    <span><a href="{results.git_url}">{results.git_url}</a></span>
                </div>
                <div class="metadata-item">
                    <label>Branch:</label>
                    <span>{results.git_branch}</span>
                </div>
                <div class="metadata-item">
                    <label>QA URL:</label>
                    <span><a href="{results.qa_url}">{results.qa_url}</a></span>
                </div>
                <div class="metadata-item">
                    <label>Jenkins Build:</label>
                    <span>#{results.build_number}</span>
                </div>
                <div class="metadata-item">
                    <label>Scan Date:</label>
                    <span>{results.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S")}</span>
                </div>
                <div class="metadata-item">
                    <label>Developer Team:</label>
                    <span>{results.developer_team}</span>
                </div>
                <div class="metadata-item">
                    <label>Developer Contact:</label>
                    <span>{results.developer_contact}</span>
                </div>
                <div class="metadata-item">
                    <label>DevSecOps Contact:</label>
                    <span>{results.devsecops_contact}</span>
                </div>
            </div>
        </section>

        <!-- Executive Summary -->
        <section class="summary-section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card risk-{stats.risk_level.lower()}">
                    <h3>Risk Level</h3>
                    <div class="big-number">{stats.risk_level}</div>
                    <div class="sub-text">Score: {stats.risk_score}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="big-number">{stats.total_findings}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="big-number">{stats.total_duration:.1f}s</div>
                </div>
            </div>

            <div class="severity-breakdown">
                <h3>Findings by Severity</h3>
                <div class="severity-bars">
                    <div class="severity-bar">
                        <span class="severity-label critical">CRITICAL</span>
                        <div class="bar-container">
                            <div class="bar critical" style="width: {_get_bar_width(stats.critical_count, stats.total_findings)}%"></div>
                        </div>
                        <span class="count">{stats.critical_count}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label high">HIGH</span>
                        <div class="bar-container">
                            <div class="bar high" style="width: {_get_bar_width(stats.high_count, stats.total_findings)}%"></div>
                        </div>
                        <span class="count">{stats.high_count}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label medium">MEDIUM</span>
                        <div class="bar-container">
                            <div class="bar medium" style="width: {_get_bar_width(stats.medium_count, stats.total_findings)}%"></div>
                        </div>
                        <span class="count">{stats.medium_count}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label low">LOW</span>
                        <div class="bar-container">
                            <div class="bar low" style="width: {_get_bar_width(stats.low_count, stats.total_findings)}%"></div>
                        </div>
                        <span class="count">{stats.low_count}</span>
                    </div>
                </div>
            </div>

            <!-- Threshold Status -->
            <div class="threshold-status {'passed' if results.passed_thresholds else 'failed'}">
                <h3>Threshold Status: {'PASSED' if results.passed_thresholds else 'FAILED'}</h3>
                {_get_threshold_violations_html(results.threshold_violations)}
            </div>
        </section>

        <!-- Scanner Results -->
        <section class="scanner-section">
            <h2>Scanner Results</h2>
            {_get_scanner_results_html(results.scanner_results)}
        </section>

        <!-- Detailed Findings -->
        <section class="findings-section">
            <h2>Detailed Findings</h2>
            {_get_findings_html(results.all_findings)}
        </section>

        <!-- Footer -->
        <footer class="footer">
            <p>Generated by TTS Security Scanning Module (ttssecure) v1.0.0</p>
            <p>Report generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>"""


def _get_css() -> str:
    """Get CSS styles for the report."""
    return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; }

        .header { display: flex; justify-content: space-between; align-items: center; padding: 20px; background: #1a365d; color: white; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { font-size: 24px; }
        .report-id { font-size: 14px; }

        section { margin-bottom: 30px; padding: 20px; background: #fafafa; border-radius: 8px; border: 1px solid #e0e0e0; }
        h2 { color: #1a365d; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #3182ce; }
        h3 { color: #2d3748; margin-bottom: 10px; }

        .metadata-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; }
        .metadata-item { display: flex; gap: 10px; }
        .metadata-item label { font-weight: bold; min-width: 120px; }
        .metadata-item a { color: #3182ce; text-decoration: none; }

        .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
        .summary-card { padding: 20px; background: white; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card h3 { font-size: 14px; color: #666; }
        .big-number { font-size: 36px; font-weight: bold; color: #1a365d; }
        .sub-text { font-size: 12px; color: #666; }

        .risk-critical { border-left: 4px solid #c53030; }
        .risk-critical .big-number { color: #c53030; }
        .risk-high { border-left: 4px solid #dd6b20; }
        .risk-high .big-number { color: #dd6b20; }
        .risk-medium { border-left: 4px solid #d69e2e; }
        .risk-medium .big-number { color: #d69e2e; }
        .risk-low { border-left: 4px solid #38a169; }
        .risk-low .big-number { color: #38a169; }

        .severity-bars { margin-top: 15px; }
        .severity-bar { display: flex; align-items: center; margin-bottom: 10px; }
        .severity-label { width: 80px; font-weight: bold; font-size: 12px; }
        .bar-container { flex: 1; height: 20px; background: #e0e0e0; border-radius: 4px; margin: 0 10px; }
        .bar { height: 100%; border-radius: 4px; transition: width 0.3s; }
        .bar.critical { background: #c53030; }
        .bar.high { background: #dd6b20; }
        .bar.medium { background: #d69e2e; }
        .bar.low { background: #38a169; }
        .severity-label.critical { color: #c53030; }
        .severity-label.high { color: #dd6b20; }
        .severity-label.medium { color: #d69e2e; }
        .severity-label.low { color: #38a169; }
        .count { width: 40px; text-align: right; font-weight: bold; }

        .threshold-status { padding: 15px; border-radius: 8px; margin-top: 20px; }
        .threshold-status.passed { background: #c6f6d5; border: 1px solid #38a169; }
        .threshold-status.failed { background: #fed7d7; border: 1px solid #c53030; }
        .threshold-status h3 { margin-bottom: 10px; }
        .violation-list { list-style: none; }
        .violation-list li { padding: 5px 0; color: #c53030; }

        .scanner-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .scanner-table th, .scanner-table td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        .scanner-table th { background: #1a365d; color: white; }
        .scanner-table tr:hover { background: #f0f0f0; }
        .status-success { color: #38a169; }
        .status-failed { color: #c53030; }

        .finding-card { background: white; border-radius: 8px; padding: 15px; margin-bottom: 15px; border-left: 4px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .finding-card.critical { border-left-color: #c53030; }
        .finding-card.high { border-left-color: #dd6b20; }
        .finding-card.medium { border-left-color: #d69e2e; }
        .finding-card.low { border-left-color: #38a169; }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .finding-title { font-weight: bold; }
        .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; color: white; }
        .severity-badge.critical { background: #c53030; }
        .severity-badge.high { background: #dd6b20; }
        .severity-badge.medium { background: #d69e2e; }
        .severity-badge.low { background: #38a169; }
        .finding-location { font-size: 12px; color: #666; margin-bottom: 10px; }
        .finding-description { margin-bottom: 10px; }
        .finding-recommendation { background: #f0f8ff; padding: 10px; border-radius: 4px; font-size: 14px; }

        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    """


def _get_bar_width(count: int, total: int) -> float:
    """Calculate bar width percentage."""
    if total == 0:
        return 0
    return min((count / total) * 100, 100)


def _get_threshold_violations_html(violations: List[str]) -> str:
    """Generate HTML for threshold violations."""
    if not violations:
        return "<p>All thresholds passed.</p>"

    items = "".join(f"<li>{v}</li>" for v in violations)
    return f"<ul class='violation-list'>{items}</ul>"


def _get_scanner_results_html(scanner_results) -> str:
    """Generate HTML for scanner results table."""
    rows = ""
    for result in scanner_results:
        status_class = "status-success" if result.success else "status-failed"
        status_text = "Success" if result.success else "Failed"

        rows += f"""
        <tr>
            <td>{result.scanner_name}</td>
            <td class="{status_class}">{status_text}</td>
            <td>{result.total_findings}</td>
            <td>{result.critical_count}</td>
            <td>{result.high_count}</td>
            <td>{result.medium_count}</td>
            <td>{result.low_count}</td>
            <td>{result.duration:.2f}s</td>
        </tr>
        """

    return f"""
    <table class="scanner-table">
        <thead>
            <tr>
                <th>Scanner</th>
                <th>Status</th>
                <th>Total</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Duration</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    """


def _get_findings_html(findings: List[Finding]) -> str:
    """Generate HTML for findings list."""
    # Group by scanner
    by_scanner: Dict[str, List[Finding]] = {}
    for f in findings[:100]:  # Limit to first 100
        if f.scanner not in by_scanner:
            by_scanner[f.scanner] = []
        by_scanner[f.scanner].append(f)

    html = ""
    for scanner, scanner_findings in by_scanner.items():
        html += f"<h3>{scanner} ({len(scanner_findings)} findings)</h3>"

        for finding in scanner_findings[:20]:  # Limit per scanner
            severity_lower = finding.severity.value.lower()
            html += f"""
            <div class="finding-card {severity_lower}">
                <div class="finding-header">
                    <span class="finding-title">{finding.rule_id}: {finding.title[:80]}</span>
                    <span class="severity-badge {severity_lower}">{finding.severity.value}</span>
                </div>
                <div class="finding-location">
                    <strong>File:</strong> {finding.file_path}
                    {f'<strong>Line:</strong> {finding.line_number}' if finding.line_number else ''}
                    {f'<strong>CWE:</strong> {finding.cwe_id}' if finding.cwe_id else ''}
                </div>
                <div class="finding-description">{finding.description[:300]}...</div>
                {f'<div class="finding-recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>' if finding.recommendation else ''}
            </div>
            """

    return html
