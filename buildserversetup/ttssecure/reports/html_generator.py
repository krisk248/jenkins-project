"""
HTML report generator for ttssecure.

Generates web-viewable HTML report with styling.
"""

import base64
import html as html_escape_module
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from reports.aggregator import AggregatedResults
from scanners.base import Finding, Severity
from utils.logger import get_logger

# Easter egg - hidden message
_EASTER_EGG = base64.b64encode(b"we grows together-by KG").decode()


def generate_html_report(
    results: AggregatedResults,
    output_path: Path,
    logo_path: Optional[Path] = None,
) -> Path:
    """
    Generate HTML report.

    Args:
        results: Aggregated scan results
        output_path: Path for output HTML file
        logo_path: Optional path to logo image

    Returns:
        Path to generated HTML file
    """
    logger = get_logger()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        html_content = _build_html(results, logo_path)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        raise


def _simplify_path(full_path: str, base_folder: str = "") -> str:
    """
    Simplify file path to show from src/ or main folder.

    Args:
        full_path: Full file path
        base_folder: Optional base folder to strip

    Returns:
        Simplified path starting from src/ or similar marker
    """
    if not full_path:
        return ""

    # Common source folder markers
    markers = ["src", "main", "java", "resources", "test", "lib", "app"]

    path_parts = full_path.replace("\\", "/").split("/")

    # Find the first marker and return from there
    for i, part in enumerate(path_parts):
        if part in markers:
            return "/".join(path_parts[i:])

    # If no marker found, return just the filename with parent
    if len(path_parts) >= 2:
        return "/".join(path_parts[-2:])

    return full_path


def _get_logo_html(logo_path: Optional[Path], large: bool = False) -> str:
    """Generate logo HTML with preserved aspect ratio.

    Args:
        logo_path: Path to logo image
        large: If True, render as large centered logo for header section
    """
    if logo_path and logo_path.exists():
        # Embed logo as base64 to make HTML self-contained
        try:
            with open(logo_path, "rb") as f:
                logo_data = base64.b64encode(f.read()).decode()
            # Determine mime type
            suffix = logo_path.suffix.lower()
            mime_type = "image/png" if suffix == ".png" else "image/jpeg"

            if large:
                # Large centered logo for header
                return f'''<img src="data:{mime_type};base64,{logo_data}"
                            alt="TTS Logo"
                            style="max-height: 100px; max-width: 280px; object-fit: contain;">'''
            else:
                return f'''<img src="data:{mime_type};base64,{logo_data}"
                            alt="TTS Logo"
                            style="max-height: 60px; max-width: 150px; object-fit: contain;">'''
        except Exception:
            pass
    return ""


def _build_html(results: AggregatedResults, logo_path: Optional[Path] = None) -> str:
    """Build HTML content."""
    stats = results.statistics
    logo_html = _get_logo_html(logo_path, large=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {results.report_id}</title>
    <!-- {_EASTER_EGG} -->
    <style>
        {_get_css()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header with Centered Logo -->
        <header class="header">
            <div class="header-top">
                <div class="logo-centered">
                    {logo_html}
                </div>
            </div>
            <div class="header-bottom">
                <h1>TTS Security Assessment Report</h1>
                <div class="report-id">
                    <strong>Report ID:</strong> {results.report_id}
                </div>
            </div>
        </header>

        <!-- Metadata Section -->
        <section class="metadata-section">
            <h2>Report Information</h2>
            <table class="info-table">
                <tr>
                    <td><strong>Project:</strong></td>
                    <td>{results.project_name}</td>
                    <td><strong>Component:</strong></td>
                    <td>{results.component_name}</td>
                </tr>
                <tr>
                    <td><strong>Git URL:</strong></td>
                    <td colspan="3"><a href="{results.git_url}">{results.git_url}</a></td>
                </tr>
                <tr>
                    <td><strong>Branch:</strong></td>
                    <td>{results.git_branch}</td>
                    <td><strong>Build #:</strong></td>
                    <td>{results.build_number}</td>
                </tr>
                <tr>
                    <td><strong>QA URL:</strong></td>
                    <td colspan="3"><a href="{results.qa_url}">{results.qa_url}</a></td>
                </tr>
                <tr>
                    <td><strong>Scan Date:</strong></td>
                    <td>{results.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>
                    <td><strong>Duration:</strong></td>
                    <td>{stats.total_duration:.1f}s</td>
                </tr>
                <tr>
                    <td><strong>Developer Team:</strong></td>
                    <td>{results.developer_team}</td>
                    <td><strong>Contact:</strong></td>
                    <td>{results.developer_contact}</td>
                </tr>
                <tr>
                    <td><strong>DevSecOps:</strong></td>
                    <td colspan="3">{results.devsecops_contact}</td>
                </tr>
            </table>
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
                    <h3>Scanners Run</h3>
                    <div class="big-number">{stats.scanners_run}</div>
                    <div class="sub-text">{stats.scanners_failed} failed</div>
                </div>
            </div>

            <div class="severity-breakdown">
                <h3>Findings by Severity</h3>
                <table class="severity-table">
                    <tr>
                        <td class="severity-cell critical">
                            <div class="severity-count">{stats.critical_count}</div>
                            <div class="severity-label">CRITICAL</div>
                        </td>
                        <td class="severity-cell high">
                            <div class="severity-count">{stats.high_count}</div>
                            <div class="severity-label">HIGH</div>
                        </td>
                        <td class="severity-cell medium">
                            <div class="severity-count">{stats.medium_count}</div>
                            <div class="severity-label">MEDIUM</div>
                        </td>
                        <td class="severity-cell low">
                            <div class="severity-count">{stats.low_count}</div>
                            <div class="severity-label">LOW</div>
                        </td>
                    </tr>
                </table>
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

        <!-- Scanner Information -->
        <section class="scanner-info-section">
            <h2>About Security Scanners</h2>
            {_get_scanner_info_html()}
        </section>

        <!-- Footer -->
        <footer class="footer">
            <p>Generated by TTS Security Scanning Module (ttssecure) v1.0.0</p>
            <p>Report generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p class="easter-egg" data-msg="{_EASTER_EGG}"></p>
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

        .header { padding: 25px; background: #1a365d; color: white; border-radius: 8px; margin-bottom: 20px; }
        .header-top { text-align: center; padding-bottom: 15px; margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.2); }
        .logo-centered { display: flex; justify-content: center; align-items: center; }
        .logo-centered img { max-height: 100px; max-width: 280px; object-fit: contain; }
        .header-bottom { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 24px; margin: 0; }
        .report-id { font-size: 14px; }

        section { margin-bottom: 30px; padding: 20px; background: #fafafa; border-radius: 8px; border: 1px solid #e0e0e0; }
        h2 { color: #1a365d; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #3182ce; }
        h3 { color: #2d3748; margin-bottom: 10px; }

        .info-table { width: 100%; border-collapse: collapse; }
        .info-table td { padding: 8px 12px; border-bottom: 1px solid #e0e0e0; }
        .info-table a { color: #3182ce; text-decoration: none; }

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

        .severity-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .severity-cell { text-align: center; padding: 20px; border-radius: 8px; }
        .severity-cell.critical { background: #fff5f5; border: 2px solid #c53030; }
        .severity-cell.high { background: #fffaf0; border: 2px solid #dd6b20; }
        .severity-cell.medium { background: #fffff0; border: 2px solid #d69e2e; }
        .severity-cell.low { background: #f0fff4; border: 2px solid #38a169; }
        .severity-count { font-size: 32px; font-weight: bold; }
        .severity-cell.critical .severity-count { color: #c53030; }
        .severity-cell.high .severity-count { color: #dd6b20; }
        .severity-cell.medium .severity-count { color: #d69e2e; }
        .severity-cell.low .severity-count { color: #38a169; }
        .severity-label { font-size: 12px; font-weight: bold; margin-top: 5px; }

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
        .status-success { color: #38a169; font-weight: bold; }
        .status-failed { color: #c53030; font-weight: bold; }

        /* Improved Finding Cards with Table Layout */
        .finding-group { margin-bottom: 30px; }
        .finding-group h3 { background: #2d3748; color: white; padding: 10px 15px; border-radius: 6px 6px 0 0; margin-bottom: 0; }

        .findings-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .findings-table th { background: #4a5568; color: white; padding: 10px; text-align: left; font-size: 12px; }
        .findings-table td { padding: 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
        .findings-table tr:hover { background: #f7fafc; }

        .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; }
        .severity-badge.critical { background: #c53030; }
        .severity-badge.high { background: #dd6b20; }
        .severity-badge.medium { background: #d69e2e; }
        .severity-badge.low { background: #38a169; }

        .file-path { font-family: monospace; font-size: 12px; color: #4a5568; word-break: break-all; }
        .line-number { font-family: monospace; font-size: 12px; color: #718096; }
        .rule-id { font-family: monospace; font-size: 11px; color: #718096; }
        .finding-title { font-weight: 600; color: #2d3748; }
        .finding-desc { font-size: 13px; color: #4a5568; margin-top: 5px; }
        .cwe-badge { font-size: 10px; background: #e2e8f0; padding: 2px 6px; border-radius: 3px; color: #4a5568; }

        /* Scanner Info Section */
        .scanner-info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .scanner-info-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .scanner-info-card h4 { color: #1a365d; margin-bottom: 10px; border-bottom: 2px solid #3182ce; padding-bottom: 5px; }
        .scanner-info-card p { font-size: 14px; color: #4a5568; margin-bottom: 10px; }
        .scanner-info-card ul { margin-left: 20px; font-size: 13px; color: #4a5568; }
        .scanner-info-card li { margin-bottom: 5px; }

        .risk-calculation { background: #f7fafc; border-radius: 8px; padding: 20px; margin-top: 20px; }
        .risk-calculation h4 { color: #1a365d; margin-bottom: 15px; }
        .risk-formula { font-family: monospace; background: #2d3748; color: #48bb78; padding: 15px; border-radius: 6px; margin-bottom: 15px; }
        .risk-levels { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
        .risk-level-item { text-align: center; padding: 10px; border-radius: 6px; }
        .risk-level-item.critical { background: #fff5f5; border: 1px solid #c53030; }
        .risk-level-item.high { background: #fffaf0; border: 1px solid #dd6b20; }
        .risk-level-item.medium { background: #fffff0; border: 1px solid #d69e2e; }
        .risk-level-item.low { background: #f0fff4; border: 1px solid #38a169; }

        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .easter-egg { display: none; }

        @media print {
            .container { max-width: 100%; }
            section { page-break-inside: avoid; }
        }
    """


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
    """Generate HTML for findings list with table format."""
    # Group by scanner - NO LIMIT, show all findings
    by_scanner: Dict[str, List[Finding]] = {}
    for f in findings:  # Show ALL findings
        if f.scanner not in by_scanner:
            by_scanner[f.scanner] = []
        by_scanner[f.scanner].append(f)

    html = ""
    for scanner, scanner_findings in by_scanner.items():
        # Sort by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        scanner_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

        html += f'''<div class="finding-group">
            <h3>{scanner.upper()} ({len(scanner_findings)} findings)</h3>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th style="width: 80px;">Severity</th>
                        <th style="width: 200px;">Location</th>
                        <th>Finding Details</th>
                    </tr>
                </thead>
                <tbody>'''

        for finding in scanner_findings:  # Show ALL findings per scanner
            severity_lower = finding.severity.value.lower()
            simplified_path = _simplify_path(finding.file_path)

            # Escape all user content to prevent XSS and display issues
            escaped_path = html_escape_module.escape(simplified_path) if simplified_path else ''
            escaped_rule_id = html_escape_module.escape(finding.rule_id) if finding.rule_id else ''
            escaped_title = html_escape_module.escape(finding.title[:100]) if finding.title else ''
            escaped_cwe = html_escape_module.escape(finding.cwe_id) if finding.cwe_id else ''

            # Build CWE badge if available
            cwe_html = f'<span class="cwe-badge">{escaped_cwe}</span>' if escaped_cwe else ''

            # Truncate and escape description
            desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
            escaped_desc = html_escape_module.escape(desc) if desc else ''

            html += f'''
                <tr>
                    <td><span class="severity-badge {severity_lower}">{finding.severity.value}</span></td>
                    <td>
                        <div class="file-path">{escaped_path}</div>
                        <div class="line-number">Line: {finding.line_number if finding.line_number else 'N/A'}</div>
                    </td>
                    <td>
                        <div class="rule-id">{escaped_rule_id} {cwe_html}</div>
                        <div class="finding-title">{escaped_title}</div>
                        <div class="finding-desc">{escaped_desc}</div>
                    </td>
                </tr>'''

        html += '''
                </tbody>
            </table>
        </div>'''

    return html


def _get_scanner_info_html() -> str:
    """Generate HTML for scanner information section."""
    return '''
    <div class="scanner-info-grid">
        <div class="scanner-info-card">
            <h4>Semgrep (SAST)</h4>
            <p>Static Application Security Testing tool that finds bugs and security vulnerabilities using pattern matching.</p>
            <ul>
                <li>Detects code injection vulnerabilities</li>
                <li>Identifies insecure coding patterns</li>
                <li>Supports 30+ programming languages</li>
                <li>Uses community and custom rules</li>
            </ul>
        </div>

        <div class="scanner-info-card">
            <h4>Trivy</h4>
            <p>Comprehensive vulnerability scanner for containers, filesystems, and Git repositories.</p>
            <ul>
                <li>Scans dependencies for known CVEs</li>
                <li>Detects misconfigurations</li>
                <li>Identifies exposed secrets</li>
                <li>Checks container images</li>
            </ul>
        </div>

        <div class="scanner-info-card">
            <h4>TruffleHog</h4>
            <p>Specialized tool for detecting secrets and credentials accidentally committed to code.</p>
            <ul>
                <li>Finds API keys and tokens</li>
                <li>Detects passwords and credentials</li>
                <li>Scans Git history</li>
                <li>Identifies private keys</li>
            </ul>
        </div>

        <div class="scanner-info-card">
            <h4>SpotBugs (Java)</h4>
            <p>Static analysis tool that finds bugs in Java programs by analyzing bytecode.</p>
            <ul>
                <li>Detects null pointer issues</li>
                <li>Finds resource leaks</li>
                <li>Identifies security vulnerabilities</li>
                <li>With FindSecBugs plugin for security</li>
            </ul>
        </div>

        <div class="scanner-info-card">
            <h4>OWASP Dependency-Check</h4>
            <p>Software Composition Analysis (SCA) tool that identifies known vulnerabilities in dependencies.</p>
            <ul>
                <li>Checks against NVD database</li>
                <li>Supports Java, .NET, Python, etc.</li>
                <li>Identifies outdated libraries</li>
                <li>Provides CVE details</li>
            </ul>
        </div>

        <div class="scanner-info-card">
            <h4>ESLint Security</h4>
            <p>JavaScript/TypeScript linting with security-focused rules to catch vulnerabilities early.</p>
            <ul>
                <li>Detects XSS vulnerabilities</li>
                <li>Finds prototype pollution</li>
                <li>Identifies unsafe eval usage</li>
                <li>Checks for injection flaws</li>
            </ul>
        </div>
    </div>

    <div class="risk-calculation">
        <h4>Risk Score Calculation</h4>
        <div class="risk-formula">
Risk Score = (Critical x 10) + (High x 5) + (Medium x 2) + (Low x 0.5)
        </div>
        <p>The overall risk level is determined by the calculated score:</p>
        <div class="risk-levels">
            <div class="risk-level-item critical">
                <strong>CRITICAL</strong><br>
                Score >= 10
            </div>
            <div class="risk-level-item high">
                <strong>HIGH</strong><br>
                Score >= 5
            </div>
            <div class="risk-level-item medium">
                <strong>MEDIUM</strong><br>
                Score >= 2
            </div>
            <div class="risk-level-item low">
                <strong>LOW</strong><br>
                Score < 2
            </div>
        </div>
    </div>
    '''
