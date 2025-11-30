"""
PDF report generator for ttssecure.

Generates professional PDF security reports with charts and styling.
"""

import io
import base64
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from PIL import Image as PILImage

from reports.aggregator import AggregatedResults
from scanners.base import Finding, Severity
from utils.logger import get_logger

# Easter egg - hidden message
_EASTER_EGG = base64.b64encode(b"we grows together-by KG").decode()

# Color definitions
COLORS = {
    "primary": colors.HexColor("#1a365d"),
    "secondary": colors.HexColor("#3182ce"),
    "critical": colors.HexColor("#c53030"),
    "high": colors.HexColor("#dd6b20"),
    "medium": colors.HexColor("#d69e2e"),
    "low": colors.HexColor("#38a169"),
    "info": colors.HexColor("#3182ce"),
    "background": colors.HexColor("#f5f5f5"),
    "text": colors.HexColor("#333333"),
    "light_bg": colors.HexColor("#f8f9fa"),
    "border": colors.HexColor("#e0e0e0"),
}


def generate_pdf_report(
    results: AggregatedResults,
    output_path: Path,
    logo_path: Path = None,
) -> Path:
    """
    Generate PDF security report.

    Args:
        results: Aggregated scan results
        output_path: Path for output PDF file
        logo_path: Path to company logo (optional)

    Returns:
        Path to generated PDF file
    """
    logger = get_logger()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Create document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch,
        )

        # Build content
        story = []
        styles = _get_styles()

        # Cover page
        story.extend(_build_cover_page(results, styles, logo_path))
        story.append(PageBreak())

        # Executive summary
        story.extend(_build_executive_summary(results, styles))
        story.append(PageBreak())

        # Scanner results
        story.extend(_build_scanner_results(results, styles))

        # Detailed findings with improved formatting
        story.extend(_build_findings_section(results, styles))

        # Scanner Information (replaces Recommendations)
        story.extend(_build_scanner_info(styles))

        # Build PDF
        doc.build(story)

        logger.info(f"PDF report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        raise


def _get_logo_with_aspect_ratio(logo_path: Path, max_width: float = 2*inch, max_height: float = 1*inch) -> Optional[Image]:
    """Load logo preserving aspect ratio."""
    try:
        if not logo_path or not Path(logo_path).exists():
            return None

        # Open with PIL to get dimensions
        with PILImage.open(logo_path) as pil_img:
            orig_width, orig_height = pil_img.size

        # Calculate scaling to fit within bounds while preserving aspect ratio
        width_ratio = max_width / orig_width
        height_ratio = max_height / orig_height
        scale = min(width_ratio, height_ratio)

        new_width = orig_width * scale
        new_height = orig_height * scale

        return Image(str(logo_path), width=new_width, height=new_height)
    except Exception:
        return None


def _get_centered_logo(logo_path: Path, max_width: float = 4*inch, max_height: float = 1.8*inch) -> Optional[Table]:
    """Create a centered logo table for cover page."""
    try:
        if not logo_path or not Path(logo_path).exists():
            return None

        # Open with PIL to get dimensions
        with PILImage.open(logo_path) as pil_img:
            orig_width, orig_height = pil_img.size

        # Calculate scaling to fit within bounds while preserving aspect ratio
        width_ratio = max_width / orig_width
        height_ratio = max_height / orig_height
        scale = min(width_ratio, height_ratio)

        new_width = orig_width * scale
        new_height = orig_height * scale

        logo_img = Image(str(logo_path), width=new_width, height=new_height)

        # Wrap in table for centering
        logo_table = Table([[logo_img]], colWidths=[6*inch])
        logo_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        return logo_table
    except Exception:
        return None


def _get_styles() -> Dict[str, ParagraphStyle]:
    """Get custom paragraph styles."""
    base_styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "CustomTitle",
            parent=base_styles["Title"],
            fontSize=24,
            textColor=COLORS["primary"],
            spaceAfter=20,
        ),
        "heading1": ParagraphStyle(
            "CustomHeading1",
            parent=base_styles["Heading1"],
            fontSize=18,
            textColor=COLORS["primary"],
            spaceBefore=20,
            spaceAfter=10,
        ),
        "heading2": ParagraphStyle(
            "CustomHeading2",
            parent=base_styles["Heading2"],
            fontSize=14,
            textColor=COLORS["secondary"],
            spaceBefore=15,
            spaceAfter=8,
        ),
        "heading3": ParagraphStyle(
            "CustomHeading3",
            parent=base_styles["Heading3"],
            fontSize=11,
            textColor=COLORS["primary"],
            spaceBefore=10,
            spaceAfter=5,
        ),
        "normal": ParagraphStyle(
            "CustomNormal",
            parent=base_styles["Normal"],
            fontSize=10,
            textColor=COLORS["text"],
        ),
        "small": ParagraphStyle(
            "CustomSmall",
            parent=base_styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
        ),
        "code": ParagraphStyle(
            "Code",
            parent=base_styles["Normal"],
            fontSize=8,
            fontName="Courier",
            textColor=COLORS["text"],
            backColor=COLORS["light_bg"],
        ),
        "critical": ParagraphStyle(
            "Critical",
            parent=base_styles["Normal"],
            textColor=COLORS["critical"],
            fontName="Helvetica-Bold",
        ),
        "high": ParagraphStyle(
            "High",
            parent=base_styles["Normal"],
            textColor=COLORS["high"],
            fontName="Helvetica-Bold",
        ),
    }


def _simplify_path(full_path: str, base_folder: str = "") -> str:
    """Simplify file path for display."""
    if not full_path:
        return ""

    # Try to extract from src/ or main folder
    path_parts = full_path.replace("\\", "/").split("/")

    # Find src or main folder markers
    markers = ["src", "main", "java", "resources", "test"]
    for i, part in enumerate(path_parts):
        if part in markers:
            return "/".join(path_parts[i:])

    # If path is very long, just show last 3 parts
    if len(path_parts) > 4:
        return ".../" + "/".join(path_parts[-3:])

    return full_path


def _build_cover_page(
    results: AggregatedResults,
    styles: Dict,
    logo_path: Path = None
) -> List:
    """Build cover page content."""
    story = []
    stats = results.statistics

    # Large centered logo for cover page
    logo_table = _get_centered_logo(logo_path, max_width=4.5*inch, max_height=2*inch)
    if logo_table:
        story.append(logo_table)
        story.append(Spacer(1, 0.3*inch))
    else:
        story.append(Spacer(1, 0.5*inch))

    # Title
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["title"]))
    story.append(Spacer(1, 0.3*inch))

    # Report ID box
    report_id_table = Table(
        [[f"Report ID: {results.report_id}"]],
        colWidths=[5*inch]
    )
    report_id_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 14),
        ("PADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(report_id_table)
    story.append(Spacer(1, 0.5*inch))

    # Metadata table
    metadata = [
        ["Project:", results.project_name],
        ["Component:", results.component_name],
        ["Git URL:", results.git_url[:60] + "..." if len(results.git_url) > 60 else results.git_url],
        ["Branch:", results.git_branch],
        ["QA URL:", results.qa_url],
        ["Jenkins Build:", f"#{results.build_number}"],
        ["Scan Date:", results.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S")],
        ["Developer Team:", results.developer_team],
        ["Developer Contact:", results.developer_contact],
        ["DevSecOps Contact:", results.devsecops_contact],
    ]

    meta_table = Table(metadata, colWidths=[1.5*inch, 4.5*inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), COLORS["primary"]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*inch))

    # Summary box
    risk_color = _get_risk_color(stats.risk_level)
    summary_data = [
        [f"TOTAL FINDINGS: {stats.total_findings}"],
        [f"Critical: {stats.critical_count}  |  High: {stats.high_count}  |  Medium: {stats.medium_count}  |  Low: {stats.low_count}"],
        [f"RISK LEVEL: {stats.risk_level} (Score: {stats.risk_score})"],
    ]

    summary_table = Table(summary_data, colWidths=[5*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f0f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 16),
        ("FONTSIZE", (0, 1), (-1, 1), 12),
        ("FONTSIZE", (0, 2), (-1, 2), 14),
        ("TEXTCOLOR", (0, 2), (-1, 2), risk_color),
        ("FONTNAME", (0, 2), (-1, 2), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 15),
        ("BOX", (0, 0), (-1, -1), 2, COLORS["primary"]),
    ]))
    story.append(summary_table)

    return story


def _build_executive_summary(results: AggregatedResults, styles: Dict) -> List:
    """Build executive summary section."""
    story = []
    stats = results.statistics

    story.append(Paragraph("Executive Summary", styles["heading1"]))

    # Risk assessment
    risk_color = _get_risk_color(stats.risk_level)
    story.append(Paragraph(
        f"<b>Risk Assessment:</b> The security scan identified a total of "
        f"<b>{stats.total_findings}</b> findings across {stats.scanners_run} scanners. "
        f"The overall risk level is <font color='{risk_color.hexval()}'><b>{stats.risk_level}</b></font> "
        f"with a risk score of {stats.risk_score}.",
        styles["normal"]
    ))
    story.append(Spacer(1, 0.2*inch))

    # Severity breakdown table
    story.append(Paragraph("Findings by Severity", styles["heading2"]))

    severity_data = [
        ["Severity", "Count", "Percentage"],
        ["CRITICAL", str(stats.critical_count), f"{_pct(stats.critical_count, stats.total_findings)}%"],
        ["HIGH", str(stats.high_count), f"{_pct(stats.high_count, stats.total_findings)}%"],
        ["MEDIUM", str(stats.medium_count), f"{_pct(stats.medium_count, stats.total_findings)}%"],
        ["LOW", str(stats.low_count), f"{_pct(stats.low_count, stats.total_findings)}%"],
    ]

    severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 1*inch])
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("TEXTCOLOR", (0, 1), (0, 1), COLORS["critical"]),
        ("TEXTCOLOR", (0, 2), (0, 2), COLORS["high"]),
        ("TEXTCOLOR", (0, 3), (0, 3), COLORS["medium"]),
        ("TEXTCOLOR", (0, 4), (0, 4), COLORS["low"]),
    ]))
    story.append(severity_table)
    story.append(Spacer(1, 0.3*inch))

    # Pie chart
    story.append(Paragraph("Severity Distribution", styles["heading2"]))
    pie_chart = _create_severity_pie_chart(stats)
    story.append(pie_chart)
    story.append(Spacer(1, 0.3*inch))

    # Findings by scanner
    story.append(Paragraph("Findings by Scanner", styles["heading2"]))
    bar_chart = _create_scanner_bar_chart(stats)
    story.append(bar_chart)
    story.append(Spacer(1, 0.3*inch))

    # Threshold status
    story.append(Paragraph("Threshold Status", styles["heading2"]))
    status_text = "PASSED" if results.passed_thresholds else "FAILED"
    status_color = COLORS["low"] if results.passed_thresholds else COLORS["critical"]
    story.append(Paragraph(
        f"<font color='{status_color.hexval()}'><b>{status_text}</b></font>",
        styles["normal"]
    ))

    if results.threshold_violations:
        for violation in results.threshold_violations:
            story.append(Paragraph(f"- {violation}", styles["normal"]))

    return story


def _build_scanner_results(results: AggregatedResults, styles: Dict) -> List:
    """Build scanner results section."""
    story = []

    story.append(Paragraph("Scanner Results", styles["heading1"]))

    # Scanner table
    data = [["Scanner", "Status", "Total", "Critical", "High", "Medium", "Low", "Duration"]]

    for result in results.scanner_results:
        status = "Success" if result.success else "Failed"
        data.append([
            result.scanner_name,
            status,
            str(result.total_findings),
            str(result.critical_count),
            str(result.high_count),
            str(result.medium_count),
            str(result.low_count),
            f"{result.duration:.1f}s"
        ])

    table = Table(data, colWidths=[1.2*inch, 0.7*inch, 0.6*inch, 0.6*inch, 0.6*inch, 0.7*inch, 0.6*inch, 0.7*inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(table)

    return story


def _build_findings_section(results: AggregatedResults, styles: Dict) -> List:
    """Build detailed findings section with improved table formatting."""
    story = []

    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", styles["heading1"]))

    # Group by severity - NO LIMIT, show all findings
    findings_by_severity = {
        Severity.CRITICAL: [],
        Severity.HIGH: [],
        Severity.MEDIUM: [],
        Severity.LOW: [],
    }

    for finding in results.all_findings:
        if finding.severity in findings_by_severity:
            findings_by_severity[finding.severity].append(finding)  # Show ALL findings

    severity_colors = {
        Severity.CRITICAL: COLORS["critical"],
        Severity.HIGH: COLORS["high"],
        Severity.MEDIUM: COLORS["medium"],
        Severity.LOW: COLORS["low"],
    }

    for severity, findings in findings_by_severity.items():
        if not findings:
            continue

        story.append(Paragraph(
            f"<font color='{severity_colors[severity].hexval()}'><b>{severity.value}</b></font> Findings ({len(findings)})",
            styles["heading2"]
        ))

        # Create table for findings
        for finding in findings:
            # Simplify path
            simple_path = _simplify_path(finding.file_path)

            # Finding table
            finding_data = [
                [Paragraph(f"<b>{finding.rule_id}</b>", styles["normal"]),
                 Paragraph(f"<font color='{severity_colors[severity].hexval()}'><b>{severity.value}</b></font>", styles["normal"])],
                [Paragraph(f"<b>File:</b> {simple_path}", styles["small"]),
                 Paragraph(f"<b>Line:</b> {finding.line_number}" if finding.line_number else "", styles["small"])],
            ]

            # Add CWE if present
            if finding.cwe_id:
                finding_data.append([
                    Paragraph(f"<b>CWE:</b> {finding.cwe_id}", styles["small"]),
                    ""
                ])

            # Add description
            desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
            finding_data.append([
                Paragraph(desc, styles["normal"]),
                ""
            ])

            finding_table = Table(finding_data, colWidths=[4.5*inch, 1.5*inch])
            finding_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLORS["light_bg"]),
                ("SPAN", (0, -1), (-1, -1)),  # Span description across columns
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("BOX", (0, 0), (-1, -1), 1, severity_colors[severity]),
                ("LINEBELOW", (0, 0), (-1, 0), 1, COLORS["border"]),
            ]))

            story.append(finding_table)
            story.append(Spacer(1, 0.1*inch))

    return story


def _build_scanner_info(styles: Dict) -> List:
    """Build scanner information page (replaces recommendations)."""
    story = []

    story.append(PageBreak())
    story.append(Paragraph("About the Security Scanners", styles["heading1"]))

    scanners_info = [
        {
            "name": "Semgrep",
            "type": "SAST (Static Application Security Testing)",
            "description": "Semgrep is a fast, open-source static analysis tool that finds bugs and enforces code standards. It uses pattern-based rules to identify security vulnerabilities, code smells, and policy violations in source code.",
            "detects": "SQL Injection, XSS, Command Injection, Path Traversal, Insecure Crypto, and custom patterns"
        },
        {
            "name": "Trivy",
            "type": "SCA (Software Composition Analysis)",
            "description": "Trivy is a comprehensive vulnerability scanner for containers, filesystems, and Git repositories. It detects vulnerabilities in OS packages, application dependencies, and Infrastructure as Code misconfigurations.",
            "detects": "CVEs in dependencies, container vulnerabilities, secrets, misconfigurations"
        },
        {
            "name": "TruffleHog",
            "type": "Secret Scanner",
            "description": "TruffleHog searches through git repositories and filesystems for high-entropy strings and patterns that indicate secrets like API keys, passwords, and tokens that should not be in source code.",
            "detects": "API keys, passwords, tokens, private keys, credentials"
        },
        {
            "name": "SpotBugs + FindSecBugs",
            "type": "Java Bytecode Analysis",
            "description": "SpotBugs analyzes Java bytecode to find bugs. With the FindSecBugs plugin, it specifically targets security vulnerabilities in Java applications by examining compiled class files.",
            "detects": "Java security bugs, injection flaws, cryptographic issues, insecure practices"
        },
        {
            "name": "OWASP Dependency-Check",
            "type": "Dependency Vulnerability Scanner",
            "description": "OWASP Dependency-Check identifies project dependencies and checks if there are any known, publicly disclosed vulnerabilities (CVEs) using the National Vulnerability Database.",
            "detects": "Known CVEs in project dependencies (Java, .NET, JavaScript, Python, etc.)"
        },
    ]

    for scanner in scanners_info:
        story.append(Paragraph(f"<b>{scanner['name']}</b> - {scanner['type']}", styles["heading3"]))
        story.append(Paragraph(scanner['description'], styles["normal"]))
        story.append(Paragraph(f"<b>Detects:</b> {scanner['detects']}", styles["small"]))
        story.append(Spacer(1, 0.15*inch))

    story.append(Spacer(1, 0.2*inch))

    # Risk Score Calculation
    story.append(Paragraph("Risk Score Calculation", styles["heading2"]))
    story.append(Paragraph(
        "The risk score is calculated using the following formula:",
        styles["normal"]
    ))
    story.append(Spacer(1, 0.1*inch))

    formula_table = Table([
        ["Risk Score = (Critical x 4 + High x 2 + Medium x 1) / 10"]
    ], colWidths=[5*inch])
    formula_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLORS["light_bg"]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("PADDING", (0, 0), (-1, -1), 12),
        ("BOX", (0, 0), (-1, -1), 1, COLORS["border"]),
    ]))
    story.append(formula_table)
    story.append(Spacer(1, 0.15*inch))

    # Risk levels
    risk_levels = [
        ["Risk Level", "Score Range", "Action Required"],
        ["CRITICAL", ">= 7.0", "Immediate remediation required"],
        ["HIGH", "5.0 - 6.9", "Address within 24-48 hours"],
        ["MEDIUM", "3.0 - 4.9", "Plan remediation within sprint"],
        ["LOW", "< 3.0", "Monitor and track"],
    ]
    risk_table = Table(risk_levels, colWidths=[1.2*inch, 1.2*inch, 2.5*inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 1, COLORS["border"]),
        ("TEXTCOLOR", (0, 1), (0, 1), COLORS["critical"]),
        ("TEXTCOLOR", (0, 2), (0, 2), COLORS["high"]),
        ("TEXTCOLOR", (0, 3), (0, 3), COLORS["medium"]),
        ("TEXTCOLOR", (0, 4), (0, 4), COLORS["low"]),
    ]))
    story.append(risk_table)

    # Hidden easter egg in metadata (not visible but in PDF)
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(
        f"<font color='white' size='1'><!-- {_EASTER_EGG} --></font>",
        styles["small"]
    ))

    # Footer
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(
        "<i>Generated by TTS Security Scanning Module (ttssecure) v1.0.0</i>",
        styles["small"]
    ))

    return story


def _create_severity_pie_chart(stats) -> Drawing:
    """Create pie chart for severity distribution."""
    drawing = Drawing(400, 200)

    data = [
        stats.critical_count or 0.1,
        stats.high_count or 0.1,
        stats.medium_count or 0.1,
        stats.low_count or 0.1,
    ]

    pie = Pie()
    pie.x = 100
    pie.y = 25
    pie.width = 150
    pie.height = 150
    pie.data = data
    pie.labels = ["Critical", "High", "Medium", "Low"]
    pie.slices[0].fillColor = COLORS["critical"]
    pie.slices[1].fillColor = COLORS["high"]
    pie.slices[2].fillColor = COLORS["medium"]
    pie.slices[3].fillColor = COLORS["low"]

    drawing.add(pie)
    return drawing


def _create_scanner_bar_chart(stats) -> Drawing:
    """Create bar chart for findings by scanner."""
    drawing = Drawing(400, 200)

    scanners = list(stats.findings_by_scanner.keys())
    values = list(stats.findings_by_scanner.values())

    if not scanners:
        return drawing

    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 50
    chart.width = 300
    chart.height = 125
    chart.data = [values]
    chart.categoryAxis.categoryNames = [s[:10] for s in scanners]
    chart.categoryAxis.labels.angle = 45
    chart.categoryAxis.labels.boxAnchor = "ne"
    chart.bars[0].fillColor = COLORS["secondary"]

    drawing.add(chart)
    return drawing


def _get_risk_color(risk_level: str) -> colors.Color:
    """Get color for risk level."""
    return {
        "CRITICAL": COLORS["critical"],
        "HIGH": COLORS["high"],
        "MEDIUM": COLORS["medium"],
        "LOW": COLORS["low"],
    }.get(risk_level, COLORS["info"])


def _pct(count: int, total: int) -> str:
    """Calculate percentage."""
    if total == 0:
        return "0"
    return f"{(count / total) * 100:.1f}"
