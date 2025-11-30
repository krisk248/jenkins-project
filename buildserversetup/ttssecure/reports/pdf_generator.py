"""
PDF report generator for ttssecure.

Generates professional PDF security reports with charts and styling.
"""

import io
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple

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

from reports.aggregator import AggregatedResults
from scanners.base import Finding, Severity
from utils.logger import get_logger


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

        # Detailed findings (limited to prevent huge PDFs)
        story.extend(_build_findings_section(results, styles))

        # Recommendations
        story.extend(_build_recommendations(results, styles))

        # Build PDF
        doc.build(story)

        logger.info(f"PDF report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        raise


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


def _build_cover_page(
    results: AggregatedResults,
    styles: Dict,
    logo_path: Path = None
) -> List:
    """Build cover page content."""
    story = []
    stats = results.statistics

    # Logo
    if logo_path and Path(logo_path).exists():
        try:
            img = Image(str(logo_path), width=2*inch, height=1*inch)
            story.append(img)
        except Exception:
            pass

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
    """Build detailed findings section."""
    story = []

    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", styles["heading1"]))

    # Limit findings to prevent huge PDFs
    max_per_severity = 15

    # Group by severity
    findings_by_severity = {
        Severity.CRITICAL: [],
        Severity.HIGH: [],
        Severity.MEDIUM: [],
        Severity.LOW: [],
    }

    for finding in results.all_findings:
        if finding.severity in findings_by_severity:
            if len(findings_by_severity[finding.severity]) < max_per_severity:
                findings_by_severity[finding.severity].append(finding)

    for severity, findings in findings_by_severity.items():
        if not findings:
            continue

        story.append(Paragraph(
            f"{severity.value} Findings ({len(findings)})",
            styles["heading2"]
        ))

        for finding in findings:
            # Finding header
            story.append(Paragraph(
                f"<b>{finding.rule_id}</b>: {finding.title[:70]}",
                styles["normal"]
            ))

            # Location
            location = f"File: {finding.file_path}"
            if finding.line_number:
                location += f" | Line: {finding.line_number}"
            if finding.cwe_id:
                location += f" | {finding.cwe_id}"
            story.append(Paragraph(location, styles["small"]))

            # Description
            if finding.description:
                story.append(Paragraph(
                    finding.description[:200] + "..." if len(finding.description) > 200 else finding.description,
                    styles["normal"]
                ))

            story.append(Spacer(1, 0.1*inch))

    return story


def _build_recommendations(results: AggregatedResults, styles: Dict) -> List:
    """Build recommendations section."""
    story = []

    story.append(PageBreak())
    story.append(Paragraph("Recommendations", styles["heading1"]))

    recommendations = [
        "Address all CRITICAL and HIGH severity findings immediately.",
        "Review and fix MEDIUM severity findings within the next sprint.",
        "Document any accepted risks for LOW severity findings.",
        "Implement security scanning in CI/CD pipeline for continuous monitoring.",
        "Conduct regular security training for development team.",
        "Keep all dependencies updated to their latest secure versions.",
    ]

    # Add specific recommendations based on findings
    if results.statistics.critical_count > 0:
        recommendations.insert(0, f"URGENT: {results.statistics.critical_count} critical vulnerabilities require immediate attention.")

    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["normal"]))
        story.append(Spacer(1, 0.1*inch))

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
