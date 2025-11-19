#!/usr/bin/env python3
"""
Comprehensive Security Assessment Report Generator
Generates professional PDF reports with complete findings, charts, and visual elements
With smart auto-detection of project metadata
"""
import json
import subprocess
import sys
import os
import argparse
from datetime import datetime
from html import escape as html_escape
from pathlib import Path

# ============================================================================
# AUTO-DETECTION FUNCTIONS
# ============================================================================

def run_git_command(command, cwd=None):
    """Run git command and return output"""
    try:
        result = subprocess.run(
            command,
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


def detect_git_url(cwd=None):
    """Auto-detect Git repository URL"""
    url = run_git_command(['git', 'remote', 'get-url', 'origin'], cwd)
    if url:
        print(f'   🔍 Auto-detected Git URL: {url}')
        return url
    return 'Unknown'


def detect_git_branch(cwd=None):
    """Auto-detect Git branch"""
    branch = run_git_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd)
    if branch:
        print(f'   🔍 Auto-detected Git branch: {branch}')
        return branch
    return 'Unknown'


def detect_developer_name(cwd=None):
    """Auto-detect developer name from last commit"""
    # Try last commit author
    author = run_git_command(['git', 'log', '-1', '--format=%an'], cwd)
    if author and author != '':
        print(f'   🔍 Auto-detected developer: {author}')
        return author

    # Try git config user.name
    user = run_git_command(['git', 'config', 'user.name'], cwd)
    if user:
        print(f'   🔍 Auto-detected developer: {user}')
        return user

    return 'Development Team'


def detect_project_name_from_package_json(project_path=None):
    """Auto-detect project name from package.json"""
    try:
        pkg_file = Path(project_path or '.') / 'package.json'
        if pkg_file.exists():
            with open(pkg_file, 'r') as f:
                pkg = json.load(f)
                name = pkg.get('name', '').strip()
                if name:
                    # Clean up npm package name
                    clean_name = name.replace('-', ' ').replace('_', ' ').title()
                    print(f'   🔍 Auto-detected from package.json: {clean_name}')
                    return clean_name
    except:
        pass
    return None


def detect_project_name_from_pom_xml(project_path=None):
    """Auto-detect project name from pom.xml"""
    try:
        import xml.etree.ElementTree as ET
        pom_file = Path(project_path or '.') / 'pom.xml'
        if pom_file.exists():
            tree = ET.parse(pom_file)
            root = tree.getroot()
            # Maven uses namespaces
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

            # Try <name> first
            name = root.find('m:name', ns)
            if name is not None and name.text:
                print(f'   🔍 Auto-detected from pom.xml: {name.text.strip()}')
                return name.text.strip()

            # Fallback to <artifactId>
            artifactId = root.find('m:artifactId', ns)
            if artifactId is not None and artifactId.text:
                clean_name = artifactId.text.replace('-', ' ').replace('_', ' ').title()
                print(f'   🔍 Auto-detected from pom.xml: {clean_name}')
                return clean_name
    except:
        pass
    return None


def detect_project_name(project_path=None):
    """Auto-detect project name from various sources"""
    # Try package.json
    name = detect_project_name_from_package_json(project_path)
    if name:
        return name

    # Try pom.xml
    name = detect_project_name_from_pom_xml(project_path)
    if name:
        return name

    # Try git remote URL
    try:
        result = subprocess.run(['git', 'remote', 'get-url', 'origin'],
                              capture_output=True, text=True, timeout=5,
                              cwd=project_path or '.')
        if result.returncode == 0:
            url = result.stdout.strip()
            # Extract repo name from URL
            repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
            clean_name = repo_name.replace('-', ' ').replace('_', ' ').title()
            print(f'   🔍 Auto-detected from git: {clean_name}')
            return clean_name
    except:
        pass

    # Try directory name
    try:
        dir_name = Path(project_path or '.').resolve().name
        if dir_name and dir_name != '.':
            clean_name = dir_name.replace('-', ' ').replace('_', ' ').title()
            print(f'   🔍 Using directory name: {clean_name}')
            return clean_name
    except:
        pass

    return 'Security Scan Report'


# ============================================================================
# METADATA COLLECTION WITH PRIORITY SYSTEM
# ============================================================================

def get_metadata(args):
    """
    Collect all metadata with priority system:
    1. Command-line arguments (highest priority)
    2. Auto-detection (git commands, project files)
    3. Environment variables (Jenkins)
    4. Defaults (fallback)
    """
    print('\n🔍 Collecting metadata...')

    metadata = {}

    # Project Name
    metadata['project_name'] = (
        args.project_name or
        detect_project_name(args.project_path) or
        os.environ.get('PROJECT_NAME', '').strip() or
        'Security Scan Report'
    )
    print(f'✓ Project Name: {metadata["project_name"]}')

    # Git URL
    metadata['git_url'] = (
        args.git_url or
        detect_git_url(args.project_path) or
        os.environ.get('GIT_URL', os.environ.get('GITHUB_URL', 'Unknown'))
    )
    print(f'✓ Git Repository: {metadata["git_url"]}')

    # Git Branch
    metadata['git_branch'] = (
        args.git_branch or
        detect_git_branch(args.project_path) or
        os.environ.get('GIT_BRANCH', 'Unknown')
    )
    print(f'✓ Git Branch: {metadata["git_branch"]}')

    # Developer
    metadata['developer'] = (
        args.developer or
        detect_developer_name(args.project_path) or
        os.environ.get('DEVELOPER_NAME', os.environ.get('GIT_COMMITTER_NAME', 'Development Team'))
    )
    print(f'✓ Developer: {metadata["developer"]}')

    # DevOps Engineer
    metadata['devops_engineer'] = (
        args.devops_engineer or
        os.environ.get('DEVOPS_ENGINEER', os.environ.get('BUILD_USER', 'DevOps Team'))
    )
    print(f'✓ DevOps Engineer: {metadata["devops_engineer"]}')

    # Contact Email
    metadata['contact_email'] = (
        args.contact_email or
        os.environ.get('CONTACT_EMAIL', os.environ.get('EMAIL_RECIPIENTS', 'security@ttsme.com'))
    )
    print(f'✓ Contact Email: {metadata["contact_email"]}')

    # Build Number
    build_num = (
        args.build_number or
        os.environ.get('BUILD_NUMBER', '000')
    )
    metadata['build_number'] = build_num
    print(f'✓ Build Number: {build_num}')

    # Document Number (auto-generated)
    date_str = datetime.now().strftime('%Y%m%d')
    metadata['document_number'] = f'TTS-SEC-{date_str}-B{str(build_num).zfill(3)}'
    print(f'✓ Document Number: {metadata["document_number"]}')

    # Scan Date
    metadata['scan_date'] = args.scan_date or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'✓ Scan Date: {metadata["scan_date"]}')

    print('✅ Metadata collection complete\n')
    return metadata


# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Security Assessment Report Generator with Auto-Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Minimal usage (auto-detects everything)
  %(prog)s --input-dir ./security-reports --output-pdf security-report.pdf

  # With project path for better auto-detection
  %(prog)s --input-dir /tts/ttsbuild/Security/ADXSIP --output-pdf /tts/ttsbuild/Security/ADXSIP/security-report.pdf --project-path /tts/ttsbuild/ADXSIP

  # Override specific metadata
  %(prog)s --input-dir ./security-reports --output-pdf report.pdf --project-name "ADXSIP Backend" --developer "John Doe"

  # Full manual control
  %(prog)s --input-dir ./security-reports --output-pdf report.pdf \\
    --project-name "My Project" --git-url "https://github.com/company/repo" \\
    --git-branch "main" --developer "John Doe" --build-number "42"
        """
    )

    # Required arguments
    parser.add_argument('--input-dir', required=True,
                       help='Directory containing JSON scan results (semgrep.json, trivy.json, trufflehog.json)')
    parser.add_argument('--output-pdf', required=True,
                       help='Output PDF file path (e.g., security-report.pdf)')

    # Optional metadata (auto-detected if not provided)
    parser.add_argument('--project-path', default=None,
                       help='Path to project root (for better auto-detection)')
    parser.add_argument('--project-name', default=None,
                       help='Project name (auto-detected from pom.xml/package.json if not provided)')
    parser.add_argument('--git-url', default=None,
                       help='Git repository URL (auto-detected via git command if not provided)')
    parser.add_argument('--git-branch', default=None,
                       help='Git branch name (auto-detected via git command if not provided)')
    parser.add_argument('--developer', default=None,
                       help='Developer name (auto-detected from git commit if not provided)')
    parser.add_argument('--devops-engineer', default=None,
                       help='DevOps engineer name (from BUILD_USER env or "DevOps Team")')
    parser.add_argument('--contact-email', default=None,
                       help='Contact email (default: security@ttsme.com)')
    parser.add_argument('--build-number', default=None,
                       help='Build number (from BUILD_NUMBER env or "000")')
    parser.add_argument('--scan-date', default=None,
                       help='Scan date (default: current timestamp)')

    return parser.parse_args()


# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Parse arguments
args = parse_arguments()

# Get metadata
metadata = get_metadata(args)

# Use metadata in variables (for backward compatibility with existing code)
PROJECT_NAME = metadata['project_name']
DOCUMENT_NUMBER = metadata['document_number']
DEVELOPER_NAME = metadata['developer']
DEVOPS_ENGINEER = metadata['devops_engineer']
CONTACT_EMAIL = metadata['contact_email']
GIT_URL = metadata['git_url']
GIT_BRANCH = metadata['git_branch']

print(f'Project: {PROJECT_NAME}')
print(f'Document: {DOCUMENT_NUMBER}\n')

# Install required packages
def install_package(package):
    try:
        __import__(package)
        return True
    except ImportError:
        print(f'Installing {package}...')
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package, '--quiet'])
            return True
        except:
            print(f'Failed to install {package}, using basic PDF generation')
            return False

has_reportlab = install_package('reportlab')

if has_reportlab:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle, Paragraph,
                                    Spacer, PageBreak, Image as RLImage, KeepTogether)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics import renderPDF
    from reportlab.lib.colors import HexColor

print('Processing scan results...')

# Change to input directory to read JSON files
original_dir = os.getcwd()
os.chdir(args.input_dir)

# Initialize statistics
issues_found = []
stats = {
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
    'info': 0,
    'total': 0
}

# Tool-specific counters
tool_stats = {
    'Semgrep': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
    'Trivy': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
    'TruffleHog': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
}

# Process Semgrep results
print('Processing Semgrep results...')
try:
    if os.path.exists('semgrep.json'):
        with open('semgrep.json', 'r') as f:
            semgrep_data = json.load(f)
            results = semgrep_data.get('results', [])

            for result in results:
                severity = result.get('extra', {}).get('severity', 'INFO').upper()
                if severity == 'ERROR':
                    severity = 'HIGH'
                elif severity == 'WARNING':
                    severity = 'MEDIUM'

                issue = {
                    'tool': 'Semgrep',
                    'type': 'Code Security',
                    'severity': severity,
                    'file': result.get('path', 'Unknown')[:80],
                    'line': result.get('start', {}).get('line', 0),
                    'title': result.get('check_id', 'Unknown'),
                    'details': result.get('extra', {}).get('message', 'No description')[:200]
                }
                issues_found.append(issue)

                sev_lower = severity.lower()
                if sev_lower in stats:
                    stats[sev_lower] += 1
                    tool_stats['Semgrep'][sev_lower] += 1
                stats['total'] += 1
                tool_stats['Semgrep']['total'] += 1

            print(f'  Found {len(results)} Semgrep issues')
except Exception as e:
    print(f'  Semgrep processing error: {e}')

# Process Trivy results
print('Processing Trivy results...')
trivy_count = 0
try:
    if os.path.exists('trivy.json'):
        with open('trivy.json', 'r') as f:
            trivy_data = json.load(f)

            for result in trivy_data.get('Results', []):
                # Process vulnerabilities
                for vuln in result.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', 'UNKNOWN').upper()

                    issue = {
                        'tool': 'Trivy',
                        'type': 'Vulnerability',
                        'severity': severity,
                        'file': result.get('Target', 'Unknown')[:80],
                        'line': 0,
                        'title': '{} - {}'.format(vuln.get('PkgName', 'Unknown'), vuln.get('VulnerabilityID', '')),
                        'details': 'Version: {} | Fix: {}'.format(
                            vuln.get('InstalledVersion', '?'),
                            vuln.get('FixedVersion', 'No fix available')
                        )
                    }
                    issues_found.append(issue)

                    sev_lower = severity.lower()
                    if sev_lower in stats:
                        stats[sev_lower] += 1
                        tool_stats['Trivy'][sev_lower] += 1
                    stats['total'] += 1
                    tool_stats['Trivy']['total'] += 1
                    trivy_count += 1

                # Process misconfigurations
                for misconfig in result.get('Misconfigurations', []):
                    severity = misconfig.get('Severity', 'UNKNOWN').upper()

                    issue = {
                        'tool': 'Trivy',
                        'type': 'Misconfiguration',
                        'severity': severity,
                        'file': result.get('Target', 'Unknown')[:80],
                        'line': misconfig.get('CauseMetadata', {}).get('StartLine', 0),
                        'title': '{} - {}'.format(misconfig.get('ID', 'Unknown'), misconfig.get('Title', '')),
                        'details': misconfig.get('Description', 'No description')[:200]
                    }
                    issues_found.append(issue)

                    sev_lower = severity.lower()
                    if sev_lower in stats:
                        stats[sev_lower] += 1
                        tool_stats['Trivy'][sev_lower] += 1
                    stats['total'] += 1
                    tool_stats['Trivy']['total'] += 1
                    trivy_count += 1

                # Process secrets
                for secret in result.get('Secrets', []):
                    severity = secret.get('Severity', 'HIGH').upper()

                    issue = {
                        'tool': 'Trivy',
                        'type': 'Secret',
                        'severity': severity,
                        'file': result.get('Target', 'Unknown')[:80],
                        'line': secret.get('StartLine', 0),
                        'title': secret.get('Title', 'Secret detected'),
                        'details': secret.get('RuleID', 'Secret found - hidden for security')
                    }
                    issues_found.append(issue)

                    sev_lower = severity.lower()
                    if sev_lower in stats:
                        stats[sev_lower] += 1
                        tool_stats['Trivy'][sev_lower] += 1
                    stats['total'] += 1
                    tool_stats['Trivy']['total'] += 1
                    trivy_count += 1

            print(f'  Found {trivy_count} Trivy issues')
except Exception as e:
    print(f'  Trivy processing error: {e}')

# Process TruffleHog results
print('Processing TruffleHog results...')
try:
    if os.path.exists('trufflehog.json'):
        with open('trufflehog.json', 'r') as f:
            trufflehog_data = json.load(f)

            for secret in trufflehog_data.get('secrets', []):
                source = secret.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {})

                issue = {
                    'tool': 'TruffleHog',
                    'type': 'Secret',
                    'severity': 'CRITICAL',
                    'file': source.get('file', 'Unknown')[:80],
                    'line': source.get('line', 0),
                    'title': secret.get('DetectorName', 'Secret detected'),
                    'details': 'Verified: {}'.format(secret.get('Verified', False))
                }
                issues_found.append(issue)
                stats['critical'] += 1
                tool_stats['TruffleHog']['critical'] += 1
                stats['total'] += 1
                tool_stats['TruffleHog']['total'] += 1

            print(f'  Found {len(trufflehog_data.get("secrets", []))} TruffleHog secrets')
except Exception as e:
    print(f'  TruffleHog processing error: {e}')

# Sort issues by severity
severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
issues_found.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['tool'], x['file']))

# Calculate risk score
if stats['total'] > 0:
    risk_score = min(10.0, (stats['critical'] * 4 + stats['high'] * 2 + stats['medium'] * 1) / 10.0)
else:
    risk_score = 0.0

# Determine risk level
if risk_score >= 7:
    risk_level = 'CRITICAL'
    risk_color = HexColor('#d32f2f')
elif risk_score >= 5:
    risk_level = 'HIGH'
    risk_color = HexColor('#f57c00')
elif risk_score >= 3:
    risk_level = 'MEDIUM'
    risk_color = HexColor('#fbc02d')
else:
    risk_level = 'LOW'
    risk_color = HexColor('#388e3c')

print('\nSummary:')
print('  Total issues: {}'.format(stats['total']))
print('  Critical: {}'.format(stats['critical']))
print('  High: {}'.format(stats['high']))
print('  Medium: {}'.format(stats['medium']))
print('  Low: {}'.format(stats['low']))
print('  Info: {}'.format(stats['info']))
print('  Risk Level: {} ({:.1f}/10)'.format(risk_level, risk_score))

# ============================================================================
# GENERATE PDF REPORT
# ============================================================================
print('\nGenerating comprehensive PDF report...')

# Change back to original directory for output
os.chdir(original_dir)

# Get absolute output path
output_pdf_path = Path(args.output_pdf).resolve()
output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

if has_reportlab:
    try:
        # Define severity colors
        SEVERITY_COLORS = {
            'CRITICAL': HexColor('#d32f2f'),
            'HIGH': HexColor('#f57c00'),
            'MEDIUM': HexColor('#fbc02d'),
            'LOW': HexColor('#1976d2'),
            'INFO': HexColor('#757575')
        }

        # Custom page template with header and footer
        class NumberedCanvas(canvas.Canvas):
            def __init__(self, *args, **kwargs):
                canvas.Canvas.__init__(self, *args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self.draw_page_number(num_pages)
                    canvas.Canvas.showPage(self)
                canvas.Canvas.save(self)

            def draw_page_number(self, page_count):
                # Footer with page number and document number (skip first page)
                if self._pageNumber > 1:
                    self.setFont("Helvetica", 8)
                    self.setFillColor(colors.grey)

                    # Left side: Confidential + Document Number
                    footer_left = "INTERNAL USE ONLY | Doc: {}".format(DOCUMENT_NUMBER)
                    self.drawString(1*cm, 1*cm, footer_left)

                    # Right side: Page numbers
                    page = "Page {} of {}".format(self._pageNumber, page_count)
                    self.drawRightString(A4[0] - 1*cm, 1*cm, page)

                # Header (skip first page)
                if self._pageNumber > 1:
                    self.setFont("Helvetica-Bold", 10)
                    self.setFillColor(HexColor('#1e3a5f'))
                    self.drawString(1*cm, A4[1] - 1.5*cm, "TTS Security Assessment Report")
                    self.drawRightString(A4[0] - 1*cm, A4[1] - 1.5*cm, PROJECT_NAME[:40])
                    # Horizontal line
                    self.setStrokeColor(colors.grey)
                    self.setLineWidth(0.5)
                    self.line(1*cm, A4[1] - 1.7*cm, A4[0] - 1*cm, A4[1] - 1.7*cm)

        # Create PDF document
        doc = SimpleDocTemplate(str(output_pdf_path), pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2.5*cm, bottomMargin=2*cm)
        story = []
        styles = getSampleStyleSheet()

        # ==================== CUSTOM STYLES ====================
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=HexColor('#1e3a5f'),
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=16,
            textColor=HexColor('#424242'),
            alignment=TA_CENTER,
            spaceAfter=30
        )

        heading1_style = ParagraphStyle(
            'CustomHeading1',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=HexColor('#1e3a5f'),
            spaceAfter=15,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        )

        heading2_style = ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#424242'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        )

        heading3_style = ParagraphStyle(
            'CustomHeading3',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=HexColor('#616161'),
            spaceAfter=8,
            spaceBefore=8,
            fontName='Helvetica-Bold'
        )

        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#212121'),
            alignment=TA_JUSTIFY,
            spaceAfter=10
        )

        # ==================== COVER PAGE ====================
        # Add TTS company logo
        logo_path = '/usr/local/bin/security-scripts/logo.png'
        if os.path.exists(logo_path):
            try:
                logo = RLImage(logo_path, width=4*inch, height=0.8*inch, kind='proportional')
                story.append(logo)
                story.append(Spacer(1, 0.2*inch))
            except Exception as e:
                print(f'  Warning: Could not load logo: {e}')
        else:
            print(f'  Warning: Logo not found at {logo_path}')

        # Company tagline
        tagline_style = ParagraphStyle(
            'Tagline',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#666666'),
            alignment=TA_CENTER,
            spaceAfter=20
        )
        story.append(Paragraph('When No One Has the Answers™', tagline_style))
        story.append(Spacer(1, 0.5*inch))

        # Main title
        story.append(Paragraph('TTS SECURITY ASSESSMENT REPORT', title_style))
        story.append(Spacer(1, 0.1*inch))

        # Subtitle
        subtitle2_style = ParagraphStyle(
            'Subtitle2',
            parent=styles['Normal'],
            fontSize=12,
            textColor=HexColor('#666666'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        story.append(Paragraph('Comprehensive Security Scan Analysis', subtitle2_style))
        story.append(Spacer(1, 0.3*inch))

        # Document details table
        doc_data = [
            ['Document Number:', DOCUMENT_NUMBER],
            ['Project Name:', html_escape(PROJECT_NAME)],
            ['Scan Date:', metadata['scan_date']],
            ['Jenkins Build:', '#{}'.format(metadata['build_number'])],
            ['Git Repository:', html_escape(GIT_URL[:60])],
            ['Git Branch:', html_escape(GIT_BRANCH)],
            ['Contact Email:', CONTACT_EMAIL],
            ['Developer:', html_escape(DEVELOPER_NAME)],
            ['DevOps Engineer:', html_escape(DEVOPS_ENGINEER)],
            ['Total Findings:', str(stats['total'])]
        ]

        doc_table = Table(doc_data, colWidths=[4*cm, 11*cm])
        doc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#1e3a5f')),
            ('BACKGROUND', (1, 0), (1, -1), HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#212121')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(doc_table)
        story.append(Spacer(1, 0.4*inch))

        # Risk level banner
        risk_banner_style = ParagraphStyle(
            'RiskBanner',
            parent=styles['Normal'],
            fontSize=20,
            textColor=colors.white,
            alignment=TA_CENTER,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        )

        risk_banner_table = Table(
            [[Paragraph('OVERALL RISK LEVEL: {} ({:.1f}/10)'.format(risk_level, risk_score), risk_banner_style)]],
            colWidths=[15*cm]
        )
        risk_banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(risk_banner_table)
        story.append(Spacer(1, 0.5*inch))

        # Confidentiality notice
        confidential_style = ParagraphStyle(
            'Confidential',
            parent=styles['Normal'],
            fontSize=11,
            textColor=HexColor('#d32f2f'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        story.append(Paragraph('INTERNAL USE ONLY', confidential_style))

        story.append(PageBreak())

        # ==================== EXECUTIVE SUMMARY ====================
        story.append(Paragraph('EXECUTIVE SUMMARY', heading1_style))
        story.append(Spacer(1, 0.2*inch))

        summary_text = """
        This comprehensive security assessment report presents findings from automated security scanning
        performed on <b>{}</b>. The analysis includes Static Application Security Testing (SAST),
        Software Composition Analysis (SCA), and Secret Detection across the entire codebase.
        """.format(html_escape(PROJECT_NAME))
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.2*inch))

        # Statistics summary table
        summary_data = [
            ['Metric', 'Count', 'Percentage', 'Risk Impact'],
            ['CRITICAL', str(stats['critical']),
             '{:.1f}%'.format((stats['critical']/max(stats['total'],1))*100),
             '⚠ Immediate Action Required'],
            ['HIGH', str(stats['high']),
             '{:.1f}%'.format((stats['high']/max(stats['total'],1))*100),
             '⚠ Priority Remediation'],
            ['MEDIUM', str(stats['medium']),
             '{:.1f}%'.format((stats['medium']/max(stats['total'],1))*100),
             '⚡ Planned Fix'],
            ['LOW', str(stats['low']),
             '{:.1f}%'.format((stats['low']/max(stats['total'],1))*100),
             '📋 Monitor'],
            ['INFO', str(stats['info']),
             '{:.1f}%'.format((stats['info']/max(stats['total'],1))*100),
             'ℹ Informational'],
            ['TOTAL', str(stats['total']), '100%', '']
        ]

        summary_table = Table(summary_data, colWidths=[3*cm, 2*cm, 2.5*cm, 5.5*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#ffebee')),
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#fff3e0')),
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#fffde7')),
            ('BACKGROUND', (0, 4), (-1, 4), HexColor('#e3f2fd')),
            ('BACKGROUND', (0, 5), (-1, 5), HexColor('#f5f5f5')),
            ('BACKGROUND', (0, 6), (-1, 6), HexColor('#e0e0e0')),
            ('FONTNAME', (0, 6), (-1, 6), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # ==================== PIE CHART ====================
        if stats['total'] > 0:
            story.append(Paragraph('Findings by Severity', heading2_style))

            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 150
            pie.height = 150
            pie.data = [
                stats['critical'], stats['high'], stats['medium'],
                stats['low'], stats['info']
            ]
            pie.labels = [
                'Critical: {}'.format(stats['critical']),
                'High: {}'.format(stats['high']),
                'Medium: {}'.format(stats['medium']),
                'Low: {}'.format(stats['low']),
                'Info: {}'.format(stats['info'])
            ]
            pie.slices.strokeWidth = 0.5
            pie.slices[0].fillColor = SEVERITY_COLORS['CRITICAL']
            pie.slices[1].fillColor = SEVERITY_COLORS['HIGH']
            pie.slices[2].fillColor = SEVERITY_COLORS['MEDIUM']
            pie.slices[3].fillColor = SEVERITY_COLORS['LOW']
            pie.slices[4].fillColor = SEVERITY_COLORS['INFO']
            drawing.add(pie)
            story.append(drawing)
            story.append(Spacer(1, 0.2*inch))

        # ==================== BAR CHART ====================
        story.append(Paragraph('Findings by Security Tool', heading2_style))

        drawing = Drawing(400, 200)
        bar = VerticalBarChart()
        bar.x = 50
        bar.y = 50
        bar.height = 125
        bar.width = 300
        bar.data = [
            [tool_stats['Semgrep']['total'],
             tool_stats['Trivy']['total'],
             tool_stats['TruffleHog']['total']]
        ]
        bar.categoryAxis.categoryNames = ['Semgrep\n(SAST)', 'Trivy\n(SCA)', 'TruffleHog\n(Secrets)']
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = max([tool_stats['Semgrep']['total'],
                                      tool_stats['Trivy']['total'],
                                      tool_stats['TruffleHog']['total']], default=10) * 1.2
        bar.bars[0].fillColor = HexColor('#1976d2')
        drawing.add(bar)
        story.append(drawing)
        story.append(Spacer(1, 0.3*inch))

        # Key findings
        story.append(Paragraph('Key Findings', heading2_style))
        key_findings = []
        if stats['critical'] > 0:
            key_findings.append('• <b>{} CRITICAL</b> issues require immediate attention and remediation'.format(stats['critical']))
        if stats['high'] > 0:
            key_findings.append('• <b>{} HIGH</b> severity vulnerabilities identified in code and dependencies'.format(stats['high']))
        if tool_stats['TruffleHog']['total'] > 0:
            key_findings.append('• <b>{} secrets</b> detected that may expose credentials or API keys'.format(tool_stats['TruffleHog']['total']))
        if stats['medium'] > 0:
            key_findings.append('• <b>{} MEDIUM</b> severity issues should be addressed in upcoming sprints'.format(stats['medium']))
        if stats['total'] == 0:
            key_findings.append('• ✅ <b>No security issues detected</b> - excellent security posture')

        for finding in key_findings:
            story.append(Paragraph(finding, body_style))

        story.append(PageBreak())

        # ==================== DETAILED FINDINGS ====================
        story.append(Paragraph('DETAILED FINDINGS', heading1_style))
        story.append(Spacer(1, 0.2*inch))

        # Group issues by severity and create tables
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_issues = [i for i in issues_found if i['severity'] == severity]
            if not severity_issues:
                continue

            # Severity header
            story.append(Paragraph(
                '<para backColor="{}" textColor="white" fontSize="14" spaceAfter="10">'
                '<b>{} SEVERITY - {} Issues</b></para>'.format(
                    SEVERITY_COLORS[severity], severity, len(severity_issues)
                ),
                body_style
            ))
            story.append(Spacer(1, 0.1*inch))

            # Create table
            table_data = [['#', 'Tool', 'File:Line', 'Issue', 'Details']]

            for idx, issue in enumerate(severity_issues[:50], 1):  # Limit to 50 per severity
                location = '{}:{}'.format(issue['file'][:30], issue['line']) if issue['line'] > 0 else issue['file'][:30]

                table_data.append([
                    str(idx),
                    issue['tool'],
                    Paragraph('<font size="7">{}</font>'.format(html_escape(location)), body_style),
                    Paragraph('<font size="7"><b>{}</b></font>'.format(html_escape(issue['title'][:60])), body_style),
                    Paragraph('<font size="7">{}</font>'.format(html_escape(issue['details'][:80])), body_style)
                ])

            issue_table = Table(table_data, colWidths=[0.8*cm, 1.5*cm, 3.5*cm, 4.5*cm, 4.7*cm])
            issue_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#424242')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f5f5f5')])
            ]))
            story.append(issue_table)
            story.append(Spacer(1, 0.3*inch))

        story.append(PageBreak())

        # ==================== RECOMMENDATIONS ====================
        story.append(Paragraph('RECOMMENDATIONS', heading1_style))
        story.append(Spacer(1, 0.2*inch))

        recommendations = []
        if stats['critical'] > 0:
            recommendations.append(('IMMEDIATE ACTION',
                'Address all {} CRITICAL issues within 24-48 hours. These represent severe security risks.'.format(stats['critical'])))
        if stats['high'] > 0:
            recommendations.append(('HIGH PRIORITY',
                'Remediate {} HIGH severity vulnerabilities within 1-2 weeks.'.format(stats['high'])))

        recommendations.extend([
            ('SECURITY PRACTICES', 'Implement pre-commit hooks to prevent secrets from being committed.'),
            ('CI/CD INTEGRATION', 'Integrate security scanning into CI/CD pipeline.'),
            ('REGULAR SCANNING', 'Schedule automated security scans weekly.')
        ])

        for idx, (title, desc) in enumerate(recommendations, 1):
            rec_box = Table([[Paragraph('<b>{}. {}</b>'.format(idx, title), heading3_style)],
                           [Paragraph(desc, body_style)]],
                          colWidths=[15*cm])
            rec_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e3f2fd')),
                ('BACKGROUND', (0, 1), (-1, 1), colors.white),
                ('BOX', (0, 0), (-1, -1), 1, HexColor('#1976d2')),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10)
            ]))
            story.append(rec_box)
            story.append(Spacer(1, 0.15*inch))

        # Build PDF
        doc.build(story, canvasmaker=NumberedCanvas)
        print(f'  ✅ PDF report generated: {output_pdf_path}')

    except Exception as e:
        print(f'  ❌ PDF generation error: {e}')
        import traceback
        traceback.print_exc()

else:
    print('  ❌ ReportLab not available, cannot generate PDF')

# Save summary JSON
summary = {
    'total': stats['total'],
    'critical': stats['critical'],
    'high': stats['high'],
    'medium': stats['medium'],
    'low': stats['low'],
    'info': stats['info'],
    'risk_level': risk_level,
    'risk_score': round(risk_score, 1)
}

summary_file = output_pdf_path.parent / 'summary.json'
summary_file.write_text(json.dumps(summary, indent=2))

print('\n✅ Report generation completed!')
print(f'📊 Files created:')
print(f'   - {output_pdf_path}')
print(f'   - {summary_file}')
print(f'\n🎯 Total findings: {stats["total"]} ({stats["critical"]} critical, {stats["high"]} high)')
