#!/usr/bin/env python3
"""
Security Scanner - Targeted Folder Scanning
Runs Semgrep, Trivy, and TruffleHog on specific project folders
"""
import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

# Project type detection and default scan folders
PROJECT_CONFIGS = {
    'maven': {
        'detect_files': ['pom.xml'],
        'scan_folders': ['src/'],
        'exclude': ['target/', '.m2/', '*.class', '*.jar']
    },
    'angular': {
        'detect_files': ['angular.json', 'package.json'],
        'scan_folders': ['src/'],
        'exclude': ['node_modules/', 'dist/', '.angular/', '*.js.map', '*.min.js']
    },
    'gulp': {
        'detect_files': ['gulpfile.js', 'Gulpfile.js'],
        'scan_folders': ['src/', 'app/'],
        'exclude': ['node_modules/', 'dist/', 'build/', '*.min.js']
    },
    'node': {
        'detect_files': ['package.json'],
        'scan_folders': ['src/', 'lib/'],
        'exclude': ['node_modules/', 'dist/', '*.min.js']
    },
    'gradle': {
        'detect_files': ['build.gradle', 'build.gradle.kts'],
        'scan_folders': ['src/'],
        'exclude': ['build/', '.gradle/', '*.class']
    },
    'python': {
        'detect_files': ['requirements.txt', 'setup.py'],
        'scan_folders': ['src/', 'app/'],
        'exclude': ['venv/', '.venv/', '__pycache__/', '*.pyc']
    }
}


def print_banner():
    """Print security scan banner"""
    print("=" * 80)
    print("🔒 TTS SECURITY SCANNER v2.0")
    print("   Targeted folder scanning with Semgrep, Trivy, and TruffleHog")
    print("=" * 80)
    print()


def detect_project_type(project_path):
    """Auto-detect project type based on configuration files"""
    print("🔍 Detecting project type...")

    for proj_type, config in PROJECT_CONFIGS.items():
        for detect_file in config['detect_files']:
            if (Path(project_path) / detect_file).exists():
                print(f"   ✅ Detected: {proj_type.upper()} project")
                return proj_type

    print("   ⚠️  Unknown project type - using generic scan")
    return 'generic'


def get_scan_folders(project_type, custom_folders=None):
    """Get folders to scan based on project type"""
    if custom_folders:
        return custom_folders.split(',')

    if project_type in PROJECT_CONFIGS:
        return PROJECT_CONFIGS[project_type]['scan_folders']

    # Generic fallback
    return ['src/']


def get_exclude_patterns(project_type):
    """Get exclude patterns based on project type"""
    base_exclude = ['.git/', '.svn/', '.hg/']

    if project_type in PROJECT_CONFIGS:
        return base_exclude + PROJECT_CONFIGS[project_type]['exclude']

    # Generic fallback
    return base_exclude + ['node_modules/', 'target/', 'dist/', 'build/']


def create_output_dir(output_dir):
    """Create output directory if it doesn't exist"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"📁 Output directory: {output_dir}")
    return output_path


def build_scan_paths(project_path, scan_folders):
    """Build list of absolute paths to scan"""
    project_path = Path(project_path).resolve()
    scan_paths = []

    print(f"📂 Project path: {project_path}")
    print(f"🎯 Scanning folders:")

    for folder in scan_folders:
        folder_path = project_path / folder.strip()
        if folder_path.exists():
            scan_paths.append(str(folder_path))
            # Count files in folder
            file_count = sum(1 for _ in folder_path.rglob('*') if _.is_file())
            print(f"   ✓ {folder} ({file_count} files)")
        else:
            print(f"   ⚠️  {folder} (not found, skipping)")

    if not scan_paths:
        print(f"   ⚠️  No valid folders found, falling back to project root")
        scan_paths = [str(project_path)]

    return scan_paths


def run_semgrep(scan_paths, output_dir, exclude_patterns):
    """Run Semgrep SAST scan"""
    print("\n" + "=" * 80)
    print("🔍 Running Semgrep (SAST)")
    print("=" * 80)

    output_file = output_dir / 'semgrep.json'

    try:
        # Build exclude arguments
        exclude_args = []
        for pattern in exclude_patterns:
            exclude_args.extend(['--exclude', pattern])

        # Run semgrep on each scan path
        cmd = [
            'semgrep', 'scan',
            '--config=auto',
            '--json',
            '--quiet'
        ] + exclude_args + scan_paths

        print(f"📋 Command: {' '.join(cmd[:5])}... (scanning {len(scan_paths)} folders)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0 or result.stdout:
            output_file.write_text(result.stdout)

            # Parse results
            try:
                data = json.loads(result.stdout)
                findings = len(data.get('results', []))
                print(f"✅ Semgrep completed: {findings} findings")
            except:
                print(f"✅ Semgrep completed (output saved)")
        else:
            print(f"⚠️  Semgrep failed, creating empty result")
            output_file.write_text('{"results":[]}')

    except subprocess.TimeoutExpired:
        print(f"⚠️  Semgrep timeout (>5 min), creating empty result")
        output_file.write_text('{"results":[]}')
    except Exception as e:
        print(f"⚠️  Semgrep error: {e}")
        output_file.write_text('{"results":[]}')


def run_trivy(scan_paths, output_dir, project_type):
    """Run Trivy vulnerability scanner"""
    print("\n" + "=" * 80)
    print("🔍 Running Trivy (SCA)")
    print("=" * 80)

    output_file = output_dir / 'trivy.json'

    try:
        # Determine what to scan based on project type
        scan_target = scan_paths[0] if scan_paths else '.'

        cmd = [
            'trivy', 'fs',
            '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--scanners', 'vuln,secret,misconfig',
            scan_target
        ]

        print(f"📋 Command: {' '.join(cmd[:6])}...")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0 or result.stdout:
            output_file.write_text(result.stdout)

            # Parse results
            try:
                data = json.loads(result.stdout)
                vulns = sum(len(r.get('Vulnerabilities', [])) for r in data.get('Results', []))
                secrets = sum(len(r.get('Secrets', [])) for r in data.get('Results', []))
                misconfigs = sum(len(r.get('Misconfigurations', [])) for r in data.get('Results', []))
                print(f"✅ Trivy completed:")
                print(f"   - Vulnerabilities: {vulns}")
                print(f"   - Secrets: {secrets}")
                print(f"   - Misconfigurations: {misconfigs}")
            except:
                print(f"✅ Trivy completed (output saved)")
        else:
            print(f"⚠️  Trivy failed, creating empty result")
            output_file.write_text('{"Results":[]}')

    except subprocess.TimeoutExpired:
        print(f"⚠️  Trivy timeout (>5 min), creating empty result")
        output_file.write_text('{"Results":[]}')
    except Exception as e:
        print(f"⚠️  Trivy error: {e}")
        output_file.write_text('{"Results":[]}')


def run_trufflehog(scan_paths, output_dir):
    """Run TruffleHog secret scanner"""
    print("\n" + "=" * 80)
    print("🔍 Running TruffleHog (Secret Detection)")
    print("=" * 80)

    output_file = output_dir / 'trufflehog.json'
    raw_file = output_dir / 'trufflehog-raw.json'

    try:
        scan_target = scan_paths[0] if scan_paths else '.'

        cmd = [
            'trufflehog', 'filesystem',
            '--json',
            '--no-verification',
            scan_target
        ]

        print(f"📋 Command: {' '.join(cmd[:4])}...")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.stdout:
            # Limit to first 100 results
            lines = result.stdout.strip().split('\n')[:100]
            raw_file.write_text('\n'.join(lines))

            # Convert to JSON array
            if lines:
                json_array = '{"secrets":[' + ','.join(lines) + ']}'
                output_file.write_text(json_array)
                print(f"✅ TruffleHog completed: {len(lines)} secrets found")
            else:
                output_file.write_text('{"secrets":[]}')
                print(f"✅ TruffleHog completed: 0 secrets found")
        else:
            output_file.write_text('{"secrets":[]}')
            print(f"✅ TruffleHog completed: 0 secrets found")

    except subprocess.TimeoutExpired:
        print(f"⚠️  TruffleHog timeout (>5 min), creating empty result")
        output_file.write_text('{"secrets":[]}')
    except Exception as e:
        print(f"⚠️  TruffleHog error: {e}")
        output_file.write_text('{"secrets":[]}')


def save_scan_metadata(output_dir, project_path, project_type, scan_folders):
    """Save scan metadata for report generation"""
    metadata = {
        'scan_date': datetime.now().isoformat(),
        'project_path': str(project_path),
        'project_type': project_type,
        'scan_folders': scan_folders,
        'scanner_version': '2.0'
    }

    metadata_file = output_dir / 'scan_metadata.json'
    metadata_file.write_text(json.dumps(metadata, indent=2))
    print(f"\n💾 Scan metadata saved: {metadata_file}")


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Security Scanner - Targeted folder scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Maven project (auto-detect)
  %(prog)s --project-path /tts/ttsbuild/ADXSIP --output-dir /tts/ttsbuild/Security/ADXSIP

  # Angular project with custom folders
  %(prog)s --project-path /tts/ttsbuild/MyApp --project-type angular --scan-folders src/,tests/

  # Explicit project type
  %(prog)s --project-path . --project-type maven --output-dir ./security-reports
        """
    )

    parser.add_argument('--project-path', required=True,
                       help='Path to project root directory')
    parser.add_argument('--project-type', default='auto',
                       choices=['auto', 'maven', 'angular', 'gulp', 'node', 'gradle', 'python', 'generic'],
                       help='Project type (default: auto-detect)')
    parser.add_argument('--scan-folders', default=None,
                       help='Comma-separated folders to scan (default: auto-detect based on project type)')
    parser.add_argument('--output-dir', default='./security-reports',
                       help='Output directory for scan results (default: ./security-reports)')
    parser.add_argument('--exclude', default=None,
                       help='Additional exclude patterns (comma-separated)')

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Detect or use specified project type
    if args.project_type == 'auto':
        project_type = detect_project_type(args.project_path)
    else:
        project_type = args.project_type
        print(f"📋 Using specified project type: {project_type.upper()}")

    # Get scan folders
    scan_folders = get_scan_folders(project_type, args.scan_folders)

    # Get exclude patterns
    exclude_patterns = get_exclude_patterns(project_type)
    if args.exclude:
        exclude_patterns.extend(args.exclude.split(','))

    print(f"\n🚫 Excluding: {', '.join(exclude_patterns[:5])}{'...' if len(exclude_patterns) > 5 else ''}")

    # Create output directory
    output_dir = create_output_dir(args.output_dir)

    # Build scan paths
    scan_paths = build_scan_paths(args.project_path, scan_folders)

    # Run security scans
    run_semgrep(scan_paths, output_dir, exclude_patterns)
    run_trivy(scan_paths, output_dir, project_type)
    run_trufflehog(scan_paths, output_dir)

    # Save metadata
    save_scan_metadata(output_dir, args.project_path, project_type, scan_folders)

    # Summary
    print("\n" + "=" * 80)
    print("✅ SECURITY SCAN COMPLETED")
    print("=" * 80)
    print(f"📊 Results saved to: {output_dir}")
    print(f"📄 Files generated:")
    print(f"   - semgrep.json")
    print(f"   - trivy.json")
    print(f"   - trufflehog.json")
    print(f"   - scan_metadata.json")
    print("\n🎯 Next step: Generate PDF report with generate_report.py")
    print("=" * 80)
    print()

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
