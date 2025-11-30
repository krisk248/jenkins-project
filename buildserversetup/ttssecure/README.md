# TTS Security Scanning Module (ttssecure)

A modular, production-grade security scanning framework for TTS Jenkins CI/CD pipelines.

## Features

- **6 Security Scanners**: Semgrep (SAST), Trivy (SCA), TruffleHog (Secrets), SpotBugs (Java), OWASP Dependency-Check, ESLint Security
- **3 Report Formats**: Professional PDF, Web HTML, Machine-readable JSON
- **Configurable Thresholds**: Fail builds based on finding severity
- **Auto Project Detection**: Automatically detects Maven, Angular, Gulp projects
- **Report Archiving**: Automatic compression after 30 days
- **Retry Logic**: Automatic retry on scanner failure

## Quick Start

### 1. Install Dependencies (using pipenv)

```bash
cd /home/ttsbuild/jenkins-automation/buildserversetup/ttssecure

# Install pipenv if not installed
pip install --user pipenv

# Install dependencies from Pipfile
pipenv install

# Run commands using pipenv run
pipenv run python ttssecure.py --help
```

### 2. Create Project Configuration

Copy the template and customize:

```bash
cp configs/template.yaml configs/myproject.yaml
# Edit configs/myproject.yaml
```

### 3. Run Security Scan

```bash
# Basic scan
./ttssecure.py --config configs/adxsip-backend.yaml

# With CLI overrides
./ttssecure.py --config configs/adxsip-backend.yaml \
  --branch develop \
  --build-number 42

# Dry run (show what would run)
./ttssecure.py --config configs/adxsip-backend.yaml --dry-run

# Verbose output
./ttssecure.py --config configs/adxsip-backend.yaml --verbose
```

## Configuration

### YAML Configuration File

```yaml
project:
  name: "ADXSIP"
  component: "backend"
  type: "maven"  # auto, maven, angular, gulp

source:
  path: "/tts/ttsbuild/ADXSIP/tts-uae-adx-sip-serverside"
  git_url: "https://github.com/org/repo.git"
  default_branch: "main"

metadata:
  developer_team: "ADXSIP Team"
  developer_contact: "dev@ttsme.com"
  devsecops_contact: "devsecops@ttsme.com"
  qa_url: "http://192.168.1.136:9993/ADXSIP"

output:
  base_dir: "/tts/securityreports"
  archive_dir: "/tts/archive/security"
  retention_days: 30

scanners:
  semgrep:
    enabled: true
    config: "auto"
    timeout: 600
  trivy:
    enabled: true
  trufflehog:
    enabled: true
  spotbugs:
    enabled: true    # Java only
  owasp_dependency:
    enabled: true
  eslint_security:
    enabled: false   # JS/TS only

threshold:
  max_critical: 0
  max_high: 10
  fail_on_secrets: true
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `--config, -c` | Path to YAML configuration (required) |
| `--branch, -b` | Git branch name (overrides config) |
| `--build-number, -n` | Jenkins build number |
| `--skip` | Comma-separated scanners to skip |
| `--output-dir, -o` | Override output directory |
| `--verbose, -v` | Enable verbose logging |
| `--dry-run` | Show what would run without executing |
| `--archive` | Run archiver to compress old reports |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - all thresholds passed |
| 1 | Error - configuration, missing files, etc. |
| 2 | Threshold exceeded - findings exceed limits |
| 3 | Partial failure - some scanners failed |

## Output

Reports are saved to: `/tts/securityreports/{PROJECT}/{BUILD_NUMBER}/`

```
/tts/securityreports/ADXSIP/42/
├── TTS_SEC_ADXSIP_QA42-113025.pdf    # Professional PDF report
├── TTS_SEC_ADXSIP_QA42-113025.html   # Web-viewable HTML
├── TTS_SEC_ADXSIP_QA42-113025.json   # Machine-readable JSON
├── scan.log                           # Execution log
└── raw/                               # Raw scanner outputs
    ├── semgrep.json
    ├── trivy.json
    └── trufflehog.json
```

## Jenkins Integration

### In Jenkinsfile

```groovy
stage('Security Scan') {
    steps {
        sh '''
            cd /home/ttsbuild/jenkins-automation/buildserversetup/ttssecure
            pipenv run python ttssecure.py \
                --config configs/adxsip-backend.yaml \
                --branch "${GIT_BRANCH}" \
                --build-number "${BUILD_NUMBER}"
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: '/tts/securityreports/ADXSIP/${BUILD_NUMBER}/*.pdf', allowEmptyArchive: true
        }
    }
}
```

### Using Shared Library

```groovy
// In securityScan.groovy
def call(Map config = [:]) {
    def projectConfig = config.get('config', 'configs/adxsip-backend.yaml')
    def branch = config.get('branch', env.GIT_BRANCH ?: 'main')
    def buildNum = config.get('buildNumber', env.BUILD_NUMBER ?: '0')

    sh """
        cd /home/ttsbuild/jenkins-automation/buildserversetup/ttssecure
        pipenv run python ttssecure.py \\
            --config ${projectConfig} \\
            --branch "${branch}" \\
            --build-number "${buildNum}"
    """
}
```

## Required Tools

Ensure these are installed on the build server:

- **Python 3.10+** with pipenv
- **Semgrep**: `pip install semgrep`
- **Trivy**: Already installed (v0.58.2)
- **TruffleHog**: Already installed (v3.63.7)
- **SpotBugs** (optional): `sudo apt install spotbugs`
- **OWASP Dependency-Check** (optional): Download from OWASP
- **ESLint** (optional): `npm install -g eslint eslint-plugin-security`

## Directory Structure

```
ttssecure/
├── ttssecure.py       # Main entry point
├── config/            # Configuration loading
├── scanners/          # Scanner implementations
├── reports/           # Report generators
├── utils/             # Utilities
├── configs/           # Project configurations
└── assets/            # Logo and assets
```

## Troubleshooting

### Scanner not running
- Check if tool is installed: `which semgrep`
- Verify config has `enabled: true`
- Check it's not in `--skip` list

### Report generation fails
- Check disk space
- Verify output directory is writable
- Check reportlab is installed: `pip install reportlab`

### Threshold exceeded
- Review findings in PDF/HTML report
- Adjust thresholds in YAML config
- Fix critical/high issues before rerunning

## Version

- **Version**: 1.0.0
- **Date**: 2025-11-30
- **Author**: TTS DevSecOps Team
