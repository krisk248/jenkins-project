"""
TTS Security Scanning Module (ttssecure)
=========================================

A modular security scanning framework for Jenkins CI/CD pipelines.

Supports:
- Multiple security scanners (Semgrep, Trivy, TruffleHog, SpotBugs, OWASP, ESLint)
- Professional PDF, HTML, and JSON report generation
- YAML-based project configuration
- Threshold-based build failure
- Automated archiving of old reports

Usage:
    ttssecure.py --config project.yaml --branch develop --build-number 42

Author: TTS DevSecOps Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "TTS DevSecOps Team"
