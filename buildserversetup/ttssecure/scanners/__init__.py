"""Security scanner modules for ttssecure."""

from .base import BaseScanner, ScanResult, Finding
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner
from .trufflehog import TruffleHogScanner
from .spotbugs import SpotBugsScanner
from .owasp_dependency import OWASPDependencyScanner
from .eslint_security import ESLintSecurityScanner

__all__ = [
    "BaseScanner",
    "ScanResult",
    "Finding",
    "SemgrepScanner",
    "TrivyScanner",
    "TruffleHogScanner",
    "SpotBugsScanner",
    "OWASPDependencyScanner",
    "ESLintSecurityScanner",
]

# Scanner registry for easy instantiation
SCANNER_REGISTRY = {
    "semgrep": SemgrepScanner,
    "trivy": TrivyScanner,
    "trufflehog": TruffleHogScanner,
    "spotbugs": SpotBugsScanner,
    "owasp_dependency": OWASPDependencyScanner,
    "eslint_security": ESLintSecurityScanner,
}


def get_scanner(name: str) -> type:
    """Get scanner class by name."""
    if name not in SCANNER_REGISTRY:
        raise ValueError(f"Unknown scanner: {name}")
    return SCANNER_REGISTRY[name]
