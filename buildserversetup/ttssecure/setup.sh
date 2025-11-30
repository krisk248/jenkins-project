#!/bin/bash
#
# TTS Security Scanning Module - Setup Script
# This script sets up the environment and validates the installation
#
# Usage: ./setup.sh [--install-only | --test-only | --full]
#
# Exit Codes:
#   0 - Success
#   1 - OS check failed
#   2 - Python check failed
#   3 - Pipenv check/install failed
#   4 - Dependencies install failed
#   5 - Dry run test failed
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/setup_error.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Logging function
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error logging for LLM diagnosis
write_error_log() {
    local error_code=$1
    local error_phase=$2
    local error_message=$3
    local suggested_fix=$4

    cat > "$LOG_FILE" << EOF
================================================================================
TTS SECURE SETUP ERROR LOG
Generated: ${TIMESTAMP}
================================================================================

ERROR SUMMARY
-------------
Error Code: ${error_code}
Phase: ${error_phase}
Message: ${error_message}

SYSTEM INFORMATION
------------------
OS: $(uname -s)
OS Version: $(uname -r)
Architecture: $(uname -m)
Hostname: $(hostname)
User: $(whoami)
Working Directory: ${SCRIPT_DIR}

ENVIRONMENT
-----------
Python Version: $(python3 --version 2>/dev/null || echo "NOT FOUND")
Pip Version: $(pip3 --version 2>/dev/null || echo "NOT FOUND")
Pipenv Version: $(pipenv --version 2>/dev/null || echo "NOT FOUND")
PATH: ${PATH}

FILES IN DIRECTORY
------------------
$(ls -la "${SCRIPT_DIR}" 2>/dev/null || echo "Cannot list directory")

SUGGESTED FIX
-------------
${suggested_fix}

DIAGNOSTIC COMMANDS
-------------------
To diagnose this issue, run these commands:

1. Check Python: python3 --version
2. Check pip: pip3 --version
3. Check pipenv: pipenv --version
4. Check permissions: ls -la ${SCRIPT_DIR}
5. Check disk space: df -h

RAW ERROR OUTPUT
----------------
${error_message}

================================================================================
For LLM Analysis: This log file is formatted for AI assistant diagnosis.
Provide this file content to get step-by-step resolution instructions.
================================================================================
EOF

    log_error "Error log written to: ${LOG_FILE}"
    log_error "Share this log file for diagnosis assistance."
}

# Check OS
check_os() {
    log "Checking operating system..."

    OS_TYPE=$(uname -s)

    case "$OS_TYPE" in
        Linux)
            log_success "Linux detected"

            # Check distribution
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                log "Distribution: ${NAME} ${VERSION}"
            fi
            ;;
        Darwin)
            log_success "macOS detected"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            log_warn "Windows environment detected (Git Bash/MSYS/Cygwin)"
            log_warn "Some features may not work as expected"
            ;;
        *)
            write_error_log 1 "OS Check" \
                "Unsupported operating system: ${OS_TYPE}" \
                "This script supports Linux, macOS, and Windows (Git Bash). Please use a supported OS or modify the script for your environment."
            return 1
            ;;
    esac

    return 0
}

# Check Python
check_python() {
    log "Checking Python installation..."

    if ! command -v python3 &> /dev/null; then
        write_error_log 2 "Python Check" \
            "Python 3 is not installed or not in PATH" \
            "Install Python 3.10+:
- Ubuntu/Debian: sudo apt install python3 python3-pip
- CentOS/RHEL: sudo yum install python3 python3-pip
- macOS: brew install python3"
        return 1
    fi

    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    log "Python version: ${PYTHON_VERSION}"

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
        write_error_log 2 "Python Check" \
            "Python version ${PYTHON_VERSION} is too old. Requires 3.10+" \
            "Upgrade Python to version 3.10 or higher:
- Ubuntu: sudo apt install python3.10
- Use pyenv: pyenv install 3.10.0 && pyenv global 3.10.0"
        return 1
    fi

    log_success "Python ${PYTHON_VERSION} OK"
    return 0
}

# Check/Install pipenv
check_pipenv() {
    log "Checking pipenv installation..."

    if command -v pipenv &> /dev/null; then
        PIPENV_VERSION=$(pipenv --version 2>/dev/null || echo "unknown")
        log_success "pipenv found: ${PIPENV_VERSION}"
        return 0
    fi

    log_warn "pipenv not found. Attempting to install..."

    # Try pip install
    if pip3 install --user pipenv 2>/dev/null; then
        log_success "pipenv installed via pip"

        # Add to PATH if needed
        export PATH="$HOME/.local/bin:$PATH"

        if command -v pipenv &> /dev/null; then
            return 0
        fi
    fi

    # Try pipx
    if command -v pipx &> /dev/null; then
        log "Trying pipx install..."
        if pipx install pipenv 2>/dev/null; then
            log_success "pipenv installed via pipx"
            return 0
        fi
    fi

    write_error_log 3 "Pipenv Check" \
        "Failed to install pipenv automatically" \
        "Install pipenv manually:
1. pip install --user pipenv
2. Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"
3. Or use pipx: pipx install pipenv

Then run this script again."
    return 1
}

# Clean existing environment
clean_environment() {
    log "Cleaning existing pipenv environment..."

    cd "$SCRIPT_DIR"

    # Remove Pipfile.lock if exists
    if [ -f "Pipfile.lock" ]; then
        rm -f Pipfile.lock
        log "Removed Pipfile.lock"
    fi

    # Remove existing Pipfile if exists (we'll create fresh from requirements.txt)
    if [ -f "Pipfile" ]; then
        rm -f Pipfile
        log "Removed existing Pipfile"
    fi

    # Remove existing virtual environment
    if pipenv --venv &> /dev/null; then
        pipenv --rm 2>/dev/null || true
        log "Removed existing virtual environment"
    fi

    log_success "Environment cleaned"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies with pipenv..."

    cd "$SCRIPT_DIR"

    # Check if requirements.txt exists
    if [ ! -f "requirements.txt" ]; then
        write_error_log 4 "Dependencies Install" \
            "requirements.txt not found in ${SCRIPT_DIR}" \
            "Create requirements.txt with the following content:
reportlab>=4.0.0
pillow>=10.0.0
pyyaml>=6.0.0
jinja2>=3.1.0
matplotlib>=3.5.0"
        return 1
    fi

    # Install from requirements.txt
    log "Running: pipenv install -r requirements.txt"

    if ! pipenv install -r requirements.txt 2>&1 | tee -a /tmp/pipenv_install.log; then
        INSTALL_ERROR=$(cat /tmp/pipenv_install.log 2>/dev/null || echo "Unknown error")
        write_error_log 4 "Dependencies Install" \
            "pipenv install failed: ${INSTALL_ERROR}" \
            "Try these steps:
1. Check internet connection
2. Clear pip cache: pip cache purge
3. Try manual install: pip install reportlab pillow pyyaml jinja2 matplotlib
4. Check for conflicting packages"
        return 1
    fi

    log_success "Dependencies installed successfully"
    return 0
}

# Run dry run test
run_dry_test() {
    log "Running dry run test..."

    cd "$SCRIPT_DIR"

    # Check if config exists
    if [ ! -f "configs/adxsip-backend.yaml" ]; then
        log_warn "Config file configs/adxsip-backend.yaml not found"
        log "Using template config for test..."

        if [ ! -f "configs/template.yaml" ]; then
            write_error_log 5 "Dry Run Test" \
                "No configuration files found in configs/" \
                "Create a configuration file in configs/ directory. Copy template.yaml and customize."
            return 1
        fi

        CONFIG_FILE="configs/template.yaml"
    else
        CONFIG_FILE="configs/adxsip-backend.yaml"
    fi

    log "Testing with config: ${CONFIG_FILE}"

    # Run dry run with pipenv
    if ! pipenv run python ttssecure.py --config "${CONFIG_FILE}" --dry-run 2>&1 | tee /tmp/dryrun.log; then
        DRY_RUN_ERROR=$(cat /tmp/dryrun.log 2>/dev/null || echo "Unknown error")
        write_error_log 5 "Dry Run Test" \
            "Dry run test failed: ${DRY_RUN_ERROR}" \
            "Check the following:
1. Python syntax errors in ttssecure.py
2. Missing imports or modules
3. Configuration file format
4. File permissions on source directories"
        return 1
    fi

    log_success "Dry run test passed!"
    return 0
}

# Check required directories
check_directories() {
    log "Checking required directories..."

    REPORT_DIR="/tts/securityreports"
    ARCHIVE_DIR="/tts/archive/security"

    if [ ! -d "$REPORT_DIR" ]; then
        log_warn "Report directory $REPORT_DIR does not exist"
        log "Creating directories (may require sudo)..."

        if sudo mkdir -p "$REPORT_DIR" "$ARCHIVE_DIR" 2>/dev/null; then
            sudo chown -R $(whoami):$(whoami) /tts 2>/dev/null || true
            log_success "Directories created"
        else
            log_warn "Could not create directories. You may need to run:"
            log_warn "  sudo mkdir -p $REPORT_DIR $ARCHIVE_DIR"
            log_warn "  sudo chown -R $(whoami):$(whoami) /tts"
        fi
    else
        log_success "Report directories exist"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "========================================"
    echo -e "${GREEN}TTS SECURE SETUP COMPLETE${NC}"
    echo "========================================"
    echo ""
    echo "Environment is ready. You can now run:"
    echo ""
    echo "  # Dry run (test mode):"
    echo "  pipenv run python ttssecure.py --config configs/adxsip-backend.yaml --dry-run"
    echo ""
    echo "  # Full scan:"
    echo "  pipenv run python ttssecure.py --config configs/adxsip-backend.yaml"
    echo ""
    echo "  # With build number:"
    echo "  pipenv run python ttssecure.py --config configs/adxsip-backend.yaml --build-number 123"
    echo ""
    echo "========================================"
}

# Main execution
main() {
    echo "========================================"
    echo "TTS Security Scanning Module - Setup"
    echo "========================================"
    echo ""

    MODE="${1:---full}"

    # Remove old error log
    rm -f "$LOG_FILE"

    # Step 1: Check OS
    if ! check_os; then
        exit 1
    fi

    # Step 2: Check Python
    if ! check_python; then
        exit 2
    fi

    # Step 3: Check/Install pipenv
    if ! check_pipenv; then
        exit 3
    fi

    if [ "$MODE" == "--test-only" ]; then
        run_dry_test
        exit $?
    fi

    # Step 4: Clean and install dependencies
    clean_environment

    if ! install_dependencies; then
        exit 4
    fi

    # Step 5: Check directories
    check_directories

    if [ "$MODE" == "--install-only" ]; then
        log_success "Installation complete (skipping test)"
        print_summary
        exit 0
    fi

    # Step 6: Run dry test
    if ! run_dry_test; then
        exit 5
    fi

    # Success
    print_summary
    exit 0
}

# Run main
main "$@"
