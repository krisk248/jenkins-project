#!/bin/bash
# ============================================================================
# BUILD SERVER SETUP SCRIPT
# ============================================================================
# This script installs all security scanning tools and dependencies
# on the Jenkins build agent (Ubuntu server)
#
# Run as: ./install.sh
# ============================================================================

set -e

echo "============================================================================"
echo "🚀 TTS Jenkins Build Server Setup"
echo "============================================================================"
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ============================================================================
# STEP 1: Check Python Installation
# ============================================================================
echo "============================================================================"
echo "STEP 1: Checking Python Installation"
echo "============================================================================"

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✅ Python3 is installed: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}❌ Python3 is not installed${NC}"
    echo "Installing Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip
fi

if command -v pip3 &> /dev/null; then
    PIP_VERSION=$(pip3 --version)
    echo -e "${GREEN}✅ pip3 is installed: $PIP_VERSION${NC}"
else
    echo -e "${RED}❌ pip3 is not installed${NC}"
    echo "Installing pip3..."
    sudo apt install -y python3-pip
fi

echo ""

# ============================================================================
# STEP 2: Install Python Dependencies
# ============================================================================
echo "============================================================================"
echo "STEP 2: Installing Python Dependencies"
echo "============================================================================"

echo "Installing system packages: python3-requests, python3-yaml, python3-reportlab, python3-pil..."
sudo apt update -qq
sudo apt install -y python3-requests python3-yaml python3-reportlab python3-pil

echo -e "${GREEN}✅ Python dependencies installed${NC}"
echo ""

# ============================================================================
# STEP 3: Install Semgrep
# ============================================================================
echo "============================================================================"
echo "STEP 3: Installing Semgrep (SAST Scanner)"
echo "============================================================================"

if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version)
    echo -e "${YELLOW}⚠️  Semgrep already installed: $SEMGREP_VERSION${NC}"
else
    echo "Installing Semgrep..."
    # Install Semgrep via pipx for isolated installation
    sudo apt install -y pipx
    pipx install semgrep
    pipx ensurepath

    # Add to PATH if not already there
    if ! grep -q '$HOME/.local/bin' ~/.bashrc; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        export PATH="$HOME/.local/bin:$PATH"
    fi
fi

# Verify installation
if command -v semgrep &> /dev/null; then
    echo -e "${GREEN}✅ Semgrep installed successfully${NC}"
    semgrep --version
else
    echo -e "${RED}❌ Semgrep installation failed${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 4: Install Trivy
# ============================================================================
echo "============================================================================"
echo "STEP 4: Installing Trivy (Dependency Scanner)"
echo "============================================================================"

if command -v trivy &> /dev/null; then
    TRIVY_VERSION=$(trivy --version)
    echo -e "${YELLOW}⚠️  Trivy already installed: $TRIVY_VERSION${NC}"
else
    echo "Installing Trivy..."

    # Download and install Trivy
    TRIVY_VERSION="0.48.0"
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    sudo dpkg -i "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    rm "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
fi

# Verify installation
if command -v trivy &> /dev/null; then
    echo -e "${GREEN}✅ Trivy installed successfully${NC}"
    trivy --version
else
    echo -e "${RED}❌ Trivy installation failed${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 5: Install TruffleHog
# ============================================================================
echo "============================================================================"
echo "STEP 5: Installing TruffleHog (Secret Scanner)"
echo "============================================================================"

if command -v trufflehog &> /dev/null; then
    TRUFFLEHOG_VERSION=$(trufflehog --version)
    echo -e "${YELLOW}⚠️  TruffleHog already installed: $TRUFFLEHOG_VERSION${NC}"
else
    echo "Installing TruffleHog..."

    # Download and install TruffleHog
    TRUFFLEHOG_VERSION="3.63.0"
    wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
    tar -xzf "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
    sudo mv trufflehog /usr/local/bin/
    rm "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
fi

# Verify installation
if command -v trufflehog &> /dev/null; then
    echo -e "${GREEN}✅ TruffleHog installed successfully${NC}"
    trufflehog --version
else
    echo -e "${RED}❌ TruffleHog installation failed${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 6: Install SonarQube Scanner (for non-Maven projects)
# ============================================================================
echo "============================================================================"
echo "STEP 6: Installing SonarQube Scanner"
echo "============================================================================"

if command -v sonar-scanner &> /dev/null; then
    SONAR_VERSION=$(sonar-scanner --version | head -n1)
    echo -e "${YELLOW}⚠️  SonarQube Scanner already installed: $SONAR_VERSION${NC}"
else
    echo "Installing SonarQube Scanner..."

    SONAR_VERSION="5.0.1.3006"
    wget -q "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_VERSION}-linux.zip"
    unzip -q "sonar-scanner-cli-${SONAR_VERSION}-linux.zip"
    sudo mv "sonar-scanner-${SONAR_VERSION}-linux" /opt/sonar-scanner
    sudo ln -sf /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner
    rm "sonar-scanner-cli-${SONAR_VERSION}-linux.zip"
fi

# Verify installation
if command -v sonar-scanner &> /dev/null; then
    echo -e "${GREEN}✅ SonarQube Scanner installed successfully${NC}"
    sonar-scanner --version | head -n1
else
    echo -e "${RED}❌ SonarQube Scanner installation failed${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 7: Copy Security Scripts
# ============================================================================
echo "============================================================================"
echo "STEP 7: Setting Up Security Scripts"
echo "============================================================================"

SCRIPT_DIR="$HOME/jenkins-automation/buildserversetup/scripts"

echo "Scripts location: $SCRIPT_DIR"

if [ -f "$SCRIPT_DIR/security_scan.py" ]; then
    echo -e "${GREEN}✅ security_scan.py found${NC}"
else
    echo -e "${RED}❌ security_scan.py not found${NC}"
    exit 1
fi

if [ -f "$SCRIPT_DIR/generate_report.py" ]; then
    echo -e "${GREEN}✅ generate_report.py found${NC}"
else
    echo -e "${RED}❌ generate_report.py not found${NC}"
    exit 1
fi

if [ -f "$SCRIPT_DIR/logo.png" ]; then
    echo -e "${GREEN}✅ logo.png found${NC}"
else
    echo -e "${RED}❌ logo.png not found${NC}"
    exit 1
fi

# Make scripts executable
chmod +x "$SCRIPT_DIR/security_scan.py"
chmod +x "$SCRIPT_DIR/generate_report.py"

echo ""

# ============================================================================
# STEP 8: Test Security Scripts
# ============================================================================
echo "============================================================================"
echo "STEP 8: Testing Security Scripts"
echo "============================================================================"

echo "Testing security_scan.py..."
if python3 "$SCRIPT_DIR/security_scan.py" --help &> /dev/null; then
    echo -e "${GREEN}✅ security_scan.py works${NC}"
else
    echo -e "${RED}❌ security_scan.py failed${NC}"
    exit 1
fi

echo "Testing generate_report.py..."
if python3 "$SCRIPT_DIR/generate_report.py" --help &> /dev/null; then
    echo -e "${GREEN}✅ generate_report.py works${NC}"
else
    echo -e "${RED}❌ generate_report.py failed${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 9: Create Security Report Directories
# ============================================================================
echo "============================================================================"
echo "STEP 9: Creating Security Report Directories"
echo "============================================================================"

REPORT_BASE_DIR="/tts/ttsbuild/securityreport"

if [ ! -d "$REPORT_BASE_DIR" ]; then
    echo "Creating $REPORT_BASE_DIR..."
    sudo mkdir -p "$REPORT_BASE_DIR"
    sudo chown -R $USER:$USER "$REPORT_BASE_DIR"
    echo -e "${GREEN}✅ Created $REPORT_BASE_DIR${NC}"
else
    echo -e "${YELLOW}⚠️  $REPORT_BASE_DIR already exists${NC}"
fi

# Create example project directories
for PROJECT in ADXSIP TTS-CAP BRHUB; do
    PROJECT_DIR="$REPORT_BASE_DIR/$PROJECT"
    REPORT_DIR="$REPORT_BASE_DIR/$PROJECT/report"

    mkdir -p "$PROJECT_DIR"
    mkdir -p "$REPORT_DIR"

    echo -e "${GREEN}✅ Created $PROJECT_DIR${NC}"
done

echo ""

# ============================================================================
# STEP 10: Final Verification
# ============================================================================
echo "============================================================================"
echo "STEP 10: Final Verification"
echo "============================================================================"

echo "Checking all tools..."
echo ""

# Check Semgrep
if semgrep --help &> /dev/null; then
    echo -e "${GREEN}✅ Semgrep: OK${NC}"
else
    echo -e "${RED}❌ Semgrep: FAILED${NC}"
fi

# Check Trivy
if trivy --help &> /dev/null; then
    echo -e "${GREEN}✅ Trivy: OK${NC}"
else
    echo -e "${RED}❌ Trivy: FAILED${NC}"
fi

# Check TruffleHog
if trufflehog --help &> /dev/null; then
    echo -e "${GREEN}✅ TruffleHog: OK${NC}"
else
    echo -e "${RED}❌ TruffleHog: FAILED${NC}"
fi

# Check SonarQube Scanner
if sonar-scanner --help &> /dev/null; then
    echo -e "${GREEN}✅ SonarQube Scanner: OK${NC}"
else
    echo -e "${RED}❌ SonarQube Scanner: FAILED${NC}"
fi

# Check Python scripts
if python3 "$SCRIPT_DIR/security_scan.py" --help &> /dev/null; then
    echo -e "${GREEN}✅ security_scan.py: OK${NC}"
else
    echo -e "${RED}❌ security_scan.py: FAILED${NC}"
fi

if python3 "$SCRIPT_DIR/generate_report.py" --help &> /dev/null; then
    echo -e "${GREEN}✅ generate_report.py: OK${NC}"
else
    echo -e "${RED}❌ generate_report.py: FAILED${NC}"
fi

echo ""
echo "============================================================================"
echo -e "${GREEN}🎉 BUILD SERVER SETUP COMPLETED SUCCESSFULLY!${NC}"
echo "============================================================================"
echo ""
echo "Installed Tools:"
echo "  - Python 3 + dependencies (requests, pyyaml, reportlab, Pillow)"
echo "  - Semgrep (SAST Scanner)"
echo "  - Trivy (Dependency Scanner)"
echo "  - TruffleHog (Secret Scanner)"
echo "  - SonarQube Scanner"
echo ""
echo "Security Scripts Location:"
echo "  $SCRIPT_DIR"
echo ""
echo "Security Reports Directory:"
echo "  $REPORT_BASE_DIR"
echo ""
echo "Next Steps:"
echo "  1. Run: ./setup-permissions.sh (to grant jenkins-agent access)"
echo "  2. Update Jenkins Shared Library"
echo "  3. Create Jenkinsfiles for your projects"
echo ""
echo "============================================================================"
