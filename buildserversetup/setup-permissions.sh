#!/bin/bash
# ============================================================================
# SETUP PERMISSIONS FOR JENKINS AGENT
# ============================================================================
# This script grants jenkins-agent user access to required directories
#
# Run as: sudo ./setup-permissions.sh
# ============================================================================

set -e

echo "============================================================================"
echo "🔐 Setting Up Permissions for jenkins-agent User"
echo "============================================================================"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root or with sudo${NC}"
    echo "Usage: sudo ./setup-permissions.sh"
    exit 1
fi

# ============================================================================
# Check if jenkins-agent user exists
# ============================================================================
if id "jenkins-agent" &>/dev/null; then
    echo -e "${GREEN}✅ jenkins-agent user exists${NC}"
else
    echo -e "${RED}❌ jenkins-agent user does not exist${NC}"
    echo "Please create the user first or check the username"
    exit 1
fi

echo ""

# ============================================================================
# Grant Access to /tts/ttsbuild/
# ============================================================================
echo "============================================================================"
echo "Setting permissions for /tts/ttsbuild/"
echo "============================================================================"

if [ -d "/tts/ttsbuild" ]; then
    echo "Granting jenkins-agent read/write access to /tts/ttsbuild/..."

    # Add jenkins-agent to ttsbuild group (if group exists)
    if getent group ttsbuild > /dev/null 2>&1; then
        usermod -a -G ttsbuild jenkins-agent
        echo -e "${GREEN}✅ Added jenkins-agent to ttsbuild group${NC}"
    fi

    # Grant read/write permissions
    chmod -R 775 /tts/ttsbuild

    # If ttsbuild user exists, set ownership
    if id "ttsbuild" &>/dev/null; then
        chown -R ttsbuild:ttsbuild /tts/ttsbuild
        echo -e "${GREEN}✅ Set ownership to ttsbuild:ttsbuild${NC}"
    fi

    echo -e "${GREEN}✅ Permissions set for /tts/ttsbuild/${NC}"
else
    echo -e "${YELLOW}⚠️  /tts/ttsbuild/ does not exist${NC}"
    echo "Creating /tts/ttsbuild/..."
    mkdir -p /tts/ttsbuild
    chown -R jenkins-agent:jenkins-agent /tts/ttsbuild
    chmod -R 775 /tts/ttsbuild
    echo -e "${GREEN}✅ Created /tts/ttsbuild/ with jenkins-agent ownership${NC}"
fi

echo ""

# ============================================================================
# Grant Access to /tts/outputttsbuild/
# ============================================================================
echo "============================================================================"
echo "Setting permissions for /tts/outputttsbuild/"
echo "============================================================================"

if [ -d "/tts/outputttsbuild" ]; then
    echo "Granting jenkins-agent read/write access to /tts/outputttsbuild/..."

    # Add jenkins-agent to ttsbuild group (if group exists)
    if getent group ttsbuild > /dev/null 2>&1; then
        usermod -a -G ttsbuild jenkins-agent
    fi

    # Grant read/write permissions
    chmod -R 775 /tts/outputttsbuild

    # If ttsbuild user exists, set ownership
    if id "ttsbuild" &>/dev/null; then
        chown -R ttsbuild:ttsbuild /tts/outputttsbuild
        echo -e "${GREEN}✅ Set ownership to ttsbuild:ttsbuild${NC}"
    fi

    echo -e "${GREEN}✅ Permissions set for /tts/outputttsbuild/${NC}"
else
    echo -e "${YELLOW}⚠️  /tts/outputttsbuild/ does not exist${NC}"
    echo "Creating /tts/outputttsbuild/..."
    mkdir -p /tts/outputttsbuild
    chown -R jenkins-agent:jenkins-agent /tts/outputttsbuild
    chmod -R 775 /tts/outputttsbuild
    echo -e "${GREEN}✅ Created /tts/outputttsbuild/ with jenkins-agent ownership${NC}"
fi

echo ""

# ============================================================================
# Create and Setup /tts/ttsbuild/securityreport/
# ============================================================================
echo "============================================================================"
echo "Setting up /tts/ttsbuild/securityreport/"
echo "============================================================================"

REPORT_DIR="/tts/ttsbuild/securityreport"

if [ ! -d "$REPORT_DIR" ]; then
    echo "Creating $REPORT_DIR..."
    mkdir -p "$REPORT_DIR"
fi

# Set ownership to jenkins-agent (since it will write reports here)
chown -R jenkins-agent:jenkins-agent "$REPORT_DIR"
chmod -R 775 "$REPORT_DIR"

# Create example project directories
for PROJECT in ADXSIP TTS-CAP BRHUB; do
    PROJECT_DIR="$REPORT_DIR/$PROJECT"
    PROJECT_REPORT_DIR="$REPORT_DIR/$PROJECT/report"

    mkdir -p "$PROJECT_DIR"
    mkdir -p "$PROJECT_REPORT_DIR"

    chown -R jenkins-agent:jenkins-agent "$PROJECT_DIR"
    chmod -R 775 "$PROJECT_DIR"

    echo -e "${GREEN}✅ Created $PROJECT_DIR${NC}"
done

echo ""

# ============================================================================
# Grant Access to jenkins-automation folder
# ============================================================================
echo "============================================================================"
echo "Setting permissions for ~/jenkins-automation/"
echo "============================================================================"

# Find ttsbuild user's home directory
TTSBUILD_HOME=$(eval echo ~ttsbuild)
JENKINS_AUTOMATION_DIR="$TTSBUILD_HOME/jenkins-automation"

if [ -d "$JENKINS_AUTOMATION_DIR" ]; then
    echo "Granting jenkins-agent read access to $JENKINS_AUTOMATION_DIR..."

    # Grant read/execute permissions to jenkins-agent
    chmod -R 755 "$JENKINS_AUTOMATION_DIR/buildserversetup"

    echo -e "${GREEN}✅ Permissions set for $JENKINS_AUTOMATION_DIR${NC}"
else
    echo -e "${YELLOW}⚠️  $JENKINS_AUTOMATION_DIR does not exist${NC}"
fi

echo ""

# ============================================================================
# Verification
# ============================================================================
echo "============================================================================"
echo "Verifying Permissions"
echo "============================================================================"

echo ""
echo "jenkins-agent group memberships:"
groups jenkins-agent

echo ""
echo "Directory permissions:"
ls -ld /tts/ttsbuild 2>/dev/null || echo "/tts/ttsbuild - not found"
ls -ld /tts/outputttsbuild 2>/dev/null || echo "/tts/outputttsbuild - not found"
ls -ld /tts/ttsbuild/securityreport 2>/dev/null || echo "/tts/ttsbuild/securityreport - not found"

echo ""
echo "============================================================================"
echo -e "${GREEN}🎉 PERMISSIONS SETUP COMPLETED!${NC}"
echo "============================================================================"
echo ""
echo "jenkins-agent user now has access to:"
echo "  ✅ /tts/ttsbuild/ (read/write)"
echo "  ✅ /tts/outputttsbuild/ (read/write)"
echo "  ✅ /tts/ttsbuild/securityreport/ (read/write)"
echo "  ✅ ~/jenkins-automation/buildserversetup/ (read)"
echo ""
echo "Next Steps:"
echo "  1. Test permissions by running: sudo -u jenkins-agent ls /tts/ttsbuild"
echo "  2. Update Jenkins Shared Library"
echo "  3. Create Jenkinsfiles for your projects"
echo ""
echo "============================================================================"
