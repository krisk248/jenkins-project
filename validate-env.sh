#!/bin/bash
# ============================================================================
# TTS Jenkins Environment Validation Script
# ============================================================================
# This script validates that all required environment variables are set
# in the .env file before starting Jenkins.
#
# Usage: ./validate-env.sh
# ============================================================================

set -e

echo "============================================================================"
echo "🔍 TTS Jenkins Environment Validation"
echo "============================================================================"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ ERROR: .env file not found!"
    echo ""
    echo "📋 Please create .env file:"
    echo "   cp .env.example .env"
    echo "   nano .env  # Fill in your actual values"
    echo ""
    exit 1
fi

echo "✅ .env file found"
echo ""

# Load environment variables
set -a
source .env
set +a

# Required variables
REQUIRED_VARS=(
    "JENKINS_ADMIN_USER"
    "JENKINS_ADMIN_PASSWORD"
    "JENKINS_ADMIN_EMAIL"
    "JENKINS_HOST"
    "GITHUB_USERNAME"
    "GITHUB_TOKEN"
    "NETWORK_SHARE_USER"
    "NETWORK_SHARE_PASS"
    "SMTP_SERVER"
    "SMTP_PORT"
    "SMTP_USER"
    "SMTP_PASS"
    "SMTP_REPLY_TO"
    "DEVOPS_EMAIL"
    "SHARED_LIBRARY_REPO"
    "BUILD_AGENT_HOST"
)

# Optional but recommended
OPTIONAL_VARS=(
    "SONARQUBE_TOKEN"
)

echo "Checking required variables..."
echo ""

MISSING_COUNT=0

for var in "${REQUIRED_VARS[@]}"; do
    value="${!var}"
    if [ -z "$value" ]; then
        echo "❌ MISSING: $var"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    elif [[ "$value" == *"your-"* ]] || [[ "$value" == *"_here"* ]]; then
        echo "⚠️  PLACEHOLDER: $var (still has placeholder value)"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    else
        # Show first 20 chars only for security
        if [[ "$var" == *"PASSWORD"* ]] || [[ "$var" == *"TOKEN"* ]] || [[ "$var" == *"PASS"* ]]; then
            echo "✅ $var: ********** (hidden for security)"
        else
            short_value="${value:0:30}"
            if [ ${#value} -gt 30 ]; then
                short_value="${short_value}..."
            fi
            echo "✅ $var: $short_value"
        fi
    fi
done

echo ""
echo "Checking optional variables..."
echo ""

for var in "${OPTIONAL_VARS[@]}"; do
    value="${!var}"
    if [ -z "$value" ]; then
        echo "⚠️  NOT SET: $var (optional - can be added later)"
    elif [[ "$value" == *"your-"* ]] || [[ "$value" == *"_here"* ]]; then
        echo "⚠️  PLACEHOLDER: $var (optional - can be added later)"
    else
        echo "✅ $var: ********** (set)"
    fi
done

echo ""
echo "============================================================================"

if [ $MISSING_COUNT -eq 0 ]; then
    echo "✅ VALIDATION PASSED!"
    echo "============================================================================"
    echo ""
    echo "All required variables are set. You can now start Jenkins:"
    echo ""
    echo "  docker compose build jenkins"
    echo "  docker compose up -d"
    echo ""
    exit 0
else
    echo "❌ VALIDATION FAILED!"
    echo "============================================================================"
    echo ""
    echo "Found $MISSING_COUNT missing or placeholder values."
    echo ""
    echo "Please edit .env file and replace all placeholder values with your actual"
    echo "credentials and configuration:"
    echo ""
    echo "  nano .env"
    echo ""
    echo "Then run this script again to validate."
    echo ""
    exit 1
fi
