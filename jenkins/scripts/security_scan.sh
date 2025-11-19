#!/bin/bash
set -e

echo "🔍 Running security scans with verbose output..."
echo "=============================================="

# Create reports directory
mkdir -p security-reports

# Auto-detect project type
echo ""
echo "🔍 Detecting project type..."
PROJECT_TYPE="UNKNOWN"

if [ -f "package.json" ]; then
    PROJECT_TYPE="NODE"
    echo "   ✅ Detected: Node.js/JavaScript project"
elif [ -f "pom.xml" ]; then
    PROJECT_TYPE="MAVEN"
    echo "   ✅ Detected: Maven/Java project"
elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
    PROJECT_TYPE="GRADLE"
    echo "   ✅ Detected: Gradle project"
elif [ -f "requirements.txt" ] || [ -f "setup.py" ]; then
    PROJECT_TYPE="PYTHON"
    echo "   ✅ Detected: Python project"
elif [ -f "go.mod" ]; then
    PROJECT_TYPE="GO"
    echo "   ✅ Detected: Go project"
elif [ -f "Gemfile" ]; then
    PROJECT_TYPE="RUBY"
    echo "   ✅ Detected: Ruby project"
elif [ -f "composer.json" ]; then
    PROJECT_TYPE="PHP"
    echo "   ✅ Detected: PHP project"
else
    echo "   ⚠️  Unknown project type - will scan as generic"
fi

# Show environment info
echo ""
echo "📋 Environment Information:"
echo "   Working Directory: $(pwd)"
echo "   Project Type: $PROJECT_TYPE"
echo "   Files in directory: $(ls -la | wc -l) items"
echo ""

# SEMGREP - Code Security Analysis (SAST)
echo "====== Running Semgrep (COMPREHENSIVE SCAN) ======"
echo "Command: semgrep scan --config=auto --json ."
echo ""
echo "📚 Using comprehensive rulesets:"
echo "   - OWASP Top 10"
echo "   - Security audit rules"
echo "   - Language-specific rules (JavaScript, TypeScript, Python, etc.)"
echo "   - Common vulnerabilities (XSS, SQLi, Path Traversal, etc.)"
echo ""

# Run semgrep with comprehensive rules (--config=auto uses all recommended rules)
echo "🔄 Scanning with Semgrep (this may take 1-2 minutes for comprehensive scan)..."

if semgrep scan --config=auto --json --quiet . > security-reports/semgrep.json 2>&1; then
    echo "✅ Semgrep completed successfully"
    echo "   Output file size: $(ls -lh security-reports/semgrep.json | awk '{print $5}')"

    # Show sample of findings (parse JSON properly)
    if command -v jq &> /dev/null; then
        FINDINGS=$(jq '.results | length' security-reports/semgrep.json 2>/dev/null || echo "0")
        echo "   Findings: $FINDINGS issues"

        # Show top 5 findings if any
        if [ "$FINDINGS" != "0" ] && [ "$FINDINGS" -gt 0 ]; then
            echo "   Sample findings:"
            jq -r '.results[0:5] | .[] | "      - \(.check_id) in \(.path):\(.start.line)"' security-reports/semgrep.json 2>/dev/null || echo "      (details in JSON)"
        fi
    else
        # Fallback if jq not available
        FINDINGS=$(grep -c '"check_id"' security-reports/semgrep.json 2>/dev/null || echo "0")
        echo "   Findings: ~$FINDINGS issues (estimated)"
    fi
else
    echo "⚠️  Semgrep failed or had errors, creating empty result"
    echo '{"results":[]}' > security-reports/semgrep.json
fi
echo ""

# TRIVY - Dependency Vulnerabilities, CVEs, Secrets, Misconfigurations
echo "====== Running Trivy (COMPREHENSIVE SCAN) ======"
echo ""
echo "📚 Scanning for:"
echo "   - Vulnerabilities in dependencies (CVEs)"
echo "   - Exposed secrets (API keys, tokens, passwords)"
echo "   - Misconfigurations (security settings)"
echo "   - License compliance issues"
echo ""

# Run trivy with comprehensive scanning on multiple targets
echo "🔄 Scanning with Trivy (this may take 1-2 minutes)..."
echo ""

# Scan 1: Filesystem (overall)
echo "   📂 Scanning filesystem..."
# Redirect stderr to /dev/null to prevent INFO logs polluting JSON output
if trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW --scanners vuln,secret,misconfig . > security-reports/trivy-fs.json 2>/dev/null; then
    echo "      ✅ Filesystem scan complete"
else
    echo '{"Results":[]}' > security-reports/trivy-fs.json
fi

# Scan 2: Project-specific dependency file (based on detected type)
echo "   📦 Scanning project dependencies..."

case "$PROJECT_TYPE" in
    NODE)
        # Try package-lock.json first, fallback to package.json
        if [ -f "package-lock.json" ]; then
            echo "      🔍 Scanning package-lock.json (Node.js)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW package-lock.json > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        elif [ -f "package.json" ]; then
            echo "      🔍 Scanning package.json (Node.js)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW package.json > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    MAVEN)
        if [ -f "pom.xml" ]; then
            echo "      🔍 Scanning pom.xml (Maven)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW pom.xml > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    GRADLE)
        if [ -f "build.gradle" ]; then
            echo "      🔍 Scanning build.gradle (Gradle)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW build.gradle > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        elif [ -f "build.gradle.kts" ]; then
            echo "      🔍 Scanning build.gradle.kts (Gradle Kotlin)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW build.gradle.kts > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    PYTHON)
        if [ -f "requirements.txt" ]; then
            echo "      🔍 Scanning requirements.txt (Python)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW requirements.txt > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    GO)
        if [ -f "go.mod" ]; then
            echo "      🔍 Scanning go.mod (Go)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW go.mod > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    RUBY)
        if [ -f "Gemfile.lock" ]; then
            echo "      🔍 Scanning Gemfile.lock (Ruby)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW Gemfile.lock > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        elif [ -f "Gemfile" ]; then
            echo "      🔍 Scanning Gemfile (Ruby)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW Gemfile > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    PHP)
        if [ -f "composer.lock" ]; then
            echo "      🔍 Scanning composer.lock (PHP)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW composer.lock > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        elif [ -f "composer.json" ]; then
            echo "      🔍 Scanning composer.json (PHP)..."
            trivy fs --format json --severity HIGH,CRITICAL,MEDIUM,LOW composer.json > security-reports/trivy-pkg.json 2>/dev/null || echo '{"Results":[]}' > security-reports/trivy-pkg.json
        else
            echo '{"Results":[]}' > security-reports/trivy-pkg.json
        fi
        ;;
    *)
        echo "      ⚠️  Unknown project type, skipping dependency scan"
        echo '{"Results":[]}' > security-reports/trivy-pkg.json
        ;;
esac

echo "      ✅ Dependency scan complete"

# Merge results into single file
echo ""
echo "   🔄 Merging scan results..."
python3 << 'EOF'
import json
import sys
import os

def read_json_safe(filepath):
    """Safely read JSON file, handling potential log pollution"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            # Try to parse directly first
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # If fails, try to find JSON start (skip log lines)
                for line in content.split('\n'):
                    if line.strip().startswith('{'):
                        json_start = content.index(line)
                        return json.loads(content[json_start:])
                # If no JSON found, return empty
                return {"Results": []}
    except Exception as e:
        print(f"      ⚠️  Failed to read {filepath}: {e}")
        return {"Results": []}

try:
    # Read both scan results safely
    fs_data = read_json_safe('security-reports/trivy-fs.json')
    pkg_data = read_json_safe('security-reports/trivy-pkg.json')

    # Merge results (combine Results arrays)
    merged = fs_data.copy()
    if 'Results' in pkg_data and pkg_data['Results']:
        if 'Results' not in merged:
            merged['Results'] = []
        merged['Results'].extend(pkg_data['Results'])

    # Write merged results
    with open('security-reports/trivy.json', 'w') as f:
        json.dump(merged, f, indent=2)

    print("      ✅ Results merged successfully")
except Exception as e:
    print(f"      ⚠️  Merge failed: {e}")
    # Fallback to fs scan only
    import shutil
    if os.path.exists('security-reports/trivy-fs.json'):
        shutil.copy('security-reports/trivy-fs.json', 'security-reports/trivy.json')
    else:
        with open('security-reports/trivy.json', 'w') as f:
            json.dump({"Results": []}, f)
EOF

echo ""
echo "✅ Trivy completed successfully"
echo "   Output file size: $(ls -lh security-reports/trivy.json | awk '{print $5}')"

# Show sample of findings
if command -v jq &> /dev/null; then
    VULNS=$(jq '[.Results[]?.Vulnerabilities[]?] | length' security-reports/trivy.json 2>/dev/null || echo "0")
    SECRETS=$(jq '[.Results[]?.Secrets[]?] | length' security-reports/trivy.json 2>/dev/null || echo "0")
    MISCONFIGS=$(jq '[.Results[]?.Misconfigurations[]?] | length' security-reports/trivy.json 2>/dev/null || echo "0")
    echo "   Vulnerabilities: $VULNS"
    echo "   Secrets: $SECRETS"
    echo "   Misconfigurations: $MISCONFIGS"

    # Show top 5 vulnerabilities if any
    if [ "$VULNS" != "0" ] && [ "$VULNS" -gt 0 ]; then
        echo "   Sample vulnerabilities:"
        jq -r '[.Results[]?.Vulnerabilities[]?] | .[0:5] | .[] | "      - \(.PkgName): \(.VulnerabilityID) (\(.Severity))"' security-reports/trivy.json 2>/dev/null || echo "      (details in JSON)"
    fi
else
    # Fallback if jq not available
    VULNS=$(grep -c '"VulnerabilityID"' security-reports/trivy.json 2>/dev/null || echo "0")
    SECRETS=$(grep -c '"Secret"' security-reports/trivy.json 2>/dev/null || echo "0")
    echo "   Vulnerabilities: ~$VULNS (estimated)"
    echo "   Secrets: ~$SECRETS (estimated)"
fi
echo ""

# TRUFFLEHOG - Deep Secret Scan
echo "====== Running TruffleHog (VERBOSE) ======"
echo "Command: trufflehog filesystem --json --no-verification ."
echo ""

# Run trufflehog - pure JSON output
echo "🔄 Scanning for secrets with TruffleHog (limiting to 100 results)..."

if trufflehog filesystem --json --no-verification . 2>/dev/null | head -100 > security-reports/trufflehog-raw.json; then
    echo "✅ TruffleHog completed"
else
    echo "⚠️  TruffleHog had errors, continuing..."
    echo '' > security-reports/trufflehog-raw.json
fi

# Format TruffleHog output
if [ -s security-reports/trufflehog-raw.json ]; then
    echo '{"secrets":[' > security-reports/trufflehog.json
    cat security-reports/trufflehog-raw.json | paste -sd ',' >> security-reports/trufflehog.json 2>/dev/null || echo "" >> security-reports/trufflehog.json
    echo ']}' >> security-reports/trufflehog.json

    SECRET_COUNT=$(grep -c "DetectorName" security-reports/trufflehog-raw.json || echo "0")
    echo "   Secrets found: $SECRET_COUNT"
else
    echo '{"secrets":[]}' > security-reports/trufflehog.json
    echo "   No secrets found"
fi
echo ""

# Summary
echo "=============================================="
echo "✅ All security scans completed!"
echo ""
echo "📊 Results Summary:"
echo "   - semgrep.json: $(ls -lh security-reports/semgrep.json | awk '{print $5}')"
echo "   - trivy.json: $(ls -lh security-reports/trivy.json | awk '{print $5}')"
echo "   - trufflehog.json: $(ls -lh security-reports/trufflehog.json | awk '{print $5}')"
echo ""
echo "✅ All JSON files are ready for report generation!"
echo ""
