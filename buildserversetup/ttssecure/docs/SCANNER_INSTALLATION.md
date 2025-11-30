# Security Scanner Installation Guide

This guide provides installation instructions for all security scanners used by ttssecure.

---

## Table of Contents

1. [SpotBugs with FindSecBugs](#spotbugs-with-findsecbugs)
2. [OWASP Dependency-Check](#owasp-dependency-check)
3. [Semgrep](#semgrep)
4. [Trivy](#trivy)
5. [TruffleHog](#trufflehog)
6. [ESLint Security](#eslint-security)

---

## SpotBugs with FindSecBugs

SpotBugs is a static analysis tool that finds bugs in Java bytecode. The FindSecBugs plugin adds security-focused rules.

### Prerequisites

- Java JDK 8+ installed
- Maven or Gradle built project (compiled .class files required)

### Installation on Ubuntu/Debian

```bash
# Install SpotBugs
sudo apt update
sudo apt install spotbugs -y

# Verify installation
spotbugs -version
```

### Installation on CentOS/RHEL

```bash
# Download and install manually
cd /opt
sudo wget https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz
sudo tar -xzf spotbugs-4.8.3.tgz
sudo ln -s /opt/spotbugs-4.8.3/bin/spotbugs /usr/local/bin/spotbugs

# Verify installation
spotbugs -version
```

### Installing FindSecBugs Plugin (Security Rules)

```bash
# Download FindSecBugs plugin
mkdir -p ~/.spotbugs/plugins
cd ~/.spotbugs/plugins
wget https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-plugin-1.12.0.jar

# OR system-wide installation
sudo mkdir -p /opt/spotbugs-plugins
cd /opt/spotbugs-plugins
sudo wget https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-plugin-1.12.0.jar
```

### Configure FindSecBugs in ttssecure

Update your YAML config to specify the FindSecBugs plugin:

```yaml
scanners:
  spotbugs:
    enabled: true
    timeout: 900
    config: "/opt/spotbugs-plugins/findsecbugs-plugin-1.12.0.jar"
    severity: "CRITICAL,HIGH,MEDIUM"
```

### Running SpotBugs Manually

```bash
# Build your Java project first
cd /path/to/your/java/project
mvn clean compile  # or: gradle build

# Run SpotBugs with FindSecBugs
spotbugs -textui \
  -pluginList /opt/spotbugs-plugins/findsecbugs-plugin-1.12.0.jar \
  -effort:max \
  -low \
  target/classes
```

### Jenkins Integration Note

For Jenkins, ensure SpotBugs is available on the build server:

```bash
# Add to Jenkins server
sudo apt install spotbugs -y

# Install FindSecBugs plugin in shared location
sudo mkdir -p /opt/spotbugs-plugins
sudo wget -O /opt/spotbugs-plugins/findsecbugs-plugin-1.12.0.jar \
  https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-plugin-1.12.0.jar
sudo chmod 644 /opt/spotbugs-plugins/findsecbugs-plugin-1.12.0.jar
```

---

## OWASP Dependency-Check

OWASP Dependency-Check is a Software Composition Analysis (SCA) tool that identifies known vulnerabilities in project dependencies.

### Prerequisites

- Java JRE 8+ installed

### Installation on Ubuntu/Debian/CentOS/RHEL

```bash
# Create installation directory
sudo mkdir -p /opt/dependency-check
cd /opt/dependency-check

# Download latest version (check for newer versions at https://owasp.org/www-project-dependency-check/)
sudo wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip
sudo unzip dependency-check-9.0.9-release.zip
sudo mv dependency-check/* .
sudo rmdir dependency-check

# Create symlink for easy access
sudo ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

# Make executable
sudo chmod +x /opt/dependency-check/bin/dependency-check.sh

# Verify installation
dependency-check --version
```

### Initial Database Setup (IMPORTANT)

The first run downloads the NVD (National Vulnerability Database) and may take 10-30 minutes:

```bash
# Initialize and update the database
dependency-check --updateonly

# You can schedule this to run nightly via cron
# Add to crontab: 0 2 * * * /opt/dependency-check/bin/dependency-check.sh --updateonly
```

### Configure in ttssecure

Update your YAML config:

```yaml
scanners:
  owasp_dependency:
    enabled: true
    timeout: 1800  # 30 minutes (first run may be slow)
    severity: "CRITICAL,HIGH,MEDIUM"
    config: "auto"
```

### Running OWASP Dependency-Check Manually

```bash
# Basic scan on a project
dependency-check \
  --project "MyProject" \
  --scan /path/to/project \
  --format JSON \
  --out /path/to/output

# Scan only specific file types
dependency-check \
  --project "MyProject" \
  --scan /path/to/project \
  --format JSON \
  --out /path/to/output \
  --enableExperimental  # Enable experimental analyzers

# Skip update (for CI/CD after initial setup)
dependency-check \
  --project "MyProject" \
  --scan /path/to/project \
  --noupdate \
  --format JSON \
  --out /path/to/output
```

### Suppression File (Optional)

Create a suppression file to ignore false positives:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <suppress>
    <notes><![CDATA[
      False positive: library not affected by this CVE
    ]]></notes>
    <cve>CVE-2021-XXXXX</cve>
  </suppress>
</suppressions>
```

Use with: `dependency-check --suppression /path/to/suppression.xml ...`

### Jenkins Integration Note

```bash
# Add to Jenkins server
sudo mkdir -p /opt/dependency-check
cd /opt/dependency-check
sudo wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip
sudo unzip dependency-check-9.0.9-release.zip
sudo mv dependency-check/* .
sudo ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check
sudo chmod +x /opt/dependency-check/bin/dependency-check.sh

# Run database update (add to cron for nightly updates)
dependency-check --updateonly

# Set Jenkins environment variable if needed
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

---

## Semgrep

Semgrep is a fast, open-source static analysis tool.

### Installation

```bash
# Using pip (recommended)
pip install semgrep

# OR using Homebrew (macOS)
brew install semgrep

# Verify installation
semgrep --version
```

### Configuration

```yaml
scanners:
  semgrep:
    enabled: true
    timeout: 600
    config: "auto"  # Uses p/security ruleset
    severity: "CRITICAL,HIGH,MEDIUM,LOW"
```

---

## Trivy

Trivy is a comprehensive vulnerability scanner.

### Installation on Ubuntu/Debian

```bash
# Add repository
sudo apt-get install wget gnupg -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list

# Install
sudo apt-get update
sudo apt-get install trivy -y

# Verify
trivy --version
```

### Installation on CentOS/RHEL

```bash
# Add repository
cat << 'EOF' | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=0
enabled=1
EOF

# Install
sudo yum -y install trivy

# Verify
trivy --version
```

---

## TruffleHog

TruffleHog is a secret scanning tool.

### Installation

```bash
# Using Go
go install github.com/trufflesecurity/trufflehog/v3@latest

# OR download binary
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.67.1/trufflehog_3.67.1_linux_amd64.tar.gz
tar -xzf trufflehog_3.67.1_linux_amd64.tar.gz
sudo mv trufflehog /usr/local/bin/

# Verify
trufflehog --version
```

---

## ESLint Security

ESLint with security plugins for JavaScript/TypeScript projects.

### Installation

```bash
# Install ESLint and security plugins
npm install -g eslint eslint-plugin-security eslint-plugin-no-unsanitized

# For a project (local installation)
npm install --save-dev eslint eslint-plugin-security eslint-plugin-no-unsanitized
```

### Configuration (.eslintrc.js)

```javascript
module.exports = {
  plugins: ['security', 'no-unsanitized'],
  extends: [
    'plugin:security/recommended',
    'plugin:no-unsanitized/DOM'
  ]
};
```

---

## Quick Installation Script

Save this script as `install-scanners.sh` and run with sudo:

```bash
#!/bin/bash
set -e

echo "Installing security scanners for ttssecure..."

# Update package lists
apt-get update

# Install Java (required for SpotBugs and Dependency-Check)
apt-get install -y default-jdk

# Install SpotBugs
apt-get install -y spotbugs

# Install FindSecBugs plugin
mkdir -p /opt/spotbugs-plugins
wget -O /opt/spotbugs-plugins/findsecbugs-plugin-1.12.0.jar \
  https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-plugin-1.12.0.jar

# Install OWASP Dependency-Check
mkdir -p /opt/dependency-check
cd /opt/dependency-check
wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip
unzip -o dependency-check-9.0.9-release.zip
mv dependency-check/* . 2>/dev/null || true
rm -rf dependency-check dependency-check-9.0.9-release.zip
chmod +x /opt/dependency-check/bin/dependency-check.sh
ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" > /etc/apt/sources.list.d/trivy.list
apt-get update
apt-get install -y trivy

# Install TruffleHog
wget -O /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/download/v3.67.1/trufflehog_3.67.1_linux_amd64.tar.gz
tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog
rm /tmp/trufflehog.tar.gz

# Install Semgrep (requires pip)
pip install semgrep

# Update OWASP database (may take 10-30 minutes)
echo "Updating OWASP Dependency-Check database (this may take a while)..."
dependency-check --updateonly

echo ""
echo "Installation complete! Verify with:"
echo "  spotbugs -version"
echo "  dependency-check --version"
echo "  trivy --version"
echo "  trufflehog --version"
echo "  semgrep --version"
```

---

## Troubleshooting

### SpotBugs: "No compiled classes found"

This means the Java project hasn't been compiled. Run:
```bash
cd /path/to/java/project
mvn clean compile  # for Maven
# OR
gradle build       # for Gradle
```

### OWASP Dependency-Check: Slow first run

The first run downloads the NVD database (~2GB). This is normal. Subsequent runs with `--noupdate` will be much faster.

### TruffleHog: Permission denied

Ensure the binary is executable:
```bash
sudo chmod +x /usr/local/bin/trufflehog
```

---

## Version Compatibility

| Scanner | Minimum Version | Tested Version |
|---------|-----------------|----------------|
| SpotBugs | 4.0.0 | 4.8.3 |
| FindSecBugs | 1.10.0 | 1.12.0 |
| Dependency-Check | 8.0.0 | 9.0.9 |
| Trivy | 0.40.0 | 0.48.3 |
| TruffleHog | 3.60.0 | 3.67.1 |
| Semgrep | 1.0.0 | 1.52.0 |
