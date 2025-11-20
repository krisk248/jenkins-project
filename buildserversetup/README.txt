================================================================================
BUILD SERVER SETUP INSTRUCTIONS
================================================================================

This folder contains scripts to set up the build server for Jenkins CI/CD.

FOLDER STRUCTURE:
--------------------------------------------------------------------------------
buildserversetup/
├── install.sh              # Install security tools and dependencies
├── setup-permissions.sh    # Set up permissions for jenkins-agent user
├── scripts/                # Security scanning scripts
│   ├── security_scan.py    # Main security scanning script
│   ├── generate_report.py  # PDF report generator
│   └── logo.png            # TTS logo for reports
└── README.txt              # This file

================================================================================
INSTALLATION STEPS
================================================================================

Follow these steps ON THE BUILD SERVER (Ubuntu):

STEP 1: Copy this folder to build server
--------------------------------------------------------------------------------
On your local machine:
  cd /home/kannan/Projects/Office/newbuild/jenkins-automation
  git add buildserversetup/
  git commit -m "Add build server setup scripts"
  git push

On build server:
  cd ~/jenkins-automation
  git pull

STEP 2: Run installation script
--------------------------------------------------------------------------------
On build server (as ttsbuild user):
  cd ~/jenkins-automation/buildserversetup
  ./install.sh

This will:
  ✅ Check Python 3 is installed
  ✅ Install Python dependencies (requests, pyyaml, reportlab, Pillow)
  ✅ Install Semgrep (SAST scanner)
  ✅ Install Trivy (dependency scanner)
  ✅ Install TruffleHog (secret scanner)
  ✅ Install SonarQube Scanner
  ✅ Test all tools with --help
  ✅ Create /tts/ttsbuild/securityreport/ directory structure
  ✅ Green signal when complete

STEP 3: Set up permissions
--------------------------------------------------------------------------------
On build server (with sudo):
  cd ~/jenkins-automation/buildserversetup
  sudo ./setup-permissions.sh

This will:
  ✅ Grant jenkins-agent access to /tts/ttsbuild/
  ✅ Grant jenkins-agent access to /tts/outputttsbuild/
  ✅ Create /tts/ttsbuild/securityreport/ with proper permissions
  ✅ Set up example project directories (ADXSIP, TTS-CAP, BRHUB)

STEP 4: Verify installation
--------------------------------------------------------------------------------
On build server (test as jenkins-agent user):
  # Test tool access
  semgrep --version
  trivy --version
  trufflehog --version
  sonar-scanner --version

  # Test Python scripts
  python3 ~/jenkins-automation/buildserversetup/scripts/security_scan.py --help
  python3 ~/jenkins-automation/buildserversetup/scripts/generate_report.py --help

  # Test directory access
  sudo -u jenkins-agent ls /tts/ttsbuild
  sudo -u jenkins-agent ls /tts/outputttsbuild
  sudo -u jenkins-agent ls /tts/ttsbuild/securityreport

All commands should work without errors!

================================================================================
SECURITY REPORTS STRUCTURE
================================================================================

Reports will be stored at:

/tts/ttsbuild/securityreport/
├── ADXSIP/
│   ├── semgrep-report.json
│   ├── trivy-report.json
│   ├── trufflehog-report.json
│   └── report/
│       └── security-report.pdf
├── TTS-CAP/
│   ├── semgrep-report.json
│   ├── trivy-report.json
│   ├── trufflehog-report.json
│   └── report/
│       └── security-report.pdf
└── BRHUB/
    ├── semgrep-report.json
    ├── trivy-report.json
    ├── trufflehog-report.json
    └── report/
        └── security-report.pdf

Jenkins will archive these files as build artifacts.

================================================================================
WHAT'S NEXT
================================================================================

After completing these steps:

1. ✅ Security tools installed on build server
2. ✅ jenkins-agent has access to all required directories
3. ✅ Security scripts ready to use

Next steps:
  - Update Jenkins Shared Library to use these scripts
  - Create Jenkinsfiles for your projects
  - Run test builds

================================================================================
TROUBLESHOOTING
================================================================================

If install.sh fails:
  - Check Python 3 is installed: python3 --version
  - Check pip3 is installed: pip3 --version
  - Check internet connection for downloading tools
  - Run with more verbosity: bash -x ./install.sh

If permissions fail:
  - Make sure jenkins-agent user exists: id jenkins-agent
  - Check directories exist: ls -la /tts/
  - Run setup-permissions.sh with sudo

If tools don't work:
  - Reload shell: source ~/.bashrc
  - Check PATH includes ~/.local/bin: echo $PATH
  - Try full path: ~/.local/bin/semgrep --version

================================================================================
