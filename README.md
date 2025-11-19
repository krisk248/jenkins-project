# TTS Jenkins Build System - Production Setup

**Lightweight Jenkins with Configuration as Code (JCasC)**

This is a production-ready Jenkins setup for TTS QA builds with:
- ✅ Lightweight Jenkins container (orchestration only)
- ✅ Security scanning (Semgrep, Trivy, TruffleHog)
- ✅ Zero manual configuration (JCasC)
- ✅ Dedicated build agents for heavy compilation
- ✅ SonarQube integration
- ✅ Email notifications
- ✅ Shared library support (Phase 4)

---

## 🚀 PHASE 1: SETUP GUIDE

### Prerequisites

- Ubuntu server with Docker and Docker Compose installed
- At least 4GB RAM available
- Ports 7080, 9000, and 50001 available
- Access to `/tts/ttsbuild` and `/tts/outputttsbuild` directories

---

## 📋 STEP-BY-STEP SETUP

### STEP 1: Prepare Environment File

1. **Copy the example environment file:**
   ```bash
   cd jenkins-automation
   cp .env.example .env
   ```

2. **Edit `.env` file and fill in YOUR actual values:**
   ```bash
   nano .env
   # or
   vim .env
   ```

3. **Required values to fill in:**

   **Jenkins Admin:**
   - `JENKINS_ADMIN_USER`: admin
   - `JENKINS_ADMIN_PASSWORD`: Choose a strong password
   - `JENKINS_ADMIN_EMAIL`: Your DevOps email
   - `JENKINS_HOST`: Your server IP (e.g., 192.168.1.136)

   **GitHub:**
   - `GITHUB_USERNAME`: Your GitHub username
   - `GITHUB_TOKEN`: Personal access token from GitHub
     - Create at: https://github.com/settings/tokens
     - Required scope: `repo` (full control of private repositories)

   **Network Share:**
   - `NETWORK_SHARE_USER`: Username for \\\\192.168.1.136\\tts-builds
   - `NETWORK_SHARE_PASS`: Password for network share

   **Email (Example for Gmail):**
   - `SMTP_SERVER`: smtp.gmail.com
   - `SMTP_PORT`: 587
   - `SMTP_USER`: your-email@gmail.com
   - `SMTP_PASS`: App-specific password (not your regular password!)
     - Generate at: https://myaccount.google.com/apppasswords
   - `SMTP_REPLY_TO`: devops@ttsme.com
   - `DEVOPS_EMAIL`: devops@ttsme.com,kannan@ttsme.com

   **SonarQube Token:**
   - Leave empty for now, we'll generate this after SonarQube starts
   - `SONARQUBE_TOKEN`: (will fill this in Step 5)

   **Shared Library:**
   - `SHARED_LIBRARY_REPO`: Will create in Phase 4
   - For now, use: https://github.com/TTS-FZLLC/jenkins-shared-library.git

4. **Verify `.env` file is NOT tracked by Git:**
   ```bash
   git status
   # .env should NOT appear in the list (it's in .gitignore)
   ```

---

### STEP 2: Stop Existing Containers (if running)

1. **Stop and remove existing containers:**
   ```bash
   cd jenkins-automation
   docker compose down
   ```

2. **Optional - Start completely fresh (DELETES ALL DATA):**
   ```bash
   # Only if you want to delete ALL Jenkins jobs, history, and configurations
   docker volume rm jenkins-automation_jenkins_home

   # Keep SonarQube data (no need to remove these)
   # docker volume rm jenkins-automation_sonarqube_data
   # docker volume rm jenkins-automation_sonarqube_extensions
   # docker volume rm jenkins-automation_postgresql_data
   ```

---

### STEP 3: Build and Start Containers

1. **Build the new lightweight Jenkins image:**
   ```bash
   cd jenkins-automation
   docker compose build jenkins
   ```

   This will take 5-10 minutes. You'll see:
   - Installing security tools (Semgrep, Trivy, TruffleHog)
   - Installing Python libraries
   - Installing Jenkins plugins
   - **NOT installing Java, Maven, Node** (moved to agents)

2. **Start all containers:**
   ```bash
   docker compose up -d
   ```

3. **Check container status:**
   ```bash
   docker compose ps
   ```

   You should see:
   - ✅ jenkins-master (healthy)
   - ✅ sonarqube (healthy)
   - ✅ sonarqube-db (healthy)

4. **Check Jenkins logs:**
   ```bash
   docker compose logs -f jenkins
   ```

   Wait until you see:
   ```
   Jenkins is fully up and running
   ```

   Press `Ctrl+C` to exit logs.

---

### STEP 4: Access Jenkins

1. **Open Jenkins in browser:**
   ```
   http://YOUR_SERVER_IP:7080
   ```
   Example: `http://192.168.1.136:7080`

2. **Login with credentials from .env file:**
   - Username: Value of `JENKINS_ADMIN_USER` (admin)
   - Password: Value of `JENKINS_ADMIN_PASSWORD`

3. **Verify Jenkins is configured:**
   - No setup wizard! (JCasC already configured everything)
   - Check: Manage Jenkins → System
   - You should see SonarQube, Email, and other settings already configured
   - Check: Manage Jenkins → Credentials
   - You should see github-pat, network-share-credentials

---

### STEP 5: Generate SonarQube Token

1. **Access SonarQube:**
   ```
   http://YOUR_SERVER_IP:9000
   ```
   Example: `http://192.168.1.136:9000`

2. **Login with default credentials:**
   - Username: `admin`
   - Password: `admin`
   - You'll be prompted to change password - do it!

3. **Generate a token for Jenkins:**
   - Go to: Administration → Security → Users
   - Click on "admin" user
   - Click "Tokens" tab
   - Click "Generate Token"
   - Name: `jenkins`
   - Type: Global Analysis Token
   - Expires: No expiration
   - Click "Generate"
   - **COPY THE TOKEN** - you can't see it again!

4. **Update .env file with the token:**
   ```bash
   nano .env
   # Update this line:
   SONARQUBE_TOKEN=squ_your_actual_token_here
   ```

5. **Restart Jenkins to pick up the new token:**
   ```bash
   docker compose restart jenkins
   ```

---

### STEP 6: Verify Everything Works

1. **Check Jenkins configuration was applied:**
   - Jenkins → Manage Jenkins → Configuration as Code
   - You should see: `/var/jenkins_home/casc_configs/jcasc.yaml`
   - Click "View Configuration" - shows current config

2. **Check SonarQube connection:**
   - Jenkins → Manage Jenkins → System
   - Scroll to "SonarQube servers"
   - You should see "SonarQube" configured with URL: http://sonarqube:9000

3. **Test email configuration:**
   - Jenkins → Manage Jenkins → System
   - Scroll to "Extended E-mail Notification"
   - Click "Test Configuration by sending test e-mail"
   - Enter your email address
   - Click "Test configuration"
   - Check your email inbox

4. **Verify security scripts are installed:**
   ```bash
   docker exec jenkins-master ls -la /usr/local/bin/security-scripts/
   ```

   You should see:
   - security_scan.py
   - generate_report.py
   - logo.png

---

## ✅ PHASE 1 COMPLETE!

You now have:
- ✅ Lightweight Jenkins container running
- ✅ Jenkins fully configured via JCasC (no manual clicking!)
- ✅ SonarQube integrated
- ✅ Email notifications configured
- ✅ Security scanning tools ready
- ✅ Credentials stored securely

**What's different from before:**
- Jenkins container is much smaller (no Java, Maven, Node inside)
- Zero manual configuration needed
- All settings in code (jcasc.yaml)
- Secrets in .env file (not committed to Git)
- Ready for build agents (Phase 2)

---

## 🔧 TROUBLESHOOTING

### Jenkins won't start
```bash
# Check logs
docker compose logs jenkins

# Common issues:
# 1. Port 7080 already in use: change in docker-compose.yml
# 2. Invalid .env values: check syntax
# 3. Permissions on volumes: sudo chown -R 1000:1000 volumes/jenkins_home
```

### JCasC configuration not applied
```bash
# Verify JCasC file is mounted
docker exec jenkins-master ls -la /var/jenkins_home/casc_configs/

# Check JCasC logs
docker compose logs jenkins | grep -i casc

# Manually reload configuration
# Jenkins → Manage Jenkins → Configuration as Code → Reload existing configuration
```

### Email test fails
```bash
# Check SMTP settings in .env
# For Gmail: Must use "App Password" not regular password
# Verify port: Gmail uses 587 (TLS) or 465 (SSL)
# Check firewall: ensure outbound SMTP traffic allowed
```

### SonarQube connection fails
```bash
# Verify token is correct
docker exec jenkins-master env | grep SONARQUBE_TOKEN

# Check SonarQube is accessible from Jenkins container
docker exec jenkins-master curl -u $SONARQUBE_TOKEN: http://sonarqube:9000/api/system/health

# Expected response: {"health":"GREEN","causes":[]}
```

---

## 📁 FOLDER STRUCTURE

```
jenkins-automation/
├── .env                          # Your secrets (NOT in Git)
├── .env.example                  # Template for .env
├── .gitignore                    # Git ignore file
├── docker-compose.yml            # Docker Compose configuration
├── README.md                     # This file
└── jenkins/
    ├── Dockerfile                # Lightweight Jenkins image
    ├── plugins.txt               # Pre-installed plugins list
    ├── casc_configs/
    │   └── jcasc.yaml           # Jenkins Configuration as Code
    ├── scripts/
    │   ├── security_scan.py     # Security scanning script
    │   ├── generate_report.py   # PDF report generator
    │   └── logo.png             # TTS logo
    └── templates/
        └── email_template.html   # Email notification template
```

---

## 🚦 WHAT'S NEXT?

**Phase 2: Build Agent Setup (Next Step)**
- Install Java, Maven, Node, Angular on Ubuntu host
- Set up Jenkins agent to run builds
- Configure agent in JCasC

**Phase 3: Shared Library (After Phase 2)**
- Create reusable pipeline templates
- Standardize build process across all projects

**Phase 4: Project Configuration (After Phase 3)**
- Simple Jenkinsfile for each project
- Project-specific settings in YAML files

---

## 🔐 SECURITY NOTES

1. **Never commit `.env` file** - it contains passwords and tokens
2. **Use strong passwords** for JENKINS_ADMIN_PASSWORD
3. **Rotate tokens regularly** - especially SonarQube and GitHub tokens
4. **Limit GitHub token scope** - only grant necessary permissions
5. **Use app-specific passwords** for email (not your main password)
6. **Review Jenkins security** periodically via Security Advisories

---

## 📞 SUPPORT

**Issues with setup?**
- Check logs: `docker compose logs jenkins`
- Verify .env values are correct
- Ensure all required ports are available
- Check firewall rules

**Need to reset everything?**
```bash
docker compose down
docker volume rm jenkins-automation_jenkins_home
# Edit .env with correct values
docker compose up -d
```

---

## 📊 MONITORING

**Check container health:**
```bash
docker compose ps
```

**View Jenkins logs:**
```bash
docker compose logs -f jenkins
```

**View SonarQube logs:**
```bash
docker compose logs -f sonarqube
```

**Check resource usage:**
```bash
docker stats
```

---

**Built with ❤️ by TTS DevOps Team**
