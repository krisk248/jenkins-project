# ============================================================================
# JENKINS DOCKERFILE - Lightweight Orchestration Container
# ============================================================================
# This is a LIGHTWEIGHT Jenkins image for orchestration only.
#
# What's INSIDE this container:
# - Jenkins LTS (orchestration engine)
# - Python 3 with PDF libraries (for security reports)
# - Security scanning tools: Semgrep, Trivy, TruffleHog
# - Custom security scripts
# - Configuration as Code (JCasC)
#
# What's NOT in this container (moved to build agents):
# - Java, Maven (heavy compilation - runs on agents)
# - Node.js, Angular (heavy builds - runs on agents)
#
# Build agents on the host server handle actual compilation.
# Jenkins master only orchestrates and runs lightweight security scans.
# ============================================================================

FROM jenkins/jenkins:lts

# Switch to root for system installations
USER root

# ============================================================================
# SYSTEM PACKAGES
# ============================================================================
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    jq \
    unzip \
    zip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# PYTHON 3 + LIBRARIES FOR PDF GENERATION
# ============================================================================
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libjpeg-dev \
    zlib1g-dev \
    && pip3 install --break-system-packages --no-cache-dir \
        reportlab \
        Pillow \
        requests \
        pyyaml \
    && python3 --version \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# SEMGREP - Static Application Security Testing (SAST)
# ============================================================================
RUN pip3 install --break-system-packages --no-cache-dir semgrep \
    && semgrep --version

# ============================================================================
# TRIVY - Vulnerability Scanner (Standalone Binary)
# ============================================================================
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.58.2/trivy_0.58.2_Linux-64bit.tar.gz \
    && tar -xzf trivy_0.58.2_Linux-64bit.tar.gz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/trivy \
    && rm trivy_0.58.2_Linux-64bit.tar.gz \
    && trivy --version

# ============================================================================
# TRUFFLEHOG v3 - Secret Scanner
# ============================================================================
RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.7/trufflehog_3.63.7_linux_amd64.tar.gz \
    && tar -xzf trufflehog_3.63.7_linux_amd64.tar.gz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/trufflehog \
    && rm trufflehog_3.63.7_linux_amd64.tar.gz \
    && trufflehog --version

# ============================================================================
# COPY CUSTOM SCRIPTS AND TEMPLATES
# ============================================================================
# Create security scripts directory
RUN mkdir -p /usr/local/bin/security-scripts && \
    mkdir -p /usr/local/bin/security-templates && \
    chmod 755 /usr/local/bin/security-scripts && \
    chmod 755 /usr/local/bin/security-templates

# Copy Python security scanning script
COPY scripts/security_scan.py /usr/local/bin/security-scripts/security_scan.py
RUN chmod +x /usr/local/bin/security-scripts/security_scan.py

# Copy Python PDF report generator
COPY scripts/generate_report.py /usr/local/bin/security-scripts/generate_report.py
RUN chmod +x /usr/local/bin/security-scripts/generate_report.py

# Copy TTS logo for PDF reports
COPY scripts/logo.png /usr/local/bin/security-scripts/logo.png
RUN chmod 644 /usr/local/bin/security-scripts/logo.png

# Copy email template
COPY templates/email_template.html /usr/local/bin/security-templates/email_template.html
RUN chmod 644 /usr/local/bin/security-templates/email_template.html

# ============================================================================
# INSTALL JENKINS PLUGINS
# ============================================================================
# Copy plugins list and install them
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# ============================================================================
# SKIP INITIAL SETUP WIZARD
# ============================================================================
# JCasC will handle all configuration
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# ============================================================================
# JCASC CONFIGURATION
# ============================================================================
# Set the path for JCasC configuration
ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc_configs/jcasc.yaml

# ============================================================================
# CLEANUP
# ============================================================================
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Switch back to Jenkins user
USER jenkins

# ============================================================================
# VERIFY INSTALLATIONS
# ============================================================================
RUN echo "=== SECURITY TOOLS ===" && \
    semgrep --version && \
    trivy --version && \
    trufflehog --version && \
    echo "" && \
    echo "=== PYTHON ===" && \
    python3 --version && \
    python3 -c "import reportlab; import PIL; import requests; import yaml; print('Python libraries OK')" && \
    echo "" && \
    echo "=== JENKINS LIGHTWEIGHT ORCHESTRATION CONTAINER READY ===" && \
    echo "Build tools (Java, Maven, Node) will run on dedicated agents"

# ============================================================================
# WORKSPACE
# ============================================================================
WORKDIR /var/jenkins_home

# Expose ports
EXPOSE 8080 50001
