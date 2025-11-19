# 🚀 QUICK START GUIDE

**Get Jenkins running in 5 minutes!**

---

## STEP 1: Create .env file

```bash
cd jenkins-automation
cp .env.example .env
nano .env
```

Fill in your actual values (see `.env.example` for details).

---

## STEP 2: Validate configuration

```bash
./validate-env.sh
```

This checks if all required values are set. Fix any issues before proceeding.

---

## STEP 3: Stop existing containers (if running)

```bash
docker compose down
```

**Optional - Start completely fresh (deletes all data):**
```bash
docker volume rm jenkins-automation_jenkins_home
```

---

## STEP 4: Build and start

```bash
docker compose build jenkins
docker compose up -d
```

---

## STEP 5: Check status

```bash
docker compose ps
docker compose logs -f jenkins
```

Wait for: "Jenkins is fully up and running"

---

## STEP 6: Access Jenkins

Open browser: `http://YOUR_SERVER_IP:7080`

Login with:
- Username: Value from `JENKINS_ADMIN_USER` in .env
- Password: Value from `JENKINS_ADMIN_PASSWORD` in .env

---

## STEP 7: Generate SonarQube token

1. Open: `http://YOUR_SERVER_IP:9000`
2. Login: admin / admin (change password when prompted)
3. Go to: Administration → Security → Users → admin → Tokens
4. Generate token named "jenkins"
5. Copy token and update `.env`:
   ```bash
   nano .env
   # Update: SONARQUBE_TOKEN=squ_your_actual_token
   ```
6. Restart Jenkins:
   ```bash
   docker compose restart jenkins
   ```

---

## ✅ DONE!

Jenkins is ready. See README.md for detailed documentation and Phase 2 (build agent setup).

---

## 🔧 Troubleshooting

**Jenkins won't start:**
```bash
docker compose logs jenkins
```

**Validation fails:**
```bash
nano .env
# Fix the issues
./validate-env.sh
```

**Reset everything:**
```bash
docker compose down
docker volume rm jenkins-automation_jenkins_home
# Fix .env
docker compose up -d
```

---

**For detailed instructions, see README.md**
