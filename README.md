# Google SecOps (Chronicle) & Google Threat Intelligence (GTI) Unified API Runner

**Author:** Edwin Raja  
> **Disclaimer:** This application is **not an official Google product or service**. It is an independent workbench designed to help security engineers, customer engineers, and threat analysts interactively explore, test, and validate both **Google SecOps (Chronicle API)** and **Google Threat Intelligence (GTI v3 API)** directly against live instances.

---

## Key Features

- **Unified 2-Tab Workbench**:
  - **Tab 1 — Chronicle API (`1,352` endpoints across `24` categories)**: Complete coverage of Chronicle v1alpha, v1beta, Legacy Backstory (`v1`/`v2`), Ingestion, YARA-L 2.0 Rules, Retrohunts, Reference Lists, Data Tables, Native Dashboards, Cases & SOAR Integration.
  - **Tab 2 — GTI API (`381` endpoints across `15` categories)**: Complete coverage of Google Threat Intelligence / VirusTotal v3 (IOC Reputation for Files/URLs/Domains/IPs, GTI Threat Actors, Malware Families, Campaigns, Software & Toolkits, Reports, IoC Stream, Livehunt, Retrohunt, Attack Surface Management, Digital Threat Monitoring, and Private Scanning).
- **Zero Demo Data**: Connects exclusively to live Chronicle and GTI endpoints.
- **Hardened Cloud Run Security**:
  - **Fernet (AES-128-CBC + HMAC-SHA256) Encryption at Rest**: Service Account JSONs and GTI `x-apikey` values are encrypted before storage and strictly masked in the UI.
  - **Per-User Tenant Isolation**: Credentials, OAuth2 token caches, favorites, and execution history are isolated by authenticated `user_email`.
  - **Strict Outbound SSRF Allowlisting**: Enforces `https://` only and restricts outbound traffic to `*.chronicle.googleapis.com`, `*.backstory.googleapis.com`, `oauth2.googleapis.com`, and `www.virustotal.com`.
  - **Google IAP / Cloud Run Auth Verification**: Cryptographically verifies Google IAP ES256 JWTs (`X-Goog-IAP-JWT-Assertion`).

---

## Local Development

```bash
pip install -r requirements.txt
PORT=8089 python3 app.py
```

---

## Deploying to GitHub & Google Cloud Run

### 1. Push to GitHub
All local SQLite databases (`data/*.db`) and encryption keys (`data/.master_key`) are automatically excluded by `.gitignore`, `.dockerignore`, and `.gcloudignore`.

```bash
git init -b main
git add .
git commit -m "Initial commit: Unified Google SecOps & GTI API Runner"
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

### 2. Deploy to Google Cloud Run (CLI or Continuous Deployment from GitHub)

#### Option A: One-Command CLI Deployment
```bash
chmod +x deploy_cloud_run.sh
./deploy_cloud_run.sh <YOUR_GCP_PROJECT_ID> us-central1 secops-gti-api-runner
```

#### Option B: Deploy directly from GitHub in Google Cloud Console
1. Open **Google Cloud Console** $\rightarrow$ **Cloud Run** $\rightarrow$ **Create Service**.
2. Select **"Continuously deploy from a repository (source or function)"** $\rightarrow$ **Set up with Cloud Build**.
3. Connect your GitHub repository, select branch `^main$`, and choose **Dockerfile** (`Dockerfile`).
4. Under **Authentication**, select **Require authentication** (and optionally enable **Identity-Aware Proxy (IAP)**).
5. Under **Container(s), Volumes, Networking, Security** $\rightarrow$ **Variables & Secrets**, add:
   - `ENFORCE_IAP=true`
   - `ALLOW_TRUSTED_IAP_HEADER_ONLY=true`
   - `SECOPS_ENCRYPTION_KEY=<32-byte-url-safe-base64-fernet-key>` (or reference from Secret Manager).
6. Click **Create**.
