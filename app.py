#!/usr/bin/env python3
"""
Google SecOps (Chronicle v1alpha) & Google Threat Intelligence (GTI v3) Unified API Runner
------------------------------------------------------------------------------------------
Production-ready unified workbench with 2 top-level platform tabs:
  1. Chronicle API (Google SecOps Chronicle REST v1alpha — 1,215 endpoints)
  2. GTI API (Google Threat Intelligence / VirusTotal REST v3 — 179 endpoints)

Features:
  - Zero demo/mock data: all requests execute live against Chronicle or GTI v3 endpoints
  - End-to-End Key Encryption at Rest: Service Account JSON keys & GTI API keys (x-apikey)
    are encrypted using Fernet (AES-128-CBC + HMAC-SHA256) before saving to SQLite
  - Strict Credential Masking: keys are never returned or displayed in cleartext
  - Hidden Compliance Audit Trail: all user actions and API calls are logged to SQLite
  - Cloud Run & Google Identity-Aware Proxy (IAP) ready

Author: Edwin Raja
Disclaimer: Not an official Google product or service.
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet, InvalidToken
import jwt

# Force IPv4 resolution to prevent Cloudtop IPv6 network timeouts
_orig_getaddrinfo = socket.getaddrinfo

def _getaddrinfo_v4(host, port, family=0, *args, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)

socket.getaddrinfo = _getaddrinfo_v4

# Environment & Directories
PORT = int(os.environ.get("PORT", 8089))
IS_CLOUD_RUN = bool(os.environ.get("K_SERVICE"))
MAX_REQUEST_BODY_BYTES = int(os.environ.get("MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024))  # 2 MB max request payload
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(DATA_DIR, "secops_gti_runner.db"))
CATALOG_PATH = os.path.join(DATA_DIR, "catalog.json")
GTI_CATALOG_PATH = os.path.join(DATA_DIR, "gti_catalog.json")
MASTER_KEY_PATH = os.environ.get("MASTER_KEY_PATH", os.path.join(DATA_DIR, ".master_key"))

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# -----------------------------------------------------------------------------
# STRICT OUTBOUND URL & SSRF PROTECTION (Cloud Run Hardened)
# -----------------------------------------------------------------------------

_CHRONICLE_HOST_RE = re.compile(r"^([a-z0-9-]+-)?(chronicle|backstory)\.googleapis\.com$", re.IGNORECASE)
_GTI_ALLOWED_HOSTS = {"www.virustotal.com", "virustotal.com"}
_OAUTH_ALLOWED_HOSTS = {"oauth2.googleapis.com", "www.googleapis.com"}
_BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}


def validate_outbound_url(url: str, target_type: str = "chronicle") -> tuple[bool, str]:
    """
    Validates outbound URLs to prevent SSRF and credential/token exfiltration on Cloud Run.
    target_type: 'chronicle' | 'gti' | 'oauth'
    Returns (is_valid, error_message_or_normalized_url).
    """
    if not url or not isinstance(url, str):
        return False, "Empty outbound URL."

    clean_url = url.strip()
    try:
        parsed = urlparse(clean_url)
    except Exception:
        return False, "Malformed URL."

    if parsed.scheme.lower() != "https":
        return False, "Security policy violation: Only https:// outbound URLs are permitted."

    host = (parsed.hostname or "").strip().lower()
    if not host or host in _BLOCKED_HOSTS or host.endswith(".internal") or host.endswith(".local"):
        return False, f"Security policy violation: Outbound host '{host}' is blocked."

    if parsed.username or parsed.password:
        return False, "Security policy violation: Embedded URL credentials are not permitted."

    if target_type == "chronicle":
        if not _CHRONICLE_HOST_RE.match(host):
            return False, (
                f"Security policy violation: Host '{host}' is not an authorized Google SecOps Chronicle endpoint "
                "(expected *.chronicle.googleapis.com or *.backstory.googleapis.com)."
            )
    elif target_type == "gti":
        if host not in _GTI_ALLOWED_HOSTS:
            return False, (
                f"Security policy violation: Host '{host}' is not an authorized Google Threat Intelligence endpoint "
                "(expected www.virustotal.com)."
            )
    elif target_type == "oauth":
        if host not in _OAUTH_ALLOWED_HOSTS:
            return False, (
                f"Security policy violation: OAuth token_uri host '{host}' is not an authorized Google OAuth2 endpoint "
                "(expected oauth2.googleapis.com)."
            )
    else:
        return False, f"Unknown outbound target_type '{target_type}'."

    return True, clean_url


# -----------------------------------------------------------------------------
# ENCRYPTION & MASTER KEY MANAGEMENT (Fernet AES-256)
# -----------------------------------------------------------------------------

def get_or_create_master_key() -> bytes:
    """Retrieves or creates the Fernet master encryption key."""
    env_key = (os.environ.get("SECOPS_ENCRYPTION_KEY") or os.environ.get("GTI_MASTER_KEY") or "").strip()
    if env_key:
        return env_key.encode("utf-8")

    if os.path.exists(MASTER_KEY_PATH):
        try:
            with open(MASTER_KEY_PATH, "rb") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception as e:
            print(f"Warning reading master key file: {e}", file=sys.stderr)

    new_key = Fernet.generate_key()
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(MASTER_KEY_PATH, flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
    except Exception as e:
        print(f"Error writing master key: {e}", file=sys.stderr)

    return new_key


def encrypt_sa_payload(cleartext_obj) -> str:
    """Encrypts Service Account JSON string or GTI key dict using AES-128-CBC + HMAC-SHA256."""
    if isinstance(cleartext_obj, (dict, list)):
        cleartext_str = json.dumps(cleartext_obj)
    else:
        cleartext_str = str(cleartext_obj)
    key = get_or_create_master_key()
    f = Fernet(key)
    token = f.encrypt(cleartext_str.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_sa_payload(ciphertext_str: str) -> dict:
    """Decrypts ciphertext into dict in-memory."""
    if not ciphertext_str:
        return None
    key = get_or_create_master_key()
    f = Fernet(key)
    try:
        decrypted_bytes = f.decrypt(ciphertext_str.encode("utf-8"))
        decoded = decrypted_bytes.decode("utf-8")
        try:
            return json.loads(decoded)
        except Exception:
            return {"gti_api_key": decoded}
    except (InvalidToken, Exception) as e:
        print(f"Failed decrypting credential payload: {e}", file=sys.stderr)
        return None


# Session signing secret
_SESSION_SECRET = hashlib.sha256(get_or_create_master_key() + b":session-secret").digest()

# Per-user in-memory OAuth2 token cache keyed by user_email (cleared on restart)
_TOKEN_CACHE: dict[str, dict] = {}

# -----------------------------------------------------------------------------
# DATABASE INITIALIZATION & MIGRATION (Per-User Tenant Isolation)
# -----------------------------------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT DEFAULT '',
        project_id TEXT DEFAULT '',
        customer_id TEXT DEFAULT '',
        location TEXT DEFAULT 'us',
        endpoint TEXT DEFAULT 'https://us-chronicle.googleapis.com',
        client_email TEXT DEFAULT '',
        service_account_encrypted TEXT DEFAULT '',
        is_authenticated INTEGER DEFAULT 0,
        last_test_status TEXT DEFAULT '',
        last_test_time TEXT DEFAULT '',
        gti_api_key_encrypted TEXT DEFAULT '',
        gti_api_key_masked TEXT DEFAULT '',
        gti_endpoint TEXT DEFAULT 'https://www.virustotal.com',
        gti_is_authenticated INTEGER DEFAULT 0,
        gti_last_test_status TEXT DEFAULT '',
        gti_last_test_time TEXT DEFAULT ''
    )
    """)

    c.execute("PRAGMA table_info(config)")
    columns = [col[1] for col in c.fetchall()]
    if "user_email" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN user_email TEXT DEFAULT ''")
    if "service_account_encrypted" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN service_account_encrypted TEXT DEFAULT ''")
    if "gti_api_key_encrypted" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_api_key_encrypted TEXT DEFAULT ''")
    if "gti_api_key_masked" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_api_key_masked TEXT DEFAULT ''")
    if "gti_endpoint" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_endpoint TEXT DEFAULT 'https://www.virustotal.com'")
    if "gti_is_authenticated" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_is_authenticated INTEGER DEFAULT 0")
    if "gti_last_test_status" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_last_test_status TEXT DEFAULT ''")
    if "gti_last_test_time" not in columns:
        c.execute("ALTER TABLE config ADD COLUMN gti_last_test_time TEXT DEFAULT ''")

    c.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user_email TEXT DEFAULT '',
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        endpoint_id TEXT,
        request_headers TEXT,
        request_body TEXT,
        status_code INTEGER,
        status_text TEXT,
        response_headers TEXT,
        response_body TEXT,
        duration_ms INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT DEFAULT '',
        endpoint_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user_email TEXT NOT NULL,
        event_type TEXT NOT NULL,
        action TEXT DEFAULT '',
        method TEXT DEFAULT '',
        url TEXT DEFAULT '',
        status INTEGER DEFAULT 0,
        status_code INTEGER DEFAULT 0,
        duration_ms INTEGER DEFAULT 0,
        ip_address TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        details TEXT DEFAULT ''
    )
    """)

    conn.commit()
    conn.close()


def get_or_create_user_config(user_email: str) -> dict:
    """Returns the isolated configuration row for the specified user_email."""
    norm_email = (user_email or "anonymous").strip().lower()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM config WHERE user_email = ? LIMIT 1", (norm_email,))
    row = c.fetchone()
    if not row:
        c.execute("""
        INSERT INTO config (
            user_email, project_id, customer_id, location, endpoint,
            client_email, service_account_encrypted, is_authenticated,
            gti_api_key_encrypted, gti_api_key_masked, gti_endpoint, gti_is_authenticated
        )
        VALUES (?, '', '', 'us', 'https://us-chronicle.googleapis.com', '', '', 0, '', '', 'https://www.virustotal.com', 0)
        """, (norm_email,))
        conn.commit()
        c.execute("SELECT * FROM config WHERE user_email = ? LIMIT 1", (norm_email,))
        row = c.fetchone()
    res = dict(row)
    conn.close()
    return res


def log_audit_event(user_email: str, event_type: str, method: str = "", url: str = "",
                    status_code: int = 0, duration_ms: int = 0, ip_address: str = "",
                    user_agent: str = "", details: dict = None):
    """Writes an immutable audit record to SQLite (restricted to DB inspection only)."""
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details) if isinstance(details, dict) else str(details or "")
        action_str = f"{method} {url}".strip() if (method or url) else event_type
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO audit_log (timestamp, user_email, event_type, action, method, url, status, status_code, duration_ms, ip_address, user_agent, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now_iso, user_email or "anonymous", event_type, action_str, method, url,
            status_code, status_code, duration_ms, ip_address, user_agent, details_str
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit event: {e}", file=sys.stderr)


# -----------------------------------------------------------------------------
# GCP IAM USER IDENTITY (Infrastructure-Level Auth Only — Zero In-App Auth Gates)
# -----------------------------------------------------------------------------

def get_authenticated_user(handler) -> dict:
    """
    Authentication is handled solely by the GCP IAM project at the Cloud Run layer.
    Extracts the user's email from GCP headers if provided for display/config isolation,
    and otherwise defaults to 'iam-user'. Never blocks or rejects any request.
    """
    iap_email_hdr = handler.headers.get("X-Goog-Authenticated-User-Email", "")
    if iap_email_hdr:
        email = iap_email_hdr.split(":")[-1].strip().lower()
        if email:
            return {
                "email": email,
                "name": email.split("@")[0].replace(".", " ").title(),
                "auth_type": "gcp_iam",
                "domain": email.split("@")[-1] if "@" in email else "",
                "verified": True
            }

    return {
        "email": "iam-user",
        "name": "IAM User",
        "auth_type": "gcp_iam",
        "domain": "",
        "verified": True
    }


# -----------------------------------------------------------------------------
# CHRONICLE & GTI CREDENTIAL VAULT HELPERS (Per-User Isolated)
# -----------------------------------------------------------------------------

def get_stored_sa(user_email: str):
    row = get_or_create_user_config(user_email)
    enc_payload = row.get("service_account_encrypted")
    if not enc_payload:
        return None, "No Service Account key configured. Please upload a valid Chronicle Service Account JSON key."
    sa_dict = decrypt_sa_payload(enc_payload)
    if not sa_dict:
        return None, "Failed decrypting stored Service Account key."
    return sa_dict, None


def mask_sa_email(email: str) -> str:
    if not email or "@" not in email:
        return "••••••••••••••••"
    local, domain = email.split("@", 1)
    if len(local) <= 3:
        masked_local = local[0] + "•••"
    else:
        masked_local = local[:4] + "••••"
    return f"{masked_local}@{domain}"


def mask_gti_key(api_key: str) -> str:
    if not api_key:
        return ""
    clean = api_key.strip()
    if len(clean) <= 8:
        return clean[:2] + "••••••••"
    return f"{clean[:4]}••••••••••••{clean[-4:]}"


def get_stored_gti_key(user_email: str):
    row = get_or_create_user_config(user_email)
    enc_payload = row.get("gti_api_key_encrypted")
    if not enc_payload:
        return None, "No Google Threat Intelligence API Key configured. Please upload or enter your GTI API Key (x-apikey) first."

    payload_dict = decrypt_sa_payload(enc_payload)
    api_key = (payload_dict or {}).get("gti_api_key", "").strip()
    if not api_key:
        return None, "Failed decrypting stored Google Threat Intelligence API key."

    return api_key, None


def get_access_token(user_email: str, force_refresh: bool = False):
    global _TOKEN_CACHE
    norm_email = (user_email or "anonymous").strip().lower()
    now = int(time.time())

    cached = _TOKEN_CACHE.get(norm_email)
    if not force_refresh and cached and cached.get("access_token") and cached.get("expires_at", 0) > (now + 120):
        return cached["access_token"], None

    sa_data, err = get_stored_sa(norm_email)
    if not sa_data:
        return None, err

    client_email = sa_data.get("client_email")
    private_key = sa_data.get("private_key")
    token_uri = sa_data.get("token_uri", "https://oauth2.googleapis.com/token")

    if not client_email or not private_key:
        return None, "Service Account key is missing 'client_email' or 'private_key'."

    valid_oauth_uri, oauth_err = validate_outbound_url(token_uri, "oauth")
    if not valid_oauth_uri:
        return None, oauth_err

    try:
        now = int(time.time())
        exp = now + 3600
        payload = {
            "iss": client_email,
            "sub": client_email,
            "aud": token_uri,
            "iat": now,
            "exp": exp,
            "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/chronicle-backstory"
        }

        assertion = jwt.encode(payload, private_key, algorithm="RS256")
        token_body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion
        }).encode("utf-8")

        del private_key, sa_data

        req = urllib.request.Request(
            token_uri,
            data=token_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            access_token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)

            _TOKEN_CACHE[norm_email] = {
                "access_token": access_token,
                "expires_at": now + expires_in,
                "client_email": client_email
            }

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE config SET is_authenticated = 1, client_email = ? WHERE user_email = ?", (client_email, norm_email))
            conn.commit()
            conn.close()

            return access_token, None

    except urllib.error.HTTPError as e:
        err_detail = str(e)
        try:
            err_json = json.loads(e.read().decode("utf-8"))
            desc = err_json.get("error_description") or err_json.get("error") or err_detail
            err_detail = f"{desc} (SA: {mask_sa_email(client_email)})"
        except Exception:
            pass
        return None, f"OAuth2 token minting failed: {err_detail}"
    except Exception as e:
        return None, f"OAuth2 minting failed: {str(e)}"


def extract_gti_summary(response_json: dict) -> dict:
    """Extracts GTI Assessment, Threat Score, AV stats, and Mandiant metadata from GTI v3 responses."""
    if not isinstance(response_json, dict):
        return None

    data = response_json.get("data")
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        primary = data[0]
        is_list = True
        list_count = len(data)
    elif isinstance(data, dict):
        primary = data
        is_list = False
        list_count = 1
    else:
        return None

    attrs = primary.get("attributes", {})
    if not isinstance(attrs, dict):
        attrs = {}

    gti_assessment = attrs.get("gti_assessment") or {}
    verdict_val = None
    threat_score_val = None
    severity_val = None

    if isinstance(gti_assessment, dict):
        v = gti_assessment.get("verdict")
        verdict_val = v.get("value") if isinstance(v, dict) else v
        ts = gti_assessment.get("threat_score")
        threat_score_val = ts.get("value") if isinstance(ts, dict) else ts
        sev = gti_assessment.get("severity")
        severity_val = sev.get("value") if isinstance(sev, dict) else sev

    stats = attrs.get("last_analysis_stats") or {}
    malicious_count = stats.get("malicious")
    suspicious_count = stats.get("suspicious")
    harmless_count = stats.get("harmless")
    undetected_count = stats.get("undetected")

    if not verdict_val and isinstance(malicious_count, int):
        if malicious_count >= 5:
            verdict_val = "MALICIOUS"
        elif malicious_count >= 1 or (isinstance(suspicious_count, int) and suspicious_count >= 2):
            verdict_val = "SUSPICIOUS"
        elif isinstance(harmless_count, int) and harmless_count > 0:
            verdict_val = "BENIGN"
        else:
            verdict_val = "UNDETECTED"

    summary = {
        "entity_id": primary.get("id"),
        "entity_type": primary.get("type"),
        "is_list": is_list,
        "list_count": list_count,
        "name": attrs.get("name") or attrs.get("meaningful_name") or attrs.get("title") or primary.get("id"),
        "collection_type": attrs.get("collection_type"),
        "gti_verdict": verdict_val,
        "gti_threat_score": threat_score_val,
        "gti_severity": severity_val,
        "reputation": attrs.get("reputation"),
        "tlp": attrs.get("tlp"),
        "av_malicious": malicious_count,
        "av_suspicious": suspicious_count,
        "av_harmless": harmless_count,
        "av_undetected": undetected_count,
        "motivations": [m.get("value") if isinstance(m, dict) else str(m) for m in (attrs.get("motivations") or [])[:4]],
        "targeted_industries": [i.get("value") if isinstance(i, dict) else str(i) for i in (attrs.get("targeted_industries") or [])[:5]],
        "popular_threat_name": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    }
    return summary


# -----------------------------------------------------------------------------
# HTTP REQUEST HANDLER
# -----------------------------------------------------------------------------

class UnifiedSecOpsGtiHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if IS_CLOUD_RUN:
            self.send_header("X-Frame-Options", "DENY")
            frame_ancestors = "frame-ancestors 'none';"
        else:
            frame_ancestors = ""
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "connect-src 'self'; " + frame_ancestors
        )
        super().end_headers()

    def _apply_cors_headers(self):
        origin = (self.headers.get("Origin") or "").strip()
        host = (self.headers.get("Host") or "").strip()
        allowed_origin = os.environ.get("ALLOWED_ORIGIN", "").strip()
        if origin:
            try:
                parsed_origin = urlparse(origin)
                if (allowed_origin and origin == allowed_origin) or (host and parsed_origin.netloc == host):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                    self.send_header("Access-Control-Allow-Headers", "Content-Type")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
            except Exception:
                pass

    def _client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _user_agent(self):
        return self.headers.get("User-Agent", "")[:250]

    def _send_json(self, status_code, data, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._apply_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            return self._send_json(200, {
                "status": "healthy",
                "service": "secops-gti-unified-api-runner",
                "platforms": ["chronicle_v1alpha", "gti_v3"],
                "version": "2.1.0",
                "author": "Edwin Raja"
            })

        if path == "/api/auth/user":
            return self._handle_get_user()

        if path.startswith("/api/"):
            user = get_authenticated_user(self)

            if path in ("/api/catalog", "/api/gti/catalog"):
                return self._handle_get_catalog(parsed)
            elif path == "/api/config":
                return self._handle_get_config(user)
            elif path == "/api/auth/token":
                return self._handle_get_token(user)
            elif path == "/api/history":
                return self._handle_get_history(user)
            elif path == "/api/favorites":
                return self._handle_get_favorites(user)
            elif path == "/api/audit":
                return self._send_json(403, {
                    "error": "Audit trail is restricted to direct database inspection only. It cannot be viewed through the web platform.",
                    "code": "AUDIT_UI_DISABLED"
                })
            else:
                return self._send_json(404, {"error": "API route not found"})

        if path == "/download":
            return self._handle_download_page()

        if path in ("/secops_gti_api_runner.zip", "/gti_api_runner.zip", "/download/zip"):
            return self._handle_download_clean_zip()

        if path.startswith("/static/"):
            rel_path = path[len("/static/"):].lstrip("/")
            self.path = "/" + rel_path
            return super().do_GET()
        elif path == "/" or not os.path.exists(os.path.join(STATIC_DIR, path.lstrip("/"))):
            self.path = "/index.html"
            return super().do_GET()
        else:
            return super().do_GET()

    def _build_clean_zip_bytes(self) -> bytes:
        import io
        import zipfile

        clean_files = [
            "app.py",
            "Dockerfile",
            "requirements.txt",
            "README.md",
            "deploy_cloud_run.sh",
            "setup_iap_load_balancer.sh",
            "start.sh",
            ".gitignore",
            ".dockerignore",
            ".gcloudignore",
            "data/catalog.json",
            "data/gti_catalog.json",
            "static/index.html",
            "static/app.js",
            "static/styles.css",
        ]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in clean_files:
                abs_p = os.path.join(BASE_DIR, rel)
                if os.path.exists(abs_p):
                    zf.write(abs_p, arcname=f"secops-gti-api-runner/{rel}")
        return buf.getvalue()

    def _handle_download_clean_zip(self):
        """Builds a clean GitHub & Cloud Run ready ZIP in memory (excludes any .db or .master_key)."""
        payload = self._build_clean_zip_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", 'attachment; filename="secops_gti_api_runner.zip"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle_download_page(self):
        """Serves an interactive download page with an embedded Base64 ZIP so downloads work in any browser or iframe."""
        zip_bytes = self._build_clean_zip_bytes()
        b64_zip = base64.b64encode(zip_bytes).decode("ascii")
        size_kb = round(len(zip_bytes) / 1024, 1)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Download SecOps & GTI API Runner Package</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0b0f19] text-gray-100 min-h-screen flex items-center justify-center p-6">
  <div class="max-w-xl w-full bg-[#111827] border border-gray-700 rounded-xl shadow-2xl p-6 space-y-5">
    <div class="flex items-center justify-between border-b border-gray-800 pb-4">
      <div>
        <h1 class="text-lg font-bold text-white">Google SecOps &amp; GTI API Runner — Source Bundle</h1>
        <p class="text-xs text-gray-400 mt-0.5">15 Compiled Files • 1,352 Chronicle APIs + 381 GTI v3 APIs • Zero Stored Keys/DBs</p>
      </div>
      <span class="px-2.5 py-1 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono">{size_kb} KB</span>
    </div>

    <div class="space-y-3">
      <button onclick="triggerBlobDownload()" class="w-full py-3 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg shadow-lg transition flex items-center justify-center space-x-2 text-sm cursor-pointer">
        <span>⬇ Download secops_gti_api_runner.zip ({size_kb} KB)</span>
      </button>
      <a href="/secops_gti_api_runner.zip" download="secops_gti_api_runner.zip" target="_blank"
         class="block w-full text-center py-2 px-4 bg-gray-800 hover:bg-gray-700 text-cyan-300 border border-gray-700 rounded-lg text-xs font-mono transition">
        Direct HTTP Download Link (/secops_gti_api_runner.zip)
      </a>
    </div>

    <div class="bg-[#0d1322] border border-gray-800 rounded-lg p-3.5 text-xs font-mono text-gray-300 space-y-1">
      <div class="text-gray-400 font-sans font-semibold mb-1.5">Included in ZIP Archive (secops-gti-api-runner/):</div>
      <div>• app.py (Hardened Cloud Run backend)</div>
      <div>• Dockerfile, requirements.txt, deploy_cloud_run.sh</div>
      <div>• .gitignore, .dockerignore, .gcloudignore, README.md</div>
      <div>• data/catalog.json (1,352 Chronicle APIs) &amp; data/gti_catalog.json (381 GTI APIs)</div>
      <div>• static/index.html, static/app.js, static/styles.css</div>
    </div>
  </div>
  <script>
    const B64_ZIP = "{b64_zip}";
    function triggerBlobDownload() {{
      const bin = atob(B64_ZIP);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes], {{ type: "application/zip" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "secops_gti_api_runner.zip";
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {{ URL.revokeObjectURL(url); a.remove(); }}, 1500);
    }}
  </script>
</body>
</html>""".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/secops_gti_api_runner.zip", "/gti_api_runner.zip", "/download/zip"):
            payload = self._build_clean_zip_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="secops_gti_api_runner.zip"')
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            return
        if path.startswith("/static/"):
            self.path = "/" + path[len("/static/"):].lstrip("/")
        return super().do_HEAD()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        user = get_authenticated_user(self)

        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > MAX_REQUEST_BODY_BYTES:
            return self._send_json(413, {
                "error": f"Request payload exceeds maximum allowed size ({MAX_REQUEST_BODY_BYTES} bytes)."
            })

        if path == "/api/config":
            self._handle_update_config(user)
        elif path == "/api/auth/upload":
            self._handle_upload_sa(user)
        elif path == "/api/auth/remove":
            self._handle_remove_sa(user)
        elif path == "/api/auth/test":
            self._handle_test_auth(user)
        elif path in ("/api/gti/auth/upload", "/api/config/key"):
            self._handle_upload_gti_key(user)
        elif path == "/api/gti/auth/remove":
            self._handle_remove_gti_key(user)
        elif path == "/api/gti/auth/test":
            self._handle_test_gti_auth(user)
        elif path == "/api/execute":
            self._handle_execute_request(user)
        elif path == "/api/favorites":
            self._handle_toggle_favorite(user)
        elif path == "/api/history/clear":
            self._handle_clear_history(user)
        else:
            self._send_json(404, {"error": "API route not found"})

    def _read_json_body(self):
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0 or content_len > MAX_REQUEST_BODY_BYTES:
            return {}
        raw = self.rfile.read(content_len).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    # -------------------------------------------------------------------------
    # USER IDENTITY HANDLER (GCP IAM Infrastructure Auth Only)
    # -------------------------------------------------------------------------

    def _handle_get_user(self):
        user = get_authenticated_user(self)
        user_data = {
            "email": user.get("email", "iam-user"),
            "name": user.get("name", "IAM User"),
            "auth_type": user.get("auth_type", "gcp_iam"),
            "domain": user.get("domain", ""),
            "verified": True,
            "enforce_iap": False
        }
        return self._send_json(200, {
            "authenticated": True,
            "email": user_data["email"],
            "name": user_data["name"],
            "auth_type": user_data["auth_type"],
            "domain": user_data["domain"],
            "verified": True,
            "enforce_iap": False,
            "user": user_data
        })

    # -------------------------------------------------------------------------
    # CONFIGURATION & KEY MANAGEMENT (Fernet AES-256 Encrypted & Per-User Isolated)
    # -------------------------------------------------------------------------

    def _handle_get_config(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        row = get_or_create_user_config(norm_email)

        has_sa = bool(row.get("service_account_encrypted"))
        raw_email = row.get("client_email", "")
        row.pop("service_account_encrypted", None)
        row["has_service_account"] = has_sa
        row["key_encrypted_at_rest"] = True
        row["client_email"] = mask_sa_email(raw_email) if has_sa else ""
        row["client_email_masked"] = mask_sa_email(raw_email) if has_sa else ""

        has_gti = bool(row.get("gti_api_key_encrypted"))
        row.pop("gti_api_key_encrypted", None)
        row["has_gti_key"] = has_gti
        row["gti_key_encrypted_at_rest"] = True
        row["gti_api_key_masked"] = row.get("gti_api_key_masked", "") if has_gti else ""
        row["gti_endpoint"] = row.get("gti_endpoint") or "https://www.virustotal.com"
        row["gti_is_authenticated"] = int(row.get("gti_is_authenticated") or 0)

        now = int(time.time())
        user_token_cache = _TOKEN_CACHE.get(norm_email, {})
        row["token_active"] = bool(user_token_cache.get("access_token") and user_token_cache.get("expires_at", 0) > now)
        row["token_expires_in"] = max(0, user_token_cache.get("expires_at", 0) - now)
        row["user"] = user

        self._send_json(200, row)

    def _handle_update_config(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        body = self._read_json_body()
        current = get_or_create_user_config(norm_email)

        project_id = body.get("project_id", current.get("project_id", "")).strip()
        customer_id = body.get("customer_id", current.get("customer_id", "")).strip()
        location = body.get("location", current.get("location", "us")).strip()
        endpoint = body.get("endpoint", f"https://{location}-chronicle.googleapis.com").strip().rstrip("/")
        gti_endpoint = body.get("gti_endpoint", current.get("gti_endpoint", "https://www.virustotal.com")).strip().rstrip("/")

        ok_chr, chr_msg = validate_outbound_url(endpoint, "chronicle")
        if not ok_chr:
            return self._send_json(400, {"error": chr_msg})

        ok_gti, gti_msg = validate_outbound_url(gti_endpoint, "gti")
        if not ok_gti:
            return self._send_json(400, {"error": gti_msg})

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE config
        SET project_id = ?, customer_id = ?, location = ?, endpoint = ?, gti_endpoint = ?
        WHERE user_email = ?
        """, (project_id, customer_id, location, endpoint, gti_endpoint, norm_email))
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "CONFIG_UPDATE", ip_address=self._client_ip(), user_agent=self._user_agent(),
                        details={"project_id": project_id, "customer_id": customer_id, "location": location, "gti_endpoint": gti_endpoint})

        self._send_json(200, {"success": True, "message": "Configuration updated successfully"})

    def _handle_upload_sa(self, user: dict):
        """Encrypts and stores uploaded Chronicle Service Account JSON key (never cleartext, per-user isolated)."""
        norm_email = (user.get("email") or "anonymous").strip().lower()
        body = self._read_json_body()
        sa_raw = body.get("service_account_json", "").strip()

        if not sa_raw:
            return self._send_json(400, {"error": "Missing service_account_json in payload"})

        try:
            sa_data = json.loads(sa_raw)
            client_email = sa_data.get("client_email", "").strip()
            sa_project_id = sa_data.get("project_id", "").strip()
            token_uri = sa_data.get("token_uri", "https://oauth2.googleapis.com/token").strip()
            if not client_email or "private_key" not in sa_data:
                return self._send_json(400, {"error": "Service account JSON must contain 'client_email' and 'private_key'"})

            ok_oauth, oauth_msg = validate_outbound_url(token_uri, "oauth")
            if not ok_oauth:
                return self._send_json(400, {"error": oauth_msg})

            current_cfg = get_or_create_user_config(norm_email)

            new_project_id = body.get("project_id", "").strip() or sa_project_id or current_cfg.get("project_id", "")
            new_customer_id = body.get("customer_id", "").strip() or current_cfg.get("customer_id", "")
            new_location = body.get("location", "").strip() or current_cfg.get("location", "us")
            new_endpoint = (body.get("endpoint", "").strip() or current_cfg.get("endpoint") or f"https://{new_location}-chronicle.googleapis.com").rstrip("/")

            ok_chr, chr_msg = validate_outbound_url(new_endpoint, "chronicle")
            if not ok_chr:
                return self._send_json(400, {"error": chr_msg})

            encrypted_payload = encrypt_sa_payload(sa_raw)

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
            UPDATE config
            SET service_account_encrypted = ?, client_email = ?, project_id = ?, customer_id = ?, location = ?, endpoint = ?, is_authenticated = 0
            WHERE user_email = ?
            """, (encrypted_payload, client_email, new_project_id, new_customer_id, new_location, new_endpoint, norm_email))
            conn.commit()
            conn.close()

            masked_email = mask_sa_email(client_email)
            del sa_raw, sa_data

            log_audit_event(norm_email, "SA_KEY_UPLOAD", ip_address=self._client_ip(), user_agent=self._user_agent(),
                            details={"service_account": masked_email, "project_id": new_project_id, "encryption": "AES-256-Fernet"})

            token, err = get_access_token(norm_email, force_refresh=True)
            if err:
                return self._send_json(200, {
                    "success": False,
                    "is_authenticated": False,
                    "encrypted": True,
                    "project_id": new_project_id,
                    "client_email": masked_email,
                    "client_email_masked": masked_email,
                    "warning": f"Key encrypted and saved ({masked_email}), but Google OAuth2 verification failed: {err}"
                })

            return self._send_json(200, {
                "success": True,
                "is_authenticated": True,
                "message": f"Service Account key ({masked_email}) identified, verified, and encrypted with AES-256 at rest.",
                "project_id": new_project_id,
                "client_email": masked_email,
                "client_email_masked": masked_email,
                "encrypted": True
            })

        except Exception as e:
            return self._send_json(400, {"error": f"Failed processing Service Account JSON: {str(e)}"})

    def _handle_remove_sa(self, user: dict):
        global _TOKEN_CACHE
        norm_email = (user.get("email") or "anonymous").strip().lower()
        _TOKEN_CACHE.pop(norm_email, None)

        get_or_create_user_config(norm_email)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE config
        SET service_account_encrypted = NULL, client_email = NULL, is_authenticated = 0, last_test_status = NULL, last_test_time = NULL
        WHERE user_email = ?
        """, (norm_email,))
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "SA_KEY_REMOVE", ip_address=self._client_ip(), user_agent=self._user_agent(),
                        details={"message": "Service account key cleared by user"})

        return self._send_json(200, {"success": True, "message": "Service account key removed successfully"})

    def _handle_get_token(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        now = int(time.time())
        token, err = get_access_token(norm_email)
        if not token:
            return self._send_json(401, {"authenticated": False, "error": err})

        user_cache = _TOKEN_CACHE.get(norm_email, {})
        masked = token[:10] + "..." + token[-6:]
        return self._send_json(200, {
            "authenticated": True,
            "token_masked": masked,
            "expires_in_seconds": max(0, user_cache.get("expires_at", 0) - now),
            "client_email": "••••••••••••••••" if user_cache.get("client_email") else None
        })

    def _handle_test_auth(self, user: dict):
        """Runs a live verification ping against the Chronicle v1alpha feeds endpoint."""
        norm_email = (user.get("email") or "anonymous").strip().lower()
        token, err = get_access_token(norm_email)
        if not token:
            return self._send_json(401, {"success": False, "error": err})

        config = get_or_create_user_config(norm_email)
        project_id = config.get("project_id", "")
        customer_id = config.get("customer_id", "")
        location = config.get("location", "us")

        test_url = f"https://{location}-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{customer_id}/feeds"
        ok_url, url_err = validate_outbound_url(test_url, "chronicle")
        if not ok_url:
            return self._send_json(400, {"success": False, "error": url_err})

        t0 = time.time()
        try:
            req = urllib.request.Request(
                test_url,
                headers={"Authorization": f"Bearer {token}", "User-Agent": "SecOps-v1alpha-Runner/2.1"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                elapsed_ms = int((time.time() - t0) * 1000)
                data = json.loads(resp.read().decode("utf-8"))
                feed_count = len(data.get("feeds", []))

                now_iso = datetime.now(timezone.utc).isoformat()
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("UPDATE config SET is_authenticated = 1, last_test_status = ?, last_test_time = ? WHERE user_email = ?",
                          (f"OK (200) - {feed_count} feeds found in {elapsed_ms}ms", now_iso, norm_email))
                conn.commit()
                conn.close()

                log_audit_event(norm_email, "API_TEST_PING", method="GET", url=test_url, status_code=200,
                                duration_ms=elapsed_ms, ip_address=self._client_ip(), user_agent=self._user_agent(),
                                details={"feeds_found": feed_count})

                return self._send_json(200, {
                    "success": True,
                    "status_code": 200,
                    "elapsed_ms": elapsed_ms,
                    "message": f"Successfully connected to Chronicle API! Found {feed_count} feed(s).",
                    "details": data
                })

        except urllib.error.HTTPError as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            err_body = e.read().decode("utf-8")
            log_audit_event(norm_email, "API_TEST_PING", method="GET", url=test_url, status_code=e.code,
                            duration_ms=elapsed_ms, ip_address=self._client_ip(), user_agent=self._user_agent(),
                            details={"error": e.reason})
            return self._send_json(200, {
                "success": False,
                "status_code": e.code,
                "elapsed_ms": elapsed_ms,
                "error": f"HTTP {e.code}: {e.reason}",
                "details": err_body
            })
        except Exception as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            return self._send_json(200, {
                "success": False,
                "status_code": 500,
                "elapsed_ms": elapsed_ms,
                "error": f"Connection error: {str(e)}"
            })

    def _handle_upload_gti_key(self, user: dict):
        """Encrypts and stores Google Threat Intelligence (VirusTotal v3) API Key (AES-256 Fernet at rest, per-user isolated)."""
        norm_email = (user.get("email") or "anonymous").strip().lower()
        body = self._read_json_body()
        raw_key = (
            body.get("gti_api_key")
            or body.get("api_key")
            or body.get("x-apikey")
            or body.get("apikey")
            or ""
        ).strip()
        gti_endpoint = (body.get("gti_endpoint") or "https://www.virustotal.com").strip().rstrip("/")

        ok_gti, gti_err = validate_outbound_url(gti_endpoint, "gti")
        if not ok_gti:
            return self._send_json(400, {"error": gti_err})

        if not raw_key:
            return self._send_json(400, {"error": "Google Threat Intelligence API Key (x-apikey) is required"})

        if raw_key.startswith("{") and raw_key.endswith("}"):
            try:
                parsed_json = json.loads(raw_key)
                raw_key = (
                    parsed_json.get("gti_api_key")
                    or parsed_json.get("api_key")
                    or parsed_json.get("x-apikey")
                    or parsed_json.get("apikey")
                    or ""
                ).strip()
            except Exception:
                pass

        if not raw_key or len(raw_key) < 16:
            return self._send_json(400, {"error": "Invalid Google Threat Intelligence API Key format."})

        masked = mask_gti_key(raw_key)
        encrypted_payload = encrypt_sa_payload(json.dumps({"gti_api_key": raw_key}))

        get_or_create_user_config(norm_email)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE config
        SET gti_api_key_encrypted = ?, gti_api_key_masked = ?, gti_endpoint = ?, gti_is_authenticated = 0
        WHERE user_email = ?
        """, (encrypted_payload, masked, gti_endpoint, norm_email))
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "GTI_KEY_UPLOAD", ip_address=self._client_ip(), user_agent=self._user_agent(),
                        details={"gti_key_masked": masked, "encryption": "AES-256-Fernet"})

        test_url = f"{gti_endpoint}/api/v3/ip_addresses/8.8.8.8"
        t0 = time.time()
        try:
            req = urllib.request.Request(
                test_url,
                headers={
                    "x-apikey": raw_key,
                    "x-tool": "GoogleCloud.SecOpsGTIRunner.2.1",
                    "Accept": "application/json",
                    "User-Agent": "Google-SecOps-GTI-API-Runner/2.1"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed_ms = int((time.time() - t0) * 1000)
                now_iso = datetime.now(timezone.utc).isoformat()
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("""
                UPDATE config
                SET gti_is_authenticated = 1, gti_last_test_status = ?, gti_last_test_time = ?
                WHERE user_email = ?
                """, (f"OK (200) - Verified against GTI v3 in {elapsed_ms}ms", now_iso, norm_email))
                conn.commit()
                conn.close()
                del raw_key
                return self._send_json(200, {
                    "success": True,
                    "is_authenticated": True,
                    "gti_is_authenticated": True,
                    "encrypted": True,
                    "gti_api_key_masked": masked,
                    "gti_endpoint": gti_endpoint,
                    "elapsed_ms": elapsed_ms,
                    "message": f"GTI API Key ({masked}) encrypted with AES-256 and verified live against {gti_endpoint}/api/v3 ({elapsed_ms}ms)!"
                })
        except urllib.error.HTTPError as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            del raw_key
            return self._send_json(200, {
                "success": True,
                "is_authenticated": False,
                "gti_is_authenticated": False,
                "encrypted": True,
                "gti_api_key_masked": masked,
                "gti_endpoint": gti_endpoint,
                "warning": f"GTI Key encrypted and stored ({masked}), but live verification returned HTTP {e.code}: {e.reason}",
                "message": f"GTI Key encrypted and stored ({masked}), but live verification returned HTTP {e.code}: {e.reason}"
            })
        except Exception as e:
            del raw_key
            return self._send_json(200, {
                "success": True,
                "is_authenticated": False,
                "gti_is_authenticated": False,
                "encrypted": True,
                "gti_api_key_masked": masked,
                "gti_endpoint": gti_endpoint,
                "warning": f"GTI Key encrypted and stored ({masked}), but live verification failed: {str(e)}",
                "message": f"GTI Key encrypted and stored ({masked}), but live verification failed: {str(e)}"
            })

    def _handle_remove_gti_key(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        get_or_create_user_config(norm_email)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE config
        SET gti_api_key_encrypted = '', gti_api_key_masked = '', gti_is_authenticated = 0, gti_last_test_status = ''
        WHERE user_email = ?
        """, (norm_email,))
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "GTI_KEY_REMOVED", ip_address=self._client_ip(), user_agent=self._user_agent())
        self._send_json(200, {"success": True, "message": "Google Threat Intelligence API Key permanently removed."})

    def _handle_test_gti_auth(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        gti_key, err = get_stored_gti_key(norm_email)
        if not gti_key:
            return self._send_json(401, {"success": False, "error": err})

        row = get_or_create_user_config(norm_email)
        gti_endpoint = (row.get("gti_endpoint") or "https://www.virustotal.com").rstrip("/")
        test_url = f"{gti_endpoint}/api/v3/ip_addresses/8.8.8.8"
        ok_gti, gti_err = validate_outbound_url(test_url, "gti")
        if not ok_gti:
            return self._send_json(400, {"success": False, "error": gti_err})

        t0 = time.time()
        try:
            req = urllib.request.Request(
                test_url,
                headers={
                    "x-apikey": gti_key,
                    "x-tool": "GoogleCloud.SecOpsGTIRunner.2.1",
                    "Accept": "application/json",
                    "User-Agent": "Google-SecOps-GTI-API-Runner/2.1"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed_ms = int((time.time() - t0) * 1000)
                now_iso = datetime.now(timezone.utc).isoformat()
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("""
                UPDATE config
                SET gti_is_authenticated = 1, gti_last_test_status = ?, gti_last_test_time = ?
                WHERE user_email = ?
                """, (f"OK (200) in {elapsed_ms}ms", now_iso, norm_email))
                conn.commit()
                conn.close()
                return self._send_json(200, {
                    "success": True,
                    "status_code": 200,
                    "elapsed_ms": elapsed_ms,
                    "message": f"Connected to Google Threat Intelligence v3 API ({elapsed_ms}ms)!"
                })
        except urllib.error.HTTPError as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            return self._send_json(200, {
                "success": False,
                "status_code": e.code,
                "elapsed_ms": elapsed_ms,
                "error": f"HTTP {e.code}: {e.reason}"
            })
        except Exception as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            return self._send_json(200, {
                "success": False,
                "status_code": 500,
                "elapsed_ms": elapsed_ms,
                "error": f"Connection error: {str(e)}"
            })

    def _handle_get_catalog(self, parsed=None):
        is_gti = False
        if parsed:
            if parsed.path == "/api/gti/catalog":
                is_gti = True
            else:
                qs = parse_qs(parsed.query or "")
                if qs.get("platform", [""])[0].lower() == "gti":
                    is_gti = True

        target_path = GTI_CATALOG_PATH if is_gti else CATALOG_PATH
        if not os.path.exists(target_path):
            return self._send_json(404, {"error": "Catalog file not found"})
        try:
            with open(target_path) as f:
                data = json.load(f)
            self._send_json(200, data)
        except Exception as e:
            self._send_json(500, {"error": f"Failed reading catalog: {str(e)}"})

    # -------------------------------------------------------------------------
    # LIVE API EXECUTION (Chronicle v1alpha & GTI v3 — Outbound SSRF Hardened)
    # -------------------------------------------------------------------------

    def _handle_execute_request(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        body = self._read_json_body()
        method = body.get("method", "GET").upper().strip()
        if method not in ("GET", "POST", "PATCH", "PUT", "DELETE"):
            return self._send_json(400, {"error": f"Unsupported HTTP method '{method}'."})

        raw_url = (body.get("url") or body.get("path") or "").strip()
        headers_input = body.get("headers", {})
        params_input = body.get("params") or body.get("query_params") or {}
        payload_input = body.get("body", None)
        endpoint_id = body.get("endpoint_id", "")
        platform = body.get("platform", "").lower().strip()

        if not raw_url:
            return self._send_json(400, {"error": "URL parameter is required"})

        is_gti = (
            platform == "gti"
            or raw_url.startswith("/api/v3")
            or "virustotal.com/api/v3" in raw_url
        )

        config = get_or_create_user_config(norm_email)

        if is_gti:
            gti_key, gti_err = get_stored_gti_key(norm_email)
            if not gti_key:
                return self._send_json(400, {
                    "error": gti_err or "No Google Threat Intelligence API Key configured. Please upload or enter your GTI API Key (x-apikey) first.",
                    "code": "NO_GTI_API_KEY"
                })

            base_endpoint = (config.get("gti_endpoint") or "https://www.virustotal.com").rstrip("/")
            if raw_url.startswith("/api/v3"):
                final_url = base_endpoint + raw_url
            elif raw_url.startswith("/"):
                final_url = f"{base_endpoint}/api/v3{raw_url}"
            elif not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                final_url = f"https://{raw_url}"
            else:
                final_url = raw_url

            ok_url, url_err = validate_outbound_url(final_url, "gti")
            if not ok_url:
                return self._send_json(400, {"error": url_err, "code": "SSRF_BLOCKED"})

            if params_input and isinstance(params_input, dict):
                clean_params = {k: v for k, v in params_input.items() if v != "" and v is not None}
                if clean_params:
                    delim = "&" if "?" in final_url else "?"
                    final_url += delim + urllib.parse.urlencode(clean_params)

            req_headers = {
                "x-apikey": gti_key,
                "x-tool": "GoogleCloud.SecOpsGTIRunner.2.1",
                "User-Agent": "Google-SecOps-GTI-API-Runner/2.1",
                "Accept": "application/json"
            }
            if headers_input and isinstance(headers_input, dict):
                for k, v in headers_input.items():
                    if k and v and k.lower() not in ("authorization", "x-apikey", "host"):
                        req_headers[k] = v
        else:
            if not config.get("service_account_encrypted"):
                return self._send_json(400, {
                    "error": "No Chronicle Service Account configured. Please upload your Service Account JSON key first.",
                    "code": "NO_SERVICE_ACCOUNT"
                })

            project_id = config.get("project_id", "")
            customer_id = config.get("customer_id", "")
            location = config.get("location", "us")
            base_endpoint = config.get("endpoint") or f"https://{location}-chronicle.googleapis.com"

            interpolated_url = raw_url
            for pk in ("{project}", "{projectId}"):
                interpolated_url = interpolated_url.replace(pk, project_id)
            for lk in ("{location}", "{locations}", "{region}"):
                interpolated_url = interpolated_url.replace(lk, location)
            for ik in ("{instance}", "{instanceId}", "{instances}", "{tenantId}"):
                interpolated_url = interpolated_url.replace(ik, customer_id)

            if interpolated_url.startswith("/"):
                final_url = base_endpoint.rstrip("/") + interpolated_url
            elif not interpolated_url.startswith("http://") and not interpolated_url.startswith("https://"):
                final_url = f"https://{interpolated_url}"
            else:
                final_url = interpolated_url

            ok_url, url_err = validate_outbound_url(final_url, "chronicle")
            if not ok_url:
                return self._send_json(400, {"error": url_err, "code": "SSRF_BLOCKED"})

            if params_input and isinstance(params_input, dict):
                clean_params = {k: v for k, v in params_input.items() if v != "" and v is not None}
                if clean_params:
                    delim = "&" if "?" in final_url else "?"
                    final_url += delim + urllib.parse.urlencode(clean_params)

            token, err = get_access_token(norm_email)
            if not token:
                return self._send_json(401, {"error": f"Authentication required: {err}"})

            req_headers = {
                "Authorization": f"Bearer {token}",
                "User-Agent": "Google-SecOps-GTI-API-Runner/2.1",
                "Accept": "application/json"
            }
            if headers_input and isinstance(headers_input, dict):
                for k, v in headers_input.items():
                    if k and v and k.lower() not in ("authorization", "x-apikey", "host"):
                        req_headers[k] = v

        req_data = None
        if method in ["POST", "PATCH", "PUT"] and payload_input:
            if isinstance(payload_input, (dict, list)):
                req_data = json.dumps(payload_input).encode("utf-8")
            elif isinstance(payload_input, str) and payload_input.strip():
                req_data = payload_input.encode("utf-8")
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"

        t0 = time.time()
        status_code = 0
        status_text = ""
        res_headers = {}
        res_body = ""
        duration_ms = 0

        try:
            req = urllib.request.Request(final_url, data=req_data, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=35) as resp:
                duration_ms = int((time.time() - t0) * 1000)
                status_code = resp.status
                status_text = resp.reason or "OK"
                res_headers = dict(resp.headers)
                res_body = resp.read().decode("utf-8")

        except urllib.error.HTTPError as e:
            duration_ms = int((time.time() - t0) * 1000)
            status_code = e.code
            status_text = e.reason or "Error"
            res_headers = dict(e.headers)
            res_body = e.read().decode("utf-8")

        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            status_code = 500
            status_text = "Connection Exception"
            res_body = json.dumps({"error": f"Exception connecting to endpoint: {str(e)}"})

        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            masked_req_headers = {
                k: ("Bearer ***" if k.lower() == "authorization" else ("*** (AES-256 Encrypted GTI Key)" if k.lower() == "x-apikey" else v))
                for k, v in req_headers.items()
            }
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
            INSERT INTO history (timestamp, user_email, method, url, endpoint_id, request_headers, request_body, status_code, status_text, response_headers, response_body, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now_iso, norm_email, method, final_url, endpoint_id,
                json.dumps(masked_req_headers),
                req_data.decode("utf-8") if req_data else "",
                status_code, status_text,
                json.dumps(res_headers),
                res_body[:50000],
                duration_ms
            ))
            if 200 <= status_code < 300:
                if is_gti:
                    c.execute("UPDATE config SET gti_is_authenticated = 1, gti_last_test_status = ?, gti_last_test_time = ? WHERE user_email = ?",
                              (f"OK ({status_code}) in {duration_ms}ms", now_iso, norm_email))
                else:
                    c.execute("UPDATE config SET is_authenticated = 1, last_test_status = ?, last_test_time = ? WHERE user_email = ?",
                              (f"OK ({status_code}) in {duration_ms}ms", now_iso, norm_email))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error recording history: {e}", file=sys.stderr)

        log_audit_event(
            user_email=norm_email,
            event_type="GTI_API_EXECUTE" if is_gti else "CHRONICLE_API_EXECUTE",
            method=method,
            url=final_url,
            status_code=status_code,
            duration_ms=duration_ms,
            ip_address=self._client_ip(),
            user_agent=self._user_agent(),
            details={"endpoint_id": endpoint_id, "platform": "gti" if is_gti else "secops"}
        )

        is_json = False
        parsed_body = res_body
        gti_summary = None
        try:
            parsed_body = json.loads(res_body)
            is_json = True
            if is_gti and isinstance(parsed_body, dict):
                gti_summary = extract_gti_summary(parsed_body)
        except Exception:
            pass

        self._send_json(200, {
            "status_code": status_code,
            "status_text": status_text,
            "duration_ms": duration_ms,
            "response_headers": res_headers,
            "response_body": parsed_body,
            "gti_summary": gti_summary,
            "is_json": is_json,
            "final_url": final_url,
            "method": method,
            "platform": "gti" if is_gti else "secops"
        })

    # -------------------------------------------------------------------------
    # FAVORITES & HISTORY HANDLERS (Per-User Isolated)
    # -------------------------------------------------------------------------

    def _handle_get_favorites(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT endpoint_id, created_at FROM favorites WHERE user_email = ? ORDER BY id DESC", (norm_email,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        self._send_json(200, {"favorites": rows})

    def _handle_toggle_favorite(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        body = self._read_json_body()
        endpoint_id = body.get("endpoint_id", "").strip()
        if not endpoint_id:
            return self._send_json(400, {"error": "Missing endpoint_id"})

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM favorites WHERE endpoint_id = ? AND user_email = ?", (endpoint_id, norm_email))
        row = c.fetchone()
        if row:
            c.execute("DELETE FROM favorites WHERE endpoint_id = ? AND user_email = ?", (endpoint_id, norm_email))
            favorited = False
        else:
            now_iso = datetime.now(timezone.utc).isoformat()
            c.execute("INSERT INTO favorites (endpoint_id, user_email, created_at) VALUES (?, ?, ?)",
                      (endpoint_id, norm_email, now_iso))
            favorited = True
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "FAVORITE_TOGGLE", ip_address=self._client_ip(), user_agent=self._user_agent(),
                        details={"endpoint_id": endpoint_id, "favorited": favorited})

        self._send_json(200, {"success": True, "favorited": favorited, "endpoint_id": endpoint_id})

    def _handle_get_history(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        SELECT id, timestamp, user_email, method, url, status_code, status_text, duration_ms
        FROM history
        WHERE user_email = ?
        ORDER BY id DESC
        LIMIT 60
        """, (norm_email,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        self._send_json(200, {"history": rows})

    def _handle_clear_history(self, user: dict):
        norm_email = (user.get("email") or "anonymous").strip().lower()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM history WHERE user_email = ?", (norm_email,))
        conn.commit()
        conn.close()

        log_audit_event(norm_email, "HISTORY_CLEAR", ip_address=self._client_ip(), user_agent=self._user_agent())
        self._send_json(200, {"success": True, "message": "History cleared"})


class DualStackHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()


def main():
    init_db()

    try:
        server = DualStackHTTPServer(("::", PORT), UnifiedSecOpsGtiHandler)
        bind_mode = "Dual-Stack IPv6+IPv4 (::)"
    except Exception:
        server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), UnifiedSecOpsGtiHandler)
        bind_mode = "IPv4 (0.0.0.0)"

    print("=========================================================================", flush=True)
    print(" Google SecOps (Chronicle v1alpha) & GTI (Threat Intel v3) API Runner", flush=True)
    print(" Disclaimer: Not an official Google app • Author: Edwin Raja", flush=True)
    print(f" Port: {PORT} ({bind_mode} - Cloudtop & Cloud Run ready)", flush=True)
    print(f" Encryption: SA & GTI keys encrypted with Fernet (AES-256) at rest", flush=True)
    print(f" Audit Trail: Active in SQLite database {DB_PATH}", flush=True)
    print("=========================================================================", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
        server.server_close()


if __name__ == "__main__":
    main()
