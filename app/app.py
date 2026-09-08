from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import subprocess


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DB_PATH = BASE_DIR / "cert_auth.db"
HOST = "127.0.0.1"
PORT = 8081

OPENSSL = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
NGINX = PROJECT_DIR / "tools" / "nginx-1.30.1" / "nginx.exe"
INTERMEDIATE_CA_CONFIG = PROJECT_DIR / "pki" / "intermediate-ca-db" / "intermediate-ca.cnf"
ROOT_CRL = PROJECT_DIR / "pki" / "crl" / "root.crl"
INTERMEDIATE_CRL = PROJECT_DIR / "pki" / "crl" / "intermediate.crl"
CHAIN_CRL = PROJECT_DIR / "pki" / "crl" / "ca-chain.crl"
CA_CHAIN = PROJECT_DIR / "pki" / "certs" / "ca-chain.crt"


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def today():
    return dt.date.today().isoformat()


def run_cmd(args):
    completed = subprocess.run(
        [str(a) for a in args],
        cwd=PROJECT_DIR,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def parse_cn(subject_dn):
    match = re.search(r"(?:^|,)CN=([^,]+)", subject_dn or "")
    if not match:
        return None
    return match.group(1).strip()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query_one(sql, params=()):
    with db() as conn:
        return conn.execute(sql, params).fetchone()


def query_all(sql, params=()):
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def execute(sql, params=()):
    with db() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 120000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password, stored):
    try:
        scheme, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 120000).hex()
    return hmac.compare_digest(candidate, digest)


def ensure_column(conn, table, column, definition):
    columns = [row["name"] for row in conn.execute(f"pragma table_info({table})")]
    if column not in columns:
        conn.execute(f"alter table {table} add column {column} {definition}")


def create_session(email):
    token = secrets.token_urlsafe(32)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8)).replace(microsecond=0).isoformat()
    execute(
        "insert into sessions (token, email, expires_at, created_at) values (?, ?, ?, ?)",
        (token, email, expires, now_iso()),
    )
    return token


def get_session_user(token):
    if not token:
        return None
    return query_one(
        """
        select e.* from sessions s
        join employees e on e.email = s.email
        where s.token = ? and s.expires_at > ?
        """,
        (token, now_iso()),
    )


def delete_session(token):
    if token:
        execute("delete from sessions where token = ?", (token,))


def audit(actor, action, target, details=""):
    execute(
        """
        insert into audit_log (actor, action, target, details, created_at)
        values (?, ?, ?, ?, ?)
        """,
        (actor, action, target, details, now_iso()),
    )


def notify_user(email, subject, body):
    execute(
        """
        insert into notifications (email, subject, body, created_at, read_at)
        values (?, ?, ?, ?, null)
        """,
        (email, subject, body, now_iso()),
    )


def init_db():
    with db() as conn:
        conn.executescript(
            """
            create table if not exists users (
                id integer primary key autoincrement,
                cn text not null unique,
                username text not null,
                display_name text not null,
                role text not null
            );

            create table if not exists employees (
                id integer primary key autoincrement,
                name text not null,
                email text not null unique,
                department text not null,
                job_title text not null,
                manager_name text not null,
                manager_email text not null,
                password_hash text,
                role text not null default 'employee'
            );

            create table if not exists sessions (
                token text primary key,
                email text not null,
                expires_at text not null,
                created_at text not null
            );

            create table if not exists certificate_requests (
                id integer primary key autoincrement,
                request_id text not null unique,
                employee_email text not null,
                employee_name text not null,
                department text not null,
                purpose text not null,
                validity_days integer not null,
                algorithm text not null,
                hash_algorithm text not null,
                csr_preview text not null,
                status text not null,
                manager_decision text,
                manager_notes text,
                admin_decision text,
                admin_notes text,
                created_at text not null,
                manager_decided_at text,
                admin_decided_at text
            );

            create table if not exists certificates (
                id integer primary key autoincrement,
                request_id text,
                cn text not null unique,
                employee_name text not null,
                email text not null,
                department text not null,
                serial text,
                status text not null,
                issued_at text not null,
                expires_at text not null,
                cert_path text not null,
                key_path text not null,
                p12_path text not null,
                revocation_reason text,
                revocation_notes text,
                revoked_at text
            );

            create table if not exists audit_log (
                id integer primary key autoincrement,
                actor text not null,
                action text not null,
                target text not null,
                details text,
                created_at text not null
            );

            create table if not exists notifications (
                id integer primary key autoincrement,
                email text not null,
                subject text not null,
                body text not null,
                created_at text not null,
                read_at text
            );
            """
        )
        ensure_column(conn, "employees", "password_hash", "text")

        seed_employees = [
            ("John Smith", "john@company.com", "Engineering", "Software Engineer", "Bob Johnson", "bob@company.com", "employee"),
            ("Sarah Lee", "sarah@company.com", "Engineering", "Security Engineer", "Bob Johnson", "bob@company.com", "employee"),
            ("Alice Brown", "alice@company.com", "Finance", "Analyst", "Bob Johnson", "bob@company.com", "employee"),
            ("Bob Johnson", "bob@company.com", "Management", "Engineering Manager", "Charlie Admin", "charlie@company.com", "manager"),
            ("Charlie Admin", "charlie@company.com", "IT", "PKI Administrator", "Charlie Admin", "charlie@company.com", "admin"),
        ]
        conn.executemany(
            """
            insert into employees (name, email, department, job_title, manager_name, manager_email, role)
            values (?, ?, ?, ?, ?, ?, ?)
            on conflict(email) do update set
                name = excluded.name,
                department = excluded.department,
                job_title = excluded.job_title,
                manager_name = excluded.manager_name,
                manager_email = excluded.manager_email,
                role = excluded.role
            """,
            seed_employees,
        )
        default_hash = password_hash("password123")
        conn.execute("update employees set password_hash = ? where password_hash is null", (default_hash,))

        seed_users = [
            ("phase1-client", "phase1_client", "Phase 1 Client", "student"),
            ("alice-client", "alice_client", "Alice Client", "student"),
        ]
        conn.executemany(
            """
            insert into users (cn, username, display_name, role)
            values (?, ?, ?, ?)
            on conflict(cn) do update set
                username = excluded.username,
                display_name = excluded.display_name,
                role = excluded.role
            """,
            seed_users,
        )

    seed_existing_certificates()


def get_cert_dates(cert_path):
    output = run_cmd([OPENSSL, "x509", "-in", cert_path, "-noout", "-serial", "-dates"])
    serial = ""
    not_after = ""
    for line in output.splitlines():
        if line.startswith("serial="):
            serial = line.split("=", 1)[1].strip()
        if line.startswith("notAfter="):
            raw = line.split("=", 1)[1].strip()
            parsed = dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
            not_after = parsed.date().isoformat()
    return serial, not_after


def seed_existing_certificates():
    existing = [
        ("phase1-client", "Phase 1 Client", "john@company.com", "Engineering", "ACTIVE", "pki/certs/client.crt", "pki/private/client.key", "client.p12"),
        ("alice-client", "Alice Client", "alice@company.com", "Finance", "ACTIVE", "pki/certs/alice-client.crt", "pki/private/alice-client.key", "alice-client.p12"),
        ("expired-client", "Expired Demo Client", "expired@company.com", "IT", "EXPIRED", "pki/certs/expired-client.crt", "pki/private/expired-client.key", "expired-client.p12"),
        ("revoked-client", "Revoked Demo Client", "revoked@company.com", "IT", "REVOKED", "pki/certs/revoked-client.crt", "pki/private/revoked-client.key", "revoked-client.p12"),
    ]
    with db() as conn:
        for cn, name, email, dept, status, cert_rel, key_rel, p12_rel in existing:
            cert_path = PROJECT_DIR / cert_rel
            if not cert_path.exists():
                continue
            serial, expires = get_cert_dates(cert_path)
            issued = "2026-05-22"
            revoked_at = now_iso() if status == "REVOKED" else None
            reason = "Key Compromise" if status == "REVOKED" else None
            conn.execute(
                """
                insert into certificates
                    (request_id, cn, employee_name, email, department, serial, status,
                     issued_at, expires_at, cert_path, key_path, p12_path,
                     revocation_reason, revocation_notes, revoked_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(cn) do update set
                    employee_name = excluded.employee_name,
                    email = excluded.email,
                    department = excluded.department,
                    serial = excluded.serial,
                    status = excluded.status,
                    expires_at = excluded.expires_at,
                    cert_path = excluded.cert_path,
                    key_path = excluded.key_path,
                    p12_path = excluded.p12_path,
                    revocation_reason = excluded.revocation_reason,
                    revoked_at = excluded.revoked_at
                """,
                (
                    None,
                    cn,
                    name,
                    email,
                    dept,
                    serial,
                    status,
                    issued,
                    expires,
                    cert_rel,
                    key_rel,
                    p12_rel,
                    reason,
                    "Seeded demo certificate" if status == "REVOKED" else None,
                    revoked_at,
                ),
            )


def find_user(cn):
    return query_one(
        "select id, cn, username, display_name, role from users where cn = ?",
        (cn,),
    )


def page(title, content, active="", current_user=None):
    nav = [("/app", "mTLS Login")]
    if current_user:
        if current_user["role"] == "employee":
            nav.append(("/app/portal", "Employee Portal"))
        if current_user["role"] in ("manager", "admin"):
            nav.append(("/app/manager", "Manager"))
        if current_user["role"] == "admin":
            nav.extend([
                ("/app/admin", "Admin Dashboard"),
                ("/app/admin/certificates", "Revocations"),
                ("/app/admin/users", "Manage Users"),
            ])
    else:
        nav.append(("/login", "Login"))

    nav_icons = {
        "mTLS Login": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.105-2.59-.308-3.837A11.986 11.986 0 0012 2.7M15 7.5a3 3 0 11-6 0 3 3 0 016 0z"/></svg>""",
        "Employee Portal": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"/></svg>""",
        "Manager": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>""",
        "Admin Dashboard": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-2.25v2.25m3-2.25v2.25m3-2.25v2.25A2.25 2.25 0 0113.5 19.5h-9a2.25 2.25 0 01-2.25-2.25v-9A2.25 2.25 0 014.5 6h9a2.25 2.25 0 012.25 2.25v1.5M16.5 10.5h3m-3 3h3M16.5 7.5h3v-3a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 003.75 4.5v3m12 3V9m-12 3v-1.5"/></svg>""",
        "Revocations": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>""",
        "Manage Users": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.109A2.25 2.25 0 0112.75 21.5h-1.5a2.25 2.25 0 01-2.25-2.263V19.13c0-1.113-.285-2.16-.786-3.07M15 7.5a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zM4.125 15.631a4.125 4.125 0 017.533-2.493M12 15.75a7.488 7.488 0 00-6 3v1.5h12v-1.5a7.488 7.488 0 00-6-3z"/></svg>""",
        "Login": """<svg class="icon" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"/></svg>"""
    }

    nav_html = "".join(
        f'<a class="{ "active" if label == active else "" }" href="{href}">{nav_icons.get(label, "")}<span>{label}</span></a>'
        for href, label in nav
    )
    account_html = ""
    if current_user:
        account_html = f"""
        <form class="account" method="post" action="/logout">
          <div class="account-info">
            <span>{html.escape(current_user['name'])}</span>
            <small>{html.escape(current_user['role'])}</small>
          </div>
          <button type="submit" style="margin-right: 6px;">Logout</button>
          <button id="theme-toggle" class="secondary" style="height: 32px; width: 32px; padding: 0; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px;" onclick="toggleTheme()" type="button">
            <svg id="theme-sun" style="width:16px;height:16px;display:none;color:#fbbf24;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 9H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707.707M12 5a7 7 0 100 14 7 7 0 000-14z"/></svg>
            <svg id="theme-moon" style="width:16px;height:16px;display:none;color:#475569;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
          </button>
        </form>
        """
    else:
        account_html = """
        <div class="account">
          <button id="theme-toggle" class="secondary" style="height: 32px; width: 32px; padding: 0; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px;" onclick="toggleTheme()" type="button">
            <svg id="theme-sun" style="width:16px;height:16px;display:none;color:#fbbf24;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 9H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707.707M12 5a7 7 0 100 14 7 7 0 000-14z"/></svg>
            <svg id="theme-moon" style="width:16px;height:16px;display:none;color:#475569;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
          </button>
        </div>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script>
    // Apply theme immediately to prevent flashing
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
  </script>
  <style>
    :root {{
      --bg: #f8fafc;
      --panel: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;
      --primary: #4f46e5;
      --primary-hover: #4338ca;
      --primary-soft: #e0e7ff;
      --success: #10b981;
      --success-soft: #ecfdf5;
      --warning: #f59e0b;
      --warning-soft: #fef3c7;
      --danger: #ef4444;
      --danger-soft: #fef2f2;
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
      --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
      --shadow-md: 0 10px 15px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
      --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.06), 0 8px 10px -6px rgba(0, 0, 0, 0.06);
    }}
    :root[data-theme="dark"] {{
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #818cf8;
      --primary-hover: #6366f1;
      --primary-soft: #1e1b4b;
      --success: #34d399;
      --success-soft: #064e3b;
      --warning: #fbbf24;
      --warning-soft: #78350f;
      --danger: #f87171;
      --danger-soft: #7f1d1d;
      --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.5);
      --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.3);
      --shadow-md: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.4);
      --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family: "Inter", "Segoe UI", Arial, sans-serif; font-size:15px; -webkit-font-smoothing: antialiased; transition: background 0.3s ease, color 0.3s ease; }}
    header {{ background: #0f172a; color: #fff; padding: 24px 32px; border-bottom: 1px solid #1e293b; }}
    .header-container {{ max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; }}
    .logo-area {{ display: flex; align-items: center; gap: 16px; }}
    .header-logo {{ width: 40px; height: 40px; color: #38bdf8; filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.4)); }}
    header h1 {{ margin: 0 0 4px; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }}
    header p {{ margin: 0; color: #94a3b8; font-size: 13px; font-weight: 400; }}
    nav {{ position: sticky; top: 0; z-index: 100; display: flex; gap: 6px; padding: 12px 32px; background: rgba(255, 255, 255, 0.85); border-bottom: 1px solid var(--border); backdrop-filter: blur(12px); box-shadow: var(--shadow-sm); flex-wrap:wrap; align-items:center; transition: background 0.3s ease, border-color 0.3s ease; }}
    :root[data-theme="dark"] nav {{ background: rgba(30, 41, 59, 0.85); }}
    nav a {{ display: inline-flex; align-items: center; gap: 8px; color: var(--text-muted); text-decoration: none; padding: 8px 16px; border-radius: 8px; font-weight: 500; font-size: 14px; transition: all 0.2s ease; }}
    nav a:hover {{ background: var(--border); color: var(--text); }}
    nav a.active {{ background: var(--primary-soft); color: var(--primary); font-weight: 600; }}
    nav a .icon {{ width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 2; }}
    .account {{ margin-left: auto; display: flex; align-items: center; gap: 12px; }}
    .account-info {{ display: flex; flex-direction: column; text-align: right; }}
    .account-info span {{ font-weight: 600; font-size: 14px; color: var(--text); }}
    .account-info small {{ color: var(--text-muted); font-size: 11px; font-weight: 500; }}
    .account button {{ height: 32px; padding: 0 12px; font-size: 13px; font-weight: 600; border-radius: 6px; border: 1px solid var(--border); background: var(--panel); color: var(--text-muted); cursor: pointer; transition: all 0.2s ease; }}
    .account button:hover {{ background: var(--border); color: var(--text); }}
    #theme-toggle {{ background: var(--panel); border: 1px solid var(--border); transition: all 0.2s ease; cursor: pointer; }}
    #theme-toggle:hover {{ background: var(--border); }}
    :root[data-theme="dark"] #theme-sun {{ color: #fbbf24; }}
    :root[data-theme="dark"] #theme-moon {{ color: #94a3b8; }}
    main {{ max-width:1200px; margin:26px auto; padding:0 22px 44px; }}
    section, .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: var(--shadow); transition: background 0.3s ease, border-color 0.3s ease; }}
    h2 {{ margin:0 0 20px; font-size: 20px; font-weight: 700; color: var(--text); letter-spacing: -0.02em; }}
    h3 {{ margin: 0 0 12px; font-size: 15px; font-weight: 600; color: var(--text-secondary); }}
    p {{ line-height:1.6; color: var(--text-secondary); }}
    .grid {{ display:grid; gap:20px; }}
    .grid.two {{ grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }}
    .grid.three {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
    .card {{ border: 1px solid var(--border); border-radius: 10px; padding: 20px; background: var(--panel); box-shadow: var(--shadow-sm); transition: all 0.2s ease; display: flex; flex-direction: column; gap: 8px; }}
    .card:hover {{ border-color: var(--primary); box-shadow: var(--shadow); transform: translateY(-1px); }}
    .metric {{ min-height: 100px; display: flex; flex-direction: column; justify-content: space-between; position: relative; overflow: hidden; }}
    .metric span {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
    .metric strong {{ display: block; font-size: 32px; font-weight: 800; margin-top: 4px; color: var(--primary); }}
    .muted {{ color:var(--text-muted); }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; background: var(--panel); margin-bottom: 16px; box-shadow: var(--shadow-sm); transition: background 0.3s ease, border-color 0.3s ease; }}
    th, td {{ text-align: left; padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
    tr:last-child td {{ border-bottom:0; }}
    tbody tr:hover {{ background: var(--bg); }}
    th {{ color: var(--text-secondary); font-size: 11px; background: var(--bg); text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); transition: background 0.3s ease; }}
    label {{ display: block; font-weight: 600; margin: 16px 0 6px; color: var(--text-secondary); font-size: 13px; }}
    input, select, textarea {{ width: 100%; padding: 10px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; font-size: 14px; background: var(--bg); color: var(--text); transition: all 0.2s ease; }}
    input:focus, select:focus, textarea:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.15); }}
    textarea {{ min-height:100px; resize:vertical; }}
    button, .button {{ display: inline-flex; align-items: center; justify-content: center; gap: 8px; height: 40px; padding: 0 16px; border: none; background: var(--primary); color: #fff; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s ease; box-shadow: var(--shadow-sm); }}
    button:hover, .button:hover {{ background: var(--primary-hover); transform: translateY(-1px); }}
    button.secondary, .button.secondary {{ background: var(--panel); color: var(--text-secondary); border: 1px solid var(--border); box-shadow: var(--shadow-sm); }}
    button.secondary:hover, .button.secondary:hover {{ background: var(--bg); color: var(--text); border-color: var(--border); transform: translateY(-1px); }}
    button.danger, .button.danger {{ background: var(--danger); }}
    button.danger:hover, .button.danger:hover {{ background: #dc2626; }}
    .status {{ display: inline-flex; align-items: center; justify-content: center; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; letter-spacing: -0.01em; }}
    .status.ACTIVE, .status.SIGNED, .status.ADMIN_SIGNED, .status.ADMIN, .status.MANAGER, .status.EMPLOYEE {{ color: #065f46; background: #ecfdf5; border: 1px solid #a7f3d0; }}
    :root[data-theme="dark"] .status.ACTIVE, :root[data-theme="dark"] .status.SIGNED, :root[data-theme="dark"] .status.ADMIN_SIGNED, :root[data-theme="dark"] .status.ADMIN, :root[data-theme="dark"] .status.MANAGER, :root[data-theme="dark"] .status.EMPLOYEE {{ color: #a7f3d0; background: #064e3b; border-color: #047857; }}
    .status.REVOKED, .status.REJECTED {{ color: #991b1b; background: #fef2f2; border: 1px solid #fca5a5; }}
    :root[data-theme="dark"] .status.REVOKED, :root[data-theme="dark"] .status.REJECTED {{ color: #fca5a5; background: #7f1d1d; border-color: #b91c1c; }}
    .status.PENDING_MANAGER, .status.MANAGER_APPROVED {{ color: #92400e; background: #fef3c7; border: 1px solid #fde68a; }}
    :root[data-theme="dark"] .status.PENDING_MANAGER, :root[data-theme="dark"] .status.MANAGER_APPROVED {{ color: #fde68a; background: #78350f; border-color: #b45309; }}
    .notice {{ border: 1px solid var(--primary-soft); border-left: 4px solid var(--primary); padding: 16px; background: var(--bg); margin: 16px 0; border-radius: 8px; font-size: 14px; color: var(--text-secondary); display: flex; align-items: flex-start; gap: 10px; }}
    .notice strong {{ color: var(--text); }}
    .notice.danger-zone {{ border-color: var(--danger-soft); border-left-color: var(--danger); background: var(--danger-soft); color: var(--danger); }}
    :root[data-theme="dark"] .notice.danger-zone {{ background: rgba(127, 29, 29, 0.15); }}
    .notice.danger-zone strong {{ color: var(--danger); }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: var(--bg); padding: 2px 6px; border-radius: 6px; font-size: 13px; color: var(--text); transition: background 0.3s ease; }}
    pre {{ padding:16px; overflow:auto; border: 1px solid var(--border); border-radius:8px; line-height:1.5; }}
    .actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
    form.card {{ margin-bottom:0; }}
    ul {{ padding-left: 20px; margin: 0; }}
    li {{ margin-bottom: 8px; color: var(--text-secondary); line-height: 1.5; }}
    .icon {{ width: 18px; height: 18px; fill: none; stroke: currentColor; stroke-width: 2; flex-shrink: 0; }}
    @media (max-width: 760px) {{
      header, nav {{ padding-left: 16px; padding-right: 16px; }}
      .account {{ width: 100%; margin-left: 0; margin-top: 10px; justify-content: space-between; }}
      th:nth-child(3), td:nth-child(3) {{ display: none; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-container">
      <div class="logo-area">
        <svg class="header-logo" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.105-2.59-.308-3.837A11.986 11.986 0 0012 2.7M15 7.5a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
        <div>
          <h1>PKI Certificate Portal</h1>
          <p>OpenSSL CA, Nginx mTLS, certificate workflow, revocation, and audit compliance</p>
        </div>
      </div>
    </div>
  </header>
  <nav>{nav_html}{account_html}</nav>
  <main>{content}</main>
  <script>
    function toggleTheme() {{
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      updateThemeIcons(newTheme);
    }}

    function updateThemeIcons(theme) {{
      const sun = document.getElementById('theme-sun');
      const moon = document.getElementById('theme-moon');
      if (!sun || !moon) return;
      if (theme === 'dark') {{
        sun.style.display = 'block';
        moon.style.display = 'none';
      }} else {{
        sun.style.display = 'none';
        moon.style.display = 'block';
      }}
    }}

    // Initial icon setup
    updateThemeIcons(document.documentElement.getAttribute('data-theme') || 'light');
  </script>
</body>
</html>"""


def login_page(message=""):
    msg = f'<div class="notice danger-zone">{html.escape(message)}</div>' if message else ""
    content = f"""
    <div style="max-width: 900px; margin: 40px auto; padding: 0 16px;">
      <div class="grid two">
        <div style="display: flex; flex-direction: column; justify-content: center; padding-right: 24px;">
          <h2 style="font-size: 28px; font-weight: 800; line-height: 1.2; margin-bottom: 16px; letter-spacing: -0.03em;">Sign in to the Secure PKI Portal</h2>
          <p class="muted" style="font-size: 16px; line-height: 1.6; margin-bottom: 24px;">Authenticate with your credentials to request identity certificates, manage team approvals, sign pending requests, or process CRL revocations.</p>
          <div class="card" style="background: #fafafb; border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: var(--shadow-sm);">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px; color: var(--primary);">
              <svg style="width: 20px; height: 20px;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
              <strong style="font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Demo Credentials</strong>
            </div>
            <div style="font-size: 14px; display: grid; gap: 8px; color: var(--text-secondary);">
              <div><span style="font-weight:600; width: 80px; display: inline-block;">Employee:</span> <code>john@company.com</code></div>
              <div><span style="font-weight:600; width: 80px; display: inline-block;">Manager:</span> <code>bob@company.com</code></div>
              <div><span style="font-weight:600; width: 80px; display: inline-block;">Admin:</span> <code>charlie@company.com</code></div>
              <div style="margin-top: 4px; padding-top: 8px; border-top: 1px dashed var(--border);"><span style="font-weight:600; width: 80px; display: inline-block;">Password:</span> <code>password123</code></div>
            </div>
          </div>
        </div>
        <form method="post" action="/login" class="card" style="padding: 32px; border-radius: 16px; box-shadow: var(--shadow-md);">
          <h3 style="font-size: 20px; font-weight: 700; margin: 0 0 8px; letter-spacing: -0.02em;">Account Sign In</h3>
          <p class="muted" style="margin: 0 0 24px; font-size: 14px;">Please enter your registered enterprise email and password.</p>
          {msg}
          <label style="margin-top: 0;">Email Address</label>
          <input name="email" type="email" placeholder="charlie@company.com" required style="height: 44px; font-size: 15px;">
          <label style="margin-top: 16px;">Password</label>
          <input name="password" type="password" placeholder="••••••••" required style="height: 44px; font-size: 15px;">
          <button type="submit" style="height: 44px; width: 100%; margin-top: 24px; font-size: 15px; font-weight: 600;">Sign In</button>
        </form>
      </div>
    </div>
    """
    return page("Login", content, "Login")


def fmt_date(value):
    if not value:
        return "-"
    return value[:10]


def days_until(value):
    try:
        return (dt.date.fromisoformat(value[:10]) - dt.date.today()).days
    except ValueError:
        return 0


def status_badge(value):
    return f'<span class="status {html.escape(value)}">{html.escape(value.replace("_", " "))}</span>'


def request_id_for(row_id):
    return f"REQ-{dt.date.today().year}-{row_id:05d}"


def create_request(employee_email):
    emp = query_one("select * from employees where email = ?", (employee_email,))
    if not emp:
        raise RuntimeError("Unknown employee")
    created = now_iso()
    row_id = execute(
        """
        insert into certificate_requests
            (request_id, employee_email, employee_name, department, purpose, validity_days,
             algorithm, hash_algorithm, csr_preview, status, created_at)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "TEMP",
            emp["email"],
            emp["name"],
            emp["department"],
            "System Access",
            730,
            "RSA 2048-bit",
            "SHA-256",
            "Browser-generated CSR demo payload; private key remains local in the conceptual flow.",
            "PENDING_MANAGER",
            created,
        ),
    )
    req_id = request_id_for(row_id)
    execute("update certificate_requests set request_id = ? where id = ?", (req_id, row_id))
    audit(emp["email"], "REQUEST_CREATED", req_id, "Employee submitted certificate request")
    notify_user(emp["manager_email"], "Certificate request awaiting approval", f"{emp['name']} submitted {req_id}.")
    return req_id


def create_employee(form):
    name = form.get("name", "").strip()
    email = form.get("email", "").strip().lower()
    department = form.get("department", "").strip()
    job_title = form.get("job_title", "").strip()
    manager_name = form.get("manager_name", "").strip()
    manager_email = form.get("manager_email", "").strip().lower()
    role = form.get("role", "employee").strip() or "employee"
    password = form.get("password", "").strip() or "password123"

    if not all([name, email, department, job_title, manager_name, manager_email]):
        raise RuntimeError("All employee fields are required")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise RuntimeError("Employee email is invalid")
    if role not in ("employee", "manager", "admin"):
        raise RuntimeError("Invalid role")

    execute(
        """
        insert into employees (name, email, department, job_title, manager_name, manager_email, password_hash, role)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(email) do update set
            name = excluded.name,
            department = excluded.department,
            job_title = excluded.job_title,
            manager_name = excluded.manager_name,
            manager_email = excluded.manager_email,
            password_hash = excluded.password_hash,
            role = excluded.role
        """,
        (name, email, department, job_title, manager_name, manager_email, password_hash(password), role),
    )
    audit("charlie@company.com", "EMPLOYEE_UPSERT", email, f"Added/updated {name} as {role}")
    return email


def approve_request(req_id, actor, decision, notes=""):
    status = "MANAGER_APPROVED" if decision == "approve" else "REJECTED"
    execute(
        """
        update certificate_requests
        set status = ?, manager_decision = ?, manager_notes = ?, manager_decided_at = ?
        where request_id = ?
        """,
        (status, decision.upper(), notes, now_iso(), req_id),
    )
    req = query_one("select * from certificate_requests where request_id = ?", (req_id,))
    audit(actor, "MANAGER_DECISION", req_id, f"{decision.upper()}: {notes}")
    if status == "MANAGER_APPROVED":
        notify_user("charlie@company.com", "Certificate ready to sign", f"{req['employee_name']} request {req_id} is ready for IT signing.")
    else:
        notify_user(req["employee_email"], "Certificate request rejected", f"Manager rejected {req_id}.")


def cert_subject(cn):
    return f"/C=IN/ST=Karnataka/L=Bengaluru/O=Cert Based Auth Lab/OU=Portal/CN={cn}"


def issue_certificate(req_id):
    req = query_one("select * from certificate_requests where request_id = ?", (req_id,))
    if not req or req["status"] != "MANAGER_APPROVED":
        raise RuntimeError("Request is not ready for signing")

    cn = req["employee_email"]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", cn)
    key_rel = f"pki/private/{safe}.key"
    csr_rel = f"pki/csr/{safe}.csr"
    cert_rel = f"pki/certs/{safe}.crt"
    p12_rel = f"{safe}.p12"
    key_path = PROJECT_DIR / key_rel
    csr_path = PROJECT_DIR / csr_rel
    cert_path = PROJECT_DIR / cert_rel
    p12_path = PROJECT_DIR / p12_rel

    run_cmd([OPENSSL, "genrsa", "-out", key_path, "2048"])
    run_cmd([OPENSSL, "req", "-new", "-key", key_path, "-out", csr_path, "-subj", cert_subject(cn)])
    run_cmd([OPENSSL, "ca", "-batch", "-config", INTERMEDIATE_CA_CONFIG, "-extensions", "client_cert", "-notext", "-in", csr_path, "-out", cert_path])
    run_cmd([OPENSSL, "pkcs12", "-export", "-out", p12_path, "-inkey", key_path, "-in", cert_path, "-certfile", CA_CHAIN, "-name", cn, "-passout", "pass:portalpass"])

    serial, expires = get_cert_dates(cert_path)
    execute(
        """
        insert into certificates
            (request_id, cn, employee_name, email, department, serial, status,
             issued_at, expires_at, cert_path, key_path, p12_path)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(cn) do update set
            request_id = excluded.request_id,
            employee_name = excluded.employee_name,
            email = excluded.email,
            department = excluded.department,
            serial = excluded.serial,
            status = excluded.status,
            issued_at = excluded.issued_at,
            expires_at = excluded.expires_at,
            cert_path = excluded.cert_path,
            key_path = excluded.key_path,
            p12_path = excluded.p12_path
        """,
        (req_id, cn, req["employee_name"], req["employee_email"], req["department"], serial, "ACTIVE", today(), expires, cert_rel, key_rel, p12_rel),
    )
    execute(
        """
        insert into users (cn, username, display_name, role)
        values (?, ?, ?, ?)
        on conflict(cn) do update set display_name = excluded.display_name
        """,
        (cn, cn.replace("@", "_").replace(".", "_"), req["employee_name"], "employee"),
    )
    execute(
        """
        update certificate_requests
        set status = ?, admin_decision = ?, admin_decided_at = ?, admin_notes = ?
        where request_id = ?
        """,
        ("ADMIN_SIGNED", "SIGNED", now_iso(), "Certificate issued by IT admin", req_id),
    )
    audit("charlie@company.com", "CERTIFICATE_SIGNED", cn, f"Issued from {req_id}")
    notify_user(req["employee_email"], "Certificate issued", f"Your certificate for {cn} is ready to download. Import password: portalpass")


def regenerate_crl_and_reload():
    run_cmd([OPENSSL, "ca", "-batch", "-config", INTERMEDIATE_CA_CONFIG, "-gencrl", "-crlexts", "crl_ext", "-out", INTERMEDIATE_CRL])
    chain = INTERMEDIATE_CRL.read_text(encoding="ascii") + ROOT_CRL.read_text(encoding="ascii")
    CHAIN_CRL.write_text(chain, encoding="ascii")
    if NGINX.exists():
        run_cmd([NGINX, "-p", PROJECT_DIR, "-c", "nginx\\nginx-mtls.conf", "-s", "reload"])


def revoke_certificate(cert_id, reason, notes):
    cert = query_one("select * from certificates where id = ?", (cert_id,))
    if not cert:
        raise RuntimeError("Certificate not found")
    if cert["status"] == "REVOKED":
        raise RuntimeError("Certificate is already revoked")
    run_cmd([OPENSSL, "ca", "-batch", "-config", INTERMEDIATE_CA_CONFIG, "-revoke", PROJECT_DIR / cert["cert_path"]])
    regenerate_crl_and_reload()
    execute(
        """
        update certificates
        set status = ?, revocation_reason = ?, revocation_notes = ?, revoked_at = ?
        where id = ?
        """,
        ("REVOKED", reason, notes, now_iso(), cert_id),
    )
    audit("charlie@company.com", "CERTIFICATE_REVOKED", cert["cn"], f"{reason}: {notes}")
    notify_user(cert["email"], "Certificate revoked", f"Your certificate {cert['cn']} was revoked. Reason: {reason}.")


def render_login_result(headers):
    verify = headers.get("X-SSL-Client-Verify", "")
    subject_dn = headers.get("X-SSL-Client-DN", "")
    issuer_dn = headers.get("X-SSL-Client-Issuer-DN", "")
    cn = parse_cn(subject_dn)

    if verify != "SUCCESS":
        return 403, {"authenticated": False, "reason": "Nginx did not report a verified client certificate.", "ssl_client_verify": verify}
    if not cn:
        return 403, {"authenticated": False, "reason": "Verified certificate subject did not contain a CN.", "ssl_client_s_dn": subject_dn}
    user = find_user(cn)
    if not user:
        return 403, {"authenticated": False, "reason": "Verified certificate CN is not mapped to a user.", "cn": cn}
    cert = query_one("select * from certificates where cn = ?", (cn,))
    return 200, {
        "authenticated": True,
        "cn": cn,
        "user": dict(user),
        "certificate": dict(cert) if cert else None,
        "ssl_client_verify": verify,
        "ssl_client_s_dn": subject_dn,
        "ssl_client_i_dn": issuer_dn,
    }


def employee_portal(query=None, current_user=None):
    query = query or {}
    employee_email = query.get("email", ["john@company.com"])[0]
    emp = query_one("select * from employees where email = ?", (employee_email,))
    if not emp:
        emp = query_one("select * from employees where email = ?", ("john@company.com",))
    if current_user and current_user["role"] == "employee":
        employees = [current_user]
    else:
        employees = query_all("select name, email, department from employees order by name")
    certs = query_all("select * from certificates where email = ? order by issued_at desc", (emp["email"],))
    requests = query_all("select * from certificate_requests where employee_email = ? order by id desc limit 5", (emp["email"],))
    notes = query_all("select * from notifications where email = ? order by id desc limit 4", (emp["email"],))

    cert_html = "".join(
        f"""
        <div class="card" style="box-shadow: var(--shadow-sm); padding: 18px; border-radius: 10px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 6px;">
            <strong style="font-size: 15px; color: var(--text);">{html.escape(c['cn'])}</strong>
            {status_badge(c['status'])}
          </div>
          <p class="muted" style="margin: 0 0 16px; font-size:13px;">Issued: {fmt_date(c['issued_at'])} | Expires: {fmt_date(c['expires_at'])} ({days_until(c['expires_at'])} days left)</p>
          <div class="actions">
            <a class="button" href="/app/download?id={c['id']}" style="height:32px; font-size:12.5px; padding: 0 12px;">
              <svg style="width: 14px; height: 14px;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              Download
            </a>
            <a class="button secondary" href="/app/certificate?id={c['id']}" style="height:32px; font-size:12.5px; padding: 0 12px;">Details</a>
          </div>
        </div>
        """
        for c in certs
    ) or '<p class="muted" style="grid-column: 1/-1; text-align: center; padding: 24px; background: #fff; border: 1px dashed var(--border); border-radius: 8px;">No certificates issued yet.</p>'

    req_html = "".join(
        f"""
        <div class="card" style="box-shadow: var(--shadow-sm); padding: 18px; border-radius: 10px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 6px;">
            <strong style="font-size: 15px; color: var(--text);">{html.escape(r['request_id'])}</strong>
            {status_badge(r['status'])}
          </div>
          <p class="muted" style="margin: 0 0 16px; font-size:13px;">Submitted: {fmt_date(r['created_at'])} | Purpose: {html.escape(r['purpose'])}</p>
          <a class="button secondary" href="/app/request?id={r['id']}" style="height:32px; font-size:12.5px; padding: 0 12px; align-self: flex-start;">View Status</a>
        </div>
        """
        for r in requests
    ) or '<p class="muted" style="grid-column: 1/-1; text-align: center; padding: 24px; background: #fff; border: 1px dashed var(--border); border-radius: 8px;">No requests submitted yet.</p>'

    note_html = "".join(f"""
        <li style="background: #ffffff; border: 1px solid var(--border); border-radius: 10px; padding: 16px; box-shadow: var(--shadow-sm); display: flex; align-items: flex-start; gap: 12px;">
          <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--primary); margin-top: 6px; flex-shrink: 0;"></div>
          <div>
            <strong style="font-size: 14px; color: var(--text);">{html.escape(n['subject'])}</strong>
            <p style="margin: 4px 0 0; font-size: 13px; color: var(--text-secondary);">{html.escape(n['body'])}</p>
          </div>
        </li>
    """ for n in notes) or '<li style="background: #ffffff; border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; color: var(--text-muted); border-style: dashed;">No new notifications.</li>'

    employee_options = "".join(
        f'<option value="{html.escape(e["email"])}"{" selected" if e["email"] == emp["email"] else ""}>{html.escape(e["name"])} - {html.escape(e["email"])}</option>'
        for e in employees
    )

    content = f"""
    <section style="border: 0; background: transparent; padding: 0; box-shadow: none;">
      <div class="card" style="padding: 20px; display: flex; flex-direction: row; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 24px; background: #ffffff; border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-sm);">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div style="width: 44px; height: 44px; border-radius: 50%; background: var(--primary-soft); color: var(--primary); display: flex; align-items: center; justify-content: center;">
            <svg style="width: 22px; height: 22px; fill:none; stroke:currentColor; stroke-width:2;" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"/></svg>
          </div>
          <div>
            <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: var(--text);">{html.escape(emp['name'])}</h3>
            <p class="muted" style="margin: 2px 0 0; font-size: 13px;">{html.escape(emp['email'])} &bull; Portal Role: <strong style="text-transform: capitalize;">{html.escape(current_user['role'] if current_user else 'employee')}</strong></p>
          </div>
        </div>
        <form method="get" action="/app/portal" style="display: flex; gap: 8px; margin: 0; align-items: center;">
          <select name="email" style="min-width: 240px; height: 38px; padding: 0 12px; font-size: 13.5px; border-radius: 6px;">{employee_options}</select>
          <button type="submit" class="secondary" style="height: 38px; font-size: 13px; padding: 0 12px;">Switch User</button>
        </form>
      </div>

      <div class="grid two" style="margin-bottom: 24px;">
        <div class="card" style="padding: 24px;">
          <h3 style="border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px; font-size: 15px; display: flex; align-items: center; gap: 8px; color: var(--text);">
            <svg style="width: 18px; height: 18px; color: var(--text-muted);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 21h19.5m-18-18v18m10.5-18v18m6-13.5V21M6.75 6.75h.75m-.75 3h.75m-.75 3h.75m3-6h.75m-.75 3h.75m-.75 3h.75M6.75 21v-3.375c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21M3 3h12v18H3V3z"/></svg>
            Employee Assignment
          </h3>
          <div style="display: grid; gap: 10px; font-size: 14px; color: var(--text-secondary);">
            <div style="display: flex; justify-content: space-between;"><span class="muted">Department:</span> <strong style="color:var(--text);">{html.escape(emp['department'])}</strong></div>
            <div style="display: flex; justify-content: space-between;"><span class="muted">Job Title:</span> <strong style="color:var(--text);">{html.escape(emp['job_title'])}</strong></div>
            <div style="display: flex; justify-content: space-between;"><span class="muted">Reports To:</span> <strong style="color:var(--text);">{html.escape(emp['manager_name'])}</strong></div>
          </div>
        </div>
        <div class="card" style="padding: 24px;">
          <h3 style="border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px; font-size: 15px; display: flex; align-items: center; gap: 8px; color: var(--text);">
            <svg style="width: 18px; height: 18px; color: var(--text-muted);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>
            Security Profile Standard
          </h3>
          <div style="display: grid; gap: 10px; font-size: 14px; color: var(--text-secondary);">
            <div style="display: flex; justify-content: space-between;"><span class="muted">Key Usage Purpose:</span> <strong style="color:var(--text);">Client Authentication (mTLS)</strong></div>
            <div style="display: flex; justify-content: space-between;"><span class="muted">Cryptographic Standard:</span> <strong style="color:var(--text);">RSA 2048-bit</strong></div>
            <div style="display: flex; justify-content: space-between;"><span class="muted">Cert Validity Term:</span> <strong style="color:var(--text);">2 Years (730 Days)</strong></div>
          </div>
        </div>
      </div>

      <div class="notice" style="margin-bottom: 24px;">
        <svg style="width: 20px; height: 20px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 11.513 1.293l-.042.02v.017a.75.75 0 11-1.5 0v-.017zm0 4.5h.008v.008h-.008v-.008zM12 3v18m9-9H3"/></svg>
        <div><strong>Conceptual Flow Note</strong>: Production portals run local client-side keypair generation and CSR submission via the browser. For local development, certificates are generated securely by the server and offered as an importable PKCS#12 bundle.</div>
      </div>
      <form method="post" action="/app/portal/request" style="margin-bottom: 44px;">
        <input type="hidden" name="employee_email" value="{html.escape(emp['email'])}">
        <button type="submit" style="height: 44px; padding: 0 20px; font-weight: 600;">
          <svg style="width:16px;height:16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
          Request &amp; Generate New Certificate
        </button>
      </form>
    </section>

    <section>
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg style="width: 20px; height: 20px; color: var(--success);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>
        Your Certificates
      </h2>
      <div class="grid two" style="margin-bottom: 32px;">{cert_html}</div>
    </section>
    <section>
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg style="width: 20px; height: 20px; color: var(--warning);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        Pending Requests
      </h2>
      <div class="grid two" style="margin-bottom: 32px;">{req_html}</div>
    </section>
    <section>
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg style="width: 20px; height: 20px; color: var(--text-muted);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c.38.19.784.356 1.205.498m10.96 0A23.847 23.847 0 0112 18c-3.807 0-7.399-.887-10.603-2.476m15.938 0a24.27 24.27 0 00-.007-3.526M5.397 15.626c-.007-1.176-.007-2.35 0-3.526m0 0A23.901 23.901 0 0112 9.75c3.21 0 6.277.625 9.079 1.75m-18.158 0a24.269 24.269 0 00.007 3.526M12 18v3m0 0l-3-3m3 3l3-3"/></svg>
        Notifications
      </h2>
      <ul style="list-style: none; padding: 0; display: grid; gap: 12px;">{note_html}</ul>
    </section>
    """
    return page("Employee Portal", content, "Employee Portal", current_user)


def manager_page(current_user=None):
    if current_user and current_user["role"] == "manager":
        rows = query_all(
            "select * from certificate_requests where status = 'PENDING_MANAGER' and employee_email in (select email from employees where manager_email = ?) order by id desc",
            (current_user["email"],),
        )
    else:
        rows = query_all("select * from certificate_requests where status = 'PENDING_MANAGER' order by id desc")
    table = "".join(
        f"""
        <tr>
          <td><strong style="color:var(--text);">{html.escape(r['request_id'])}</strong></td>
          <td>
            <div style="font-weight:600; color:var(--text);">{html.escape(r['employee_name'])}</div>
            <span class="muted" style="font-size:12px;">{html.escape(r['employee_email'])}</span>
          </td>
          <td>{html.escape(r['department'])}</td>
          <td>{status_badge(r['status'])}</td>
          <td class="actions">
            <form method="post" action="/app/manager/decision" style="display:inline-block; margin:0;"><input type="hidden" name="request_id" value="{html.escape(r['request_id'])}"><input type="hidden" name="decision" value="approve"><button type="submit" style="height:32px; font-size:12.5px; padding:0 12px;">Approve</button></form>
            <form method="post" action="/app/manager/decision" style="display:inline-block; margin:0;"><input type="hidden" name="request_id" value="{html.escape(r['request_id'])}"><input type="hidden" name="decision" value="reject"><button class="secondary" type="submit" style="height:32px; font-size:12.5px; padding:0 12px;">Reject</button></form>
          </td>
        </tr>
        """
        for r in rows
    ) or '<tr><td colspan="5" class="muted" style="text-align:center; padding: 24px;">No requests waiting for manager approval.</td></tr>'
    content = f"""
    <section>
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg style="width: 22px; height: 22px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>
        Manager Approval Queue
      </h2>
      <p class="muted" style="margin-bottom: 20px;">Review and process certificate signing authorization requests from your engineering/operations team.</p>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Request ID</th>
              <th>Employee Details</th>
              <th>Department</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>{table}</tbody>
        </table>
      </div>
    </section>
    """
    return page("Manager Approval", content, "Manager", current_user)


def admin_dashboard(current_user=None):
    stats = {
        "Total Certs": query_one("select count(*) c from certificates")["c"],
        "Active Certs": query_one("select count(*) c from certificates where status = 'ACTIVE'")["c"],
        "Pending": query_one("select count(*) c from certificate_requests where status in ('PENDING_MANAGER','MANAGER_APPROVED')")["c"],
        "Revoked": query_one("select count(*) c from certificates where status = 'REVOKED'")["c"],
        "Expiring 30d": query_one("select count(*) c from certificates where status = 'ACTIVE' and date(expires_at) <= date('now', '+30 days')")["c"],
        "Sign Rate": "2.5 hrs",
    }
    stat_icons = {
        "Total Certs": """<svg style="width: 24px; height: 24px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>""",
        "Active Certs": """<svg style="width: 24px; height: 24px; color: var(--success);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>""",
        "Pending": """<svg style="width: 24px; height: 24px; color: var(--warning);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>""",
        "Revoked": """<svg style="width: 24px; height: 24px; color: var(--danger);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>""",
        "Expiring 30d": """<svg style="width: 24px; height: 24px; color: #f97316;" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>""",
        "Sign Rate": """<svg style="width: 24px; height: 24px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>"""
    }

    stat_cards = "".join(f"""
        <div class="card metric" style="padding: 20px; border-radius: 12px;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <span style="font-size: 11px; font-weight:700; color: var(--text-muted); text-transform: uppercase; letter-spacing:0.05em;">{html.escape(k)}</span>
            {stat_icons.get(k, "")}
          </div>
          <strong style="margin-top: 8px; font-size: 28px; font-weight:800; color:var(--text);">{html.escape(str(v))}</strong>
        </div>
    """ for k, v in stats.items())

    ready = query_all("select * from certificate_requests where status = 'MANAGER_APPROVED' order by id desc")
    pending = query_all("select * from certificate_requests where status = 'PENDING_MANAGER' order by id desc limit 5")
    audit_rows = query_all("select * from audit_log order by id desc limit 10")
    dept_rows = query_all("select department, count(*) c from certificates group by department order by c desc")

    ready_html = "".join(
        f'<tr><td><div style="font-weight:600;color:var(--text);">{html.escape(r["employee_email"])}</div><span class="muted" style="font-size:12px;">{html.escape(r["request_id"])} &bull; {html.escape(r["employee_name"])}</span></td><td style="text-align: right;"><form method="post" action="/app/admin/sign" style="margin:0;"><input type="hidden" name="request_id" value="{html.escape(r["request_id"])}"><button type="submit" style="height:32px;padding:0 12px;font-size:12.5px;"><svg style="width:14px;height:14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125"/></svg>Sign &amp; Issue</button></form></td></tr>'
        for r in ready
    ) or '<tr><td colspan="2" class="muted" style="text-align: center; padding: 20px;">No requests approved and waiting for signing.</td></tr>'

    pending_html = "".join(f"""
        <li style="padding: 12px 0; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between;">
          <div>
            <strong style="font-size: 14px; color: var(--text);">{html.escape(r["employee_email"])}</strong>
            <div class="muted" style="font-size: 12px;">{html.escape(r["request_id"])} &bull; {html.escape(r["employee_name"])}</div>
          </div>
          <span class="status PENDING_MANAGER" style="font-size: 11px;">Pending Manager</span>
        </li>
    """ for r in pending) or '<li class="muted" style="padding: 12px 0; text-align: center; border-bottom: 0;">No pending manager approvals.</li>'

    audit_html = "".join(f"""
        <li style="padding: 10px 0; border-bottom: 1px dashed var(--border); font-size: 13.5px; color: var(--text-secondary); line-height: 1.4;">
          <span style="font-family: monospace; font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 2px;">{html.escape(a["created_at"][:19])}</span>
          <strong>{html.escape(a["actor"])}</strong> <span style="color: var(--primary); font-weight: 600;">{html.escape(a["action"])}</span> {html.escape(a["target"])}
        </li>
    """ for a in audit_rows) or '<li class="muted" style="padding: 10px 0;">No audit events yet.</li>'

    dept_html = "".join(f"""
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: #fafafb; border: 1px solid var(--border); border-radius: 8px;">
          <strong style="font-size: 13.5px; color: var(--text-secondary);">{html.escape(d["department"])}</strong>
          <span style="background: var(--primary-soft); color: var(--primary); padding: 2px 8px; border-radius: 12px; font-weight: 700; font-size: 12px;">{d["c"]} certs</span>
        </div>
    """ for d in dept_rows) or "<p class='muted'>No department data.</p>"

    content = f"""
    <section style="border: 0; background: transparent; padding: 0; box-shadow: none; margin-bottom: 28px;">
      <h2 style="margin-bottom: 16px;">PKI Statistics</h2>
      <div class="grid three">{stat_cards}</div>
    </section>

    <div class="grid two">
      <section style="margin-bottom: 0; padding: 24px;">
        <h2 style="display: flex; align-items: center; gap: 8px; font-size: 18px;">
          <svg style="width: 20px; height: 20px; color: var(--success);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>
          Ready to Sign &amp; Issue
        </h2>
        <table style="box-shadow: none; border-radius: 8px; margin-top: 12px; margin-bottom: 0;">
          <tbody>{ready_html}</tbody>
        </table>
      </section>

      <section style="margin-bottom: 0; padding: 24px;">
        <h2 style="display: flex; align-items: center; gap: 8px; font-size: 18px;">
          <svg style="width: 20px; height: 20px; color: var(--warning);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          Pending Approvals Queue
        </h2>
        <ul style="list-style: none; padding: 0; margin-top: 12px;">{pending_html}</ul>
      </section>
    </div>

    <div class="grid two" style="margin-top: 24px;">
      <section style="margin-bottom: 0; padding: 24px;">
        <h2 style="display: flex; align-items: center; gap: 8px; font-size: 18px;">
          <svg style="width: 20px; height: 20px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6a7.5 7.5 0 107.5 7.5h-7.5V6z"/><path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5H21A7.5 7.5 0 0013.5 3v7.5z"/></svg>
          Department Analytics
        </h2>
        <div style="display: grid; gap: 12px; margin-top: 16px;">{dept_html}</div>
      </section>

      <section style="margin-bottom: 0; padding: 24px;">
        <h2 style="display: flex; align-items: center; gap: 8px; font-size: 18px;">
          <svg style="width: 20px; height: 20px; color: var(--text-muted);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          Recent Activity Timeline
        </h2>
        <ul style="list-style: none; padding: 0; margin-top: 12px; max-height: 250px; overflow-y: auto;">{audit_html}</ul>
      </section>
    </div>

    <section style="margin-top: 24px; padding: 24px;">
      <h2 style="font-size: 18px; margin-bottom: 16px;">Quick Operations</h2>
      <div class="actions">
        <a class="button" href="/app/admin/certificates">
          <svg style="width:16px;height:16px;" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.637z"/></svg>
          Manage All Certificates
        </a>
        <a class="button secondary" href="/app/admin/users">Manage Employee Accounts</a>
        <a class="button secondary" href="/app/manager">Approval Inbox</a>
        <a class="button secondary" href="/app/audit">Compliance Logs</a>
      </div>
    </section>
    """
    return page("Admin Dashboard", content, "Admin Dashboard", current_user)


def users_page(current_user=None):
    employees = query_all("select * from employees order by department, name")
    rows = "".join(
        f"""
        <tr>
          <td>
            <div style="font-weight:600; color:var(--text);">{html.escape(e['name'])}</div>
            <span class="muted" style="font-size:12px;">{html.escape(e['email'])}</span>
          </td>
          <td>{html.escape(e['department'])}</td>
          <td>{html.escape(e['job_title'])}</td>
          <td>
            <div style="font-weight:500; font-size:13.5px; color:var(--text-secondary);">{html.escape(e['manager_name'])}</div>
            <span class="muted" style="font-size:11.5px;">{html.escape(e['manager_email'])}</span>
          </td>
          <td>{status_badge(e['role'].upper())}</td>
          <td class="actions">
            <a class="button secondary" href="/app/portal?email={html.escape(e['email'])}" style="height:32px; font-size:12.5px; padding:0 10px;">Open Portal</a>
            <form method="post" action="/app/portal/request" style="display:inline-block; margin:0;">
              <input type="hidden" name="employee_email" value="{html.escape(e['email'])}">
              <button type="submit" style="height:32px; font-size:12.5px; padding:0 10px;">Request Cert</button>
            </form>
          </td>
        </tr>
        """
        for e in employees
    ) or '<tr><td colspan="6" class="muted" style="text-align:center; padding:24px;">No user profiles found in database.</td></tr>'
    content = f"""
    <section>
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 16px;">
        <h2 style="margin: 0; display: flex; align-items: center; gap: 8px;">
          <svg style="width: 22px; height: 22px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.109A2.25 2.25 0 0112.75 21.5h-1.5a2.25 2.25 0 01-2.25-2.263V19.13c0-1.113-.285-2.16-.786-3.07M15 7.5a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zM4.125 15.631a4.125 4.125 0 017.533-2.493M12 15.75a7.488 7.488 0 00-6 3v1.5h12v-1.5a7.488 7.488 0 00-6-3z"/></svg>
          Manage Users &amp; Identities
        </h2>
        <div class="actions">
          <a class="button" href="/app/admin/users/new">
            <svg style="width:16px;height:16px;" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
            Add Employee
          </a>
          <a class="button secondary" href="/app/admin">Back to Dashboard</a>
        </div>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Employee Details</th>
              <th>Department</th>
              <th>Job Title</th>
              <th>Manager Details</th>
              <th>System Role</th>
              <th>Portal Actions</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>
    """
    return page("Manage Users", content, "Admin Dashboard", current_user)


def new_user_form(current_user=None):
    managers = query_all("select name, email from employees where role in ('manager', 'admin') order by name")
    manager_options = "".join(
        f'<option value="{html.escape(m["name"])}|{html.escape(m["email"])}">{html.escape(m["name"])} - {html.escape(m["email"])}</option>'
        for m in managers
    )
    content = f"""
    <section style="max-width: 800px; margin: 0 auto; padding: 32px;">
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg style="width: 22px; height: 22px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zM4 19.235v-.11a6.375 6.375 0 0112.75 0v.109A12.318 12.318 0 0110.374 21c-2.331 0-4.512-.645-6.374-1.766z"/></svg>
        Add Employee Account
      </h2>
      <p class="muted" style="margin-bottom: 24px;">Register a new user profile. By default, it creates standard user credentials.</p>
      <form method="post" action="/app/admin/users/new">
        <div class="grid two">
          <div><label style="margin-top:0;">Full Name</label><input name="name" placeholder="Rahul Kumar" required style="height:42px;"></div>
          <div><label style="margin-top:0;">Email Address</label><input name="email" type="email" placeholder="rahul@company.com" required style="height:42px;"></div>
          <div><label style="margin-top:0;">Department</label><input name="department" placeholder="Engineering" required style="height:42px;"></div>
          <div><label style="margin-top:0;">Job Title</label><input name="job_title" placeholder="Software Engineer" required style="height:42px;"></div>
          <div><label style="margin-top:0;">Reporting Manager</label><select name="manager_choice" style="height:42px;">{manager_options}</select></div>
          <div><label style="margin-top:0;">Portal Role</label><select name="role" style="height:42px;"><option value="employee">Employee</option><option value="manager">Manager</option><option value="admin">Admin</option></select></div>
          <div><label style="margin-top:0;">Initial Password</label><input name="password" type="text" value="password123" required style="height:42px;"></div>
        </div>
        <input type="hidden" name="manager_name" value="">
        <input type="hidden" name="manager_email" value="">
        <div class="notice" style="margin-top: 24px;">
          <svg style="width: 20px; height: 20px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 11.513 1.293l-.042.02v.017a.75.75 0 11-1.5 0v-.017zm0 4.5h.008v.008h-.008v-.008zM12 3v18m9-9H3"/></svg>
          <div>After adding the employee profile, open their Portal to generate their cryptographic browser certificate.</div>
        </div>
        <div class="actions" style="margin-top: 24px;">
          <button type="submit" style="height:42px; font-weight:600;">Save Employee Account</button>
          <a class="button secondary" href="/app/admin/users" style="height:42px;">Cancel</a>
        </div>
      </form>
      <script>
        const form = document.querySelector('form');
        form.addEventListener('submit', () => {{
          const [name, email] = form.manager_choice.value.split('|');
          form.manager_name.value = name;
          form.manager_email.value = email;
        }});
      </script>
    </section>
    """
    return page("Add Employee", content, "Admin Dashboard", current_user)


def certificates_page(query, current_user=None):
    search = query.get("q", [""])[0]
    params = []
    where = ""
    if search:
        where = "where employee_name like ? or email like ? or cn like ?"
        like = f"%{search}%"
        params = [like, like, like]
    certs = query_all(f"select * from certificates {where} order by status, expires_at", params)
    rows = "".join(
        f"""
        <tr>
          <td>
            <div style="font-weight:600; color:var(--text);">{html.escape(c['employee_name'])}</div>
            <span class="muted" style="font-size:12px;">{html.escape(c['email'])}</span>
          </td>
          <td>{html.escape(c['department'])}</td>
          <td>
            <span>{fmt_date(c['expires_at'])}</span>
            {'<br><strong style="color:#d97706; font-size:11px; text-transform:uppercase;">expiring soon</strong>' if 0 <= days_until(c['expires_at']) <= 30 else ''}
          </td>
          <td>{status_badge(c['status'])}</td>
          <td><code>{html.escape(c['serial'] or '-')}</code></td>
          <td class="actions">
            <a class="button secondary" href="/app/certificate?id={c['id']}" style="height:32px; font-size:12.5px; padding:0 10px;">Details</a>
            {f'<a class="button danger" href="/app/admin/revoke?id={c["id"]}" style="height:32px; font-size:12.5px; padding:0 10px;">Revoke</a>' if c['status'] == 'ACTIVE' else ''}
          </td>
        </tr>
        """
        for c in certs
    ) or '<tr><td colspan="6" class="muted" style="text-align:center; padding: 24px;">No digital certificates matching query.</td></tr>'
    content = f"""
    <section>
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 16px;">
        <h2 style="margin:0; display: flex; align-items: center; gap: 8px;">
          <svg style="width: 22px; height: 22px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"/></svg>
          Digital Certificates &amp; Revocations
        </h2>
        <a class="button secondary" href="/app/admin">Back to Dashboard</a>
      </div>
      <form method="get" action="/app/admin/certificates" style="margin-bottom: 24px; display: flex; gap: 8px; align-items: flex-end;">
        <div style="flex: 1;">
          <label style="margin-top: 0;">Search Database</label>
          <input name="q" value="{html.escape(search)}" placeholder="Search by Employee, email, or certificate CN..." style="height: 40px; margin-top: 6px;">
        </div>
        <button type="submit" style="height: 40px;">Search</button>
      </form>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Employee Details</th>
              <th>Department</th>
              <th>Expiration Date</th>
              <th>Status</th>
              <th>Serial Number</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>
    """
    return page("Certificate Management", content, "Revocations", current_user)


def revoke_form(cert_id, current_user=None):
    cert = query_one("select * from certificates where id = ?", (cert_id,))
    if not cert:
        return page("Not Found", "<section><h2>Certificate not found</h2></section>", current_user=current_user)
    reasons = ["Employee Terminated", "Lost/Stolen Device", "Compromised Credentials", "Duplicate Certificate", "Certificate Expired", "Key Compromise", "Other"]
    reason_html = "".join(f'<option value="{html.escape(r)}">{html.escape(r)}</option>' for r in reasons)
    content = f"""
    <section class="danger-zone" style="max-width: 680px; margin: 0 auto; border: 1px solid #fecaca; background: #fff; padding: 32px;">
      <h2 style="color: var(--danger); display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
        <svg style="width: 24px; height: 24px;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        Revoke Digital Certificate
      </h2>
      <p style="margin-bottom: 20px; font-size:15px; color: var(--text-secondary);">You are revoking the client certificate issued to <strong>{html.escape(cert['employee_name'])}</strong>.</p>

      <div style="background: #fafafb; border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 24px; font-size:14px; display: grid; gap: 10px;">
        <div><span class="muted" style="width: 140px; display: inline-block;">Common Name (CN):</span> <code>{html.escape(cert['cn'])}</code></div>
        <div><span class="muted" style="width: 140px; display: inline-block;">Serial Number:</span> <code>{html.escape(cert['serial'] or '-')}</code></div>
        <div><span class="muted" style="width: 140px; display: inline-block;">Certificate Term:</span> {fmt_date(cert['issued_at'])} to {fmt_date(cert['expires_at'])}</div>
      </div>

      <form method="post" action="/app/admin/revoke">
        <input type="hidden" name="id" value="{cert['id']}">
        <label style="margin-top:0;">Reason for Revocation</label>
        <select name="reason" required style="height: 42px;">{reason_html}</select>
        <label>Additional Audit Notes</label>
        <textarea name="notes" placeholder="Enter reason details for compliance audit trail..."></textarea>

        <div class="notice danger-zone" style="margin: 20px 0;">
          <svg style="width: 20px; height: 20px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <div><strong>Compliance Notice</strong>: Once executed, OpenSSL will publish the revocation to the CRL registry. Nginx will immediately deny authentication for this certificate.</div>
        </div>

        <div class="actions">
          <button class="danger" type="submit" style="height: 42px; font-weight: 600;">Revoke Certificate</button>
          <a class="button secondary" href="/app/admin/certificates" style="height: 42px;">Cancel</a>
        </div>
      </form>
    </section>
    """
    return page("Revoke Certificate", content, "Revocations", current_user)


def certificate_details(cert_id, current_user=None):
    cert = query_one("select * from certificates where id = ?", (cert_id,))
    if not cert:
        return page("Not Found", "<section><h2>Certificate not found</h2></section>", current_user=current_user)
    if current_user and current_user["role"] != "admin" and cert["email"] != current_user["email"]:
        return page("Forbidden", "<section class='danger-zone'><h2>403 Forbidden</h2><p>You can only view your own certificate details.</p></section>", current_user=current_user)
    content = f"""
    <section style="max-width: 720px; margin: 0 auto; padding: 32px;">
      <h2 style="display: flex; align-items: center; gap: 8px; margin-bottom: 20px;">
        <svg style="width: 22px; height: 22px; color: var(--primary);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
        Certificate Details
      </h2>
      <div style="background: #ffffff; border: 1px solid var(--border); border-radius: 12px; padding: 24px; font-size: 14.5px; display: grid; gap: 14px; box-shadow: var(--shadow-sm); margin-bottom: 24px;">
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Common Name (CN):</span> <code>{html.escape(cert['cn'])}</code></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Owner Identity:</span> <strong>{html.escape(cert['employee_name'])}</strong> &bull; <span class="muted">{html.escape(cert['email'])}</span></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Department:</span> <span>{html.escape(cert['department'])}</span></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Verification Status:</span> <span>{status_badge(cert['status'])}</span></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Serial Number:</span> <code>{html.escape(cert['serial'] or '-')}</code></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Issued On:</span> <span>{fmt_date(cert['issued_at'])}</span></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Expires On:</span> <span>{fmt_date(cert['expires_at'])} ({days_until(cert['expires_at'])} days left)</span></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Certificate File:</span> <code>{html.escape(cert['cert_path'])}</code></div>
        <div style="display: flex; border-bottom: 1px solid var(--border); padding-bottom: 10px;"><span class="muted" style="width: 180px;">Private Key:</span> <code style="color:var(--danger);">Securely stored on HSM/Gateway</code></div>
        <div style="display: flex; padding-bottom: 0;"><span class="muted" style="width: 180px;">P12 Bundle Download:</span> <code>{html.escape(cert['p12_path'])}</code></div>
      </div>
      <div class="actions">
        <a class="button" href="/app/download?id={cert['id']}">
          <svg style="width:16px;height:16px;" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
          Download PKCS#12 (.p12)
        </a>
        <a class="button secondary" href="/app/admin/certificates">Back to Certificates</a>
      </div>
    </section>
    """
    return page("Certificate Details", content, current_user=current_user)


def audit_page(current_user=None):
    rows = query_all("select * from audit_log order by id desc limit 100")
    table = "".join(
        f"<tr><td style='font-family: monospace; font-size:13px; color:var(--text-muted);'>{html.escape(r['created_at'][:19])}</td><td style='font-weight: 500;'>{html.escape(r['actor'])}</td><td><span style='font-family: monospace; font-size:12.5px; font-weight:700; color: var(--primary);'>{html.escape(r['action'])}</span></td><td><code>{html.escape(r['target'])}</code></td><td style='font-size:13.5px; color:var(--text-secondary);'>{html.escape(r['details'] or '')}</td></tr>"
        for r in rows
    ) or '<tr><td colspan="5" class="muted" style="text-align:center; padding: 24px;">No audit compliance logs recorded yet.</td></tr>'
    content = f"""
    <section>
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;">
        <h2 style="margin: 0; display: flex; align-items: center; gap: 8px;">
          <svg style="width: 22px; height: 22px; color: var(--text-muted);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>
          Security Audit Compliance Logs
        </h2>
        <a class="button secondary" href="/app/admin">Back to Dashboard</a>
      </div>
      <p class="muted" style="margin-bottom: 20px;">Displays the last 100 security-relevant events recorded by the certificate portal.</p>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th style="width: 180px;">Time (UTC)</th>
              <th>Actor</th>
              <th>Action Type</th>
              <th>Target Object</th>
              <th>Compliance Details</th>
            </tr>
          </thead>
          <tbody>{table}</tbody>
        </table>
      </div>
    </section>
    """
    return page("Audit Log", content, current_user=current_user)


class CertAuthHandler(BaseHTTPRequestHandler):
    server_version = "CertAuthPortal/2.0"

    def session_token(self):
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        jar.load(raw)
        morsel = jar.get("pki_session")
        return morsel.value if morsel else None

    def current_user(self):
        return get_session_user(self.session_token())

    def require_login(self):
        user = self.current_user()
        if not user:
            self.redirect("/login")
            return None
        return user

    def require_role(self, allowed):
        user = self.require_login()
        if not user:
            return None
        if user["role"] not in allowed:
            self.send_html(
                page(
                    "Forbidden",
                    f"<section class='danger-zone'><h2>403 Forbidden</h2><p>Your role <code>{html.escape(user['role'])}</code> cannot access this portal.</p></section>",
                    current_user=user,
                ),
                403,
            )
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/":
            self.redirect("/login")
            return
        if path == "/login":
            self.send_html(login_page())
            return
        if path in ("/health", "/app/health"):
            self.send_json(200, {"status": "ok"})
            return
        if path == "/app":
            self.handle_app()
            return
        if path == "/app/portal":
            user = self.require_role(("employee",))
            if not user:
                return
            self.send_html(employee_portal({"email": [user["email"]]}, user))
            return
        if path == "/app/manager":
            user = self.require_role(("manager", "admin"))
            if not user:
                return
            self.send_html(manager_page(user))
            return
        if path == "/app/admin":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(admin_dashboard(user))
            return
        if path == "/app/admin/certificates":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(certificates_page(query, user))
            return
        if path == "/app/admin/users":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(users_page(user))
            return
        if path == "/app/admin/users/new":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(new_user_form(user))
            return
        if path == "/app/admin/revoke":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(revoke_form(int(query.get("id", ["0"])[0]), user))
            return
        if path == "/app/certificate":
            user = self.require_login()
            if not user:
                return
            self.send_html(certificate_details(int(query.get("id", ["0"])[0]), user))
            return
        if path == "/app/download":
            user = self.require_login()
            if not user:
                return
            self.download_p12(int(query.get("id", ["0"])[0]))
            return
        if path == "/app/audit":
            user = self.require_role(("admin",))
            if not user:
                return
            self.send_html(audit_page(user))
            return
        if path == "/app/request":
            user = self.require_login()
            if not user:
                return
            req = query_one("select * from certificate_requests where id = ?", (int(query.get("id", ["0"])[0]),))
            self.send_html(page("Request Status", f"<section><h2>{html.escape(req['request_id'])}</h2><p>Status: {status_badge(req['status'])}</p><p>Employee: {html.escape(req['employee_name'])}</p><p>CSR: {html.escape(req['csr_preview'])}</p></section>", current_user=user) if req else page("Not Found", "<section><h2>Request not found</h2></section>", current_user=user))
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        form = self.read_form()
        try:
            if path == "/login":
                user = query_one("select * from employees where email = ?", (form.get("email", "").strip().lower(),))
                if user and user["password_hash"] and verify_password(form.get("password", ""), user["password_hash"]):
                    token = create_session(user["email"])
                    target = {"employee": "/app/portal", "manager": "/app/manager", "admin": "/app/admin"}[user["role"]]
                    self.redirect_with_cookie(target, token)
                    return
                self.send_html(login_page("Invalid email or password"), 401)
                return
            if path == "/logout":
                delete_session(self.session_token())
                self.redirect_clear_cookie("/login")
                return
            if path == "/app/portal/request":
                user = self.require_role(("employee", "admin"))
                if not user:
                    return
                employee_email = user["email"] if user["role"] == "employee" else form.get("employee_email", "john@company.com")
                req_id = create_request(employee_email)
                self.redirect(f"/app/request?id={query_one('select id from certificate_requests where request_id = ?', (req_id,))['id']}")
                return
            if path == "/app/admin/users/new":
                user = self.require_role(("admin",))
                if not user:
                    return
                manager_choice = form.get("manager_choice", "")
                if manager_choice and "|" in manager_choice:
                    manager_name, manager_email = manager_choice.split("|", 1)
                    form["manager_name"] = manager_name
                    form["manager_email"] = manager_email
                email = create_employee(form)
                self.redirect(f"/app/portal?email={email}")
                return
            if path == "/app/manager/decision":
                user = self.require_role(("manager", "admin"))
                if not user:
                    return
                approve_request(form.get("request_id", ""), user["email"], form.get("decision", "reject"), form.get("notes", ""))
                self.redirect("/app/manager")
                return
            if path == "/app/admin/sign":
                user = self.require_role(("admin",))
                if not user:
                    return
                issue_certificate(form.get("request_id", ""))
                self.redirect("/app/admin")
                return
            if path == "/app/admin/revoke":
                user = self.require_role(("admin",))
                if not user:
                    return
                revoke_certificate(int(form.get("id", "0")), form.get("reason", "Other"), form.get("notes", ""))
                self.redirect("/app/admin/certificates")
                return
        except Exception as exc:
            self.send_html(page("Action Failed", f"<section class='danger-zone'><h2>Action failed</h2><p>{html.escape(str(exc))}</p><p><a class='button secondary' href='/app/admin'>Back to dashboard</a></p></section>"))
            return
        self.send_error(404, "Not found")

    def handle_app(self):
        status, payload = render_login_result(self.headers)
        if "application/json" in self.headers.get("Accept", ""):
            self.send_json(status, payload)
            return
        if status != 200:
            self.send_html(page("Access Denied", f"<section class='danger-zone'><h2>Certificate access denied</h2><pre>{html.escape(json.dumps(payload, indent=2))}</pre></section>", "mTLS Login"), status)
            return
        user = payload["user"]
        cert = payload.get("certificate")
        cert_line = f"<p>Status: {status_badge(cert['status'])} | Expires: {fmt_date(cert['expires_at'])}</p>" if cert else ""
        body = f"""
        <section>
          <h2>Certificate login successful</h2>
          <p>Nginx verified the client certificate and the backend mapped its CN to a user.</p>
          <div class="grid two">
            <div class="card">
              <h3>User</h3>
              <p>Name: <strong>{html.escape(user['display_name'])}</strong></p>
              <p>Username: {html.escape(user['username'])}</p>
              <p>Role: {html.escape(user['role'])}</p>
            </div>
            <div class="card">
              <h3>Certificate</h3>
              <p>CN: <code>{html.escape(payload['cn'])}</code></p>
              <p>Verify: <code>{html.escape(payload['ssl_client_verify'])}</code></p>
              {cert_line}
            </div>
          </div>
        </section>
        """
        self.send_html(page("Certificate Login", body, "mTLS Login"))

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw)
        return {k: v[0] for k, v in parsed.items()}

    def download_p12(self, cert_id):
        user = self.current_user()
        cert = query_one("select * from certificates where id = ?", (cert_id,))
        if not cert:
            self.send_error(404, "Certificate not found")
            return
        if not user:
            self.redirect("/login")
            return
        if user["role"] != "admin" and cert["email"] != user["email"]:
            self.send_html(
                page(
                    "Forbidden",
                    "<section class='danger-zone'><h2>403 Forbidden</h2><p>You can only download your own certificate bundle.</p></section>",
                    current_user=user,
                ),
                403,
            )
            return
        path = PROJECT_DIR / cert["p12_path"]
        if not path.exists():
            self.send_error(404, "P12 not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pkcs12")
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target):
        self.send_response(303)
        self.send_header("Location", target)
        self.end_headers()

    def redirect_with_cookie(self, target, token):
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("Set-Cookie", f"pki_session={token}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def redirect_clear_cookie(self, target):
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("Set-Cookie", "pki_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def send_html(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), CertAuthHandler)
    print(f"PKI portal listening on http://{HOST}:{PORT}")
    server.serve_forever()
