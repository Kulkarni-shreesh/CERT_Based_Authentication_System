# Corrected Flask-Style Route Design

This file keeps the same structure as the proposed Flask blueprint design, but corrects a few security, workflow, and implementation issues.

Important note: the current project uses a Python standard-library backend in `app/app.py`, not Flask. This document is a clean Flask-style design that can be used if the project is later migrated to Flask.

## Why The Browser Shows Access Denied

If you open:

```text
http://127.0.0.1:8081/app
```

you are calling the backend directly. That bypasses Nginx, so these headers are missing:

```text
X-SSL-Client-Verify
X-SSL-Client-DN
X-SSL-Client-Issuer-DN
```

The backend correctly denies access because Nginx did not verify a client certificate.

Use this for the portal:

```text
http://127.0.0.1:8081/app/portal
```

Use this for the mTLS login demo:

```text
https://localhost/app
```

The `https://localhost/app` route goes through Nginx, so Nginx can verify the browser certificate and pass the trusted headers.

---

# routes/auth.py

```python
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for("portal.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            flash(f"Welcome, {user.full_name}!", "success")
            return redirect(url_for("portal.dashboard"))

        flash("Invalid username or password", "error")

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """User logout."""
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for("auth.login"))
```

Corrections:

- `logout` should be `POST`, not plain `GET`, because logout changes session state.
- `logout` should use `@login_required`.
- Username is stripped before lookup.
- `db` import is unnecessary in this file.

---

# routes/portal.py

```python
from datetime import datetime
import hashlib
import logging
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user

from models import CertRequest, AuditLog, db

portal_bp = Blueprint("portal", __name__, url_prefix="/pki")


@portal_bp.route("/dashboard")
@login_required
def dashboard():
    """Employee dashboard."""
    user_requests = CertRequest.query.filter_by(user_id=current_user.id).all()

    active_certs = [
        r for r in user_requests
        if r.status == "SIGNED" and not r.revoked_at and r.expiry_date > datetime.utcnow()
    ]
    pending_certs = [
        r for r in user_requests
        if r.status in ["PENDING", "MANAGER_APPROVED", "IT_APPROVED"]
    ]

    return render_template(
        "dashboard.html",
        active_certs=active_certs,
        pending_certs=pending_certs,
        all_requests=user_requests,
    )


@portal_bp.route("/request", methods=["GET", "POST"])
@login_required
def request_certificate():
    """Request a new certificate."""
    if request.method == "GET":
        return render_template("request_cert.html")

    data = request.get_json(silent=True) or {}
    csr_pem = data.get("csr", "")

    if not csr_pem:
        return jsonify({"error": "CSR required"}), 400

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())
        if not csr.is_signature_valid:
            return jsonify({"error": "CSR signature is invalid"}), 400
    except Exception as exc:
        logging.error("Invalid CSR from %s: %s", current_user.email, exc)
        return jsonify({"error": "Invalid CSR format"}), 400

    active = (
        CertRequest.query
        .filter_by(user_id=current_user.id, status="SIGNED")
        .filter(CertRequest.expiry_date > datetime.utcnow())
        .filter(CertRequest.revoked_at.is_(None))
        .first()
    )
    if active:
        return jsonify({"error": "You already have an active certificate"}), 400

    cert_request = CertRequest(
        request_id=f"REQ-{datetime.utcnow().year}-{uuid.uuid4().hex[:8].upper()}",
        user_id=current_user.id,
        email=current_user.email,
        department=current_user.department,
        csr_data=csr_pem,
        csr_hash=hashlib.sha256(csr_pem.encode("utf-8")).hexdigest(),
        manager_id=current_user.manager_id,
        status="PENDING",
        created_at=datetime.utcnow(),
    )

    db.session.add(cert_request)
    db.session.commit()

    log_audit(
        user_id=current_user.id,
        action="CREATE_REQUEST",
        request_id=cert_request.request_id,
        details=f"Certificate request created for {current_user.email}",
        status="SUCCESS",
    )

    return jsonify({
        "success": True,
        "request_id": cert_request.request_id,
        "message": "Certificate request submitted",
    }), 201


@portal_bp.route("/request/<request_id>")
@login_required
def view_request(request_id):
    """View request status."""
    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404

    if current_user.id != cert_request.user_id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({
        "request_id": cert_request.request_id,
        "status": cert_request.status,
        "created_at": cert_request.created_at.isoformat() if cert_request.created_at else None,
        "manager_approved_at": cert_request.manager_approved_at.isoformat() if cert_request.manager_approved_at else None,
        "it_approved_at": cert_request.it_approved_at.isoformat() if cert_request.it_approved_at else None,
        "signed_at": cert_request.signed_at.isoformat() if cert_request.signed_at else None,
        "expiry_date": cert_request.expiry_date.isoformat() if cert_request.expiry_date else None,
        "manager_notes": cert_request.manager_notes,
        "it_notes": cert_request.it_notes,
    })


@portal_bp.route("/download/<request_id>")
@login_required
def download_certificate(request_id):
    """Download issued .p12 file."""
    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404
    if current_user.id != cert_request.user_id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    if cert_request.status != "SIGNED":
        return jsonify({"error": "Certificate not signed yet"}), 400
    if cert_request.revoked_at:
        return jsonify({"error": "Certificate is revoked"}), 410

    cert_request.download_count += 1
    cert_request.last_downloaded = datetime.utcnow()
    db.session.commit()

    log_audit(
        user_id=current_user.id,
        action="DOWNLOAD_CERT",
        request_id=request_id,
        details="Downloaded certificate bundle",
        status="SUCCESS",
    )

    return send_file(
        cert_request.p12_path,
        as_attachment=True,
        download_name=f"{cert_request.email}.p12",
        mimetype="application/x-pkcs12",
    )


def log_audit(user_id, action, request_id, details, status):
    """Log action to audit trail."""
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        request_id=request_id,
        details=details,
        status=status,
        timestamp=datetime.utcnow(),
    )
    db.session.add(log_entry)
    db.session.commit()
```

Corrections:

- `csr_hash` should be calculated server-side, not trusted from client JSON.
- CSR signature is checked with `csr.is_signature_valid`.
- Active certificate check also excludes revoked certificates.
- Download should return `.p12`, not PEM.
- Authorization allows owner or admin, depending on use case.

---

# routes/manager.py

```python
from datetime import datetime
import logging

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from models import User, CertRequest, AuditLog, db

manager_bp = Blueprint("manager", __name__, url_prefix="/pki/approve")


@manager_bp.route("/")
@login_required
def pending_requests():
    """View pending requests for approval."""
    team_members = User.query.filter_by(manager_id=current_user.id).all()
    team_ids = [u.id for u in team_members]

    pending = (
        CertRequest.query
        .filter(CertRequest.user_id.in_(team_ids))
        .filter(CertRequest.status == "PENDING")
        .all()
    )

    return render_template(
        "manager_approval.html",
        pending_requests=pending,
        team_members=team_members,
    )


@manager_bp.route("/<request_id>")
@login_required
def view_request(request_id):
    """View request details."""
    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404
    if current_user.id != cert_request.manager_id:
        return jsonify({"error": "Unauthorized"}), 403

    return render_template("request_detail.html", request=cert_request)


@manager_bp.route("/<request_id>/approve", methods=["POST"])
@login_required
def approve_request(request_id):
    """Approve certificate request."""
    data = request.get_json(silent=True) or {}
    notes = data.get("notes", "")

    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404
    if current_user.id != cert_request.manager_id:
        return jsonify({"error": "Unauthorized"}), 403
    if cert_request.status != "PENDING":
        return jsonify({"error": "Request is not pending manager approval"}), 400

    try:
        cert_request.status = "MANAGER_APPROVED"
        cert_request.manager_approved_at = datetime.utcnow()
        cert_request.manager_notes = notes

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="MANAGER_APPROVE",
            request_id=request_id,
            details=f"Manager approved: {notes}",
            status="SUCCESS",
            timestamp=datetime.utcnow(),
        ))
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as exc:
        db.session.rollback()
        logging.error("Approval error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@manager_bp.route("/<request_id>/reject", methods=["POST"])
@login_required
def reject_request(request_id):
    """Reject certificate request."""
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "")

    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404
    if current_user.id != cert_request.manager_id:
        return jsonify({"error": "Unauthorized"}), 403
    if cert_request.status != "PENDING":
        return jsonify({"error": "Request is not pending manager approval"}), 400

    try:
        cert_request.status = "REJECTED"
        cert_request.manager_rejected_at = datetime.utcnow()
        cert_request.manager_notes = f"Rejected: {reason}"

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="MANAGER_REJECT",
            request_id=request_id,
            details=f"Rejected: {reason}",
            status="SUCCESS",
            timestamp=datetime.utcnow(),
        ))
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as exc:
        db.session.rollback()
        logging.error("Rejection error: %s", exc)
        return jsonify({"error": str(exc)}), 500
```

Corrections:

- AuditLog must be added with `db.session.add(...)`.
- Check request status before approve/reject.
- Use rollback on exceptions.
- `request.get_json(silent=True) or {}` prevents crashes on empty JSON.

---

# routes/admin.py

```python
from datetime import datetime, timedelta
from functools import wraps
import logging
import subprocess

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy import func

from models import User, CertRequest, AuditLog, db

admin_bp = Blueprint("admin", __name__, url_prefix="/pki/admin")


def admin_only(f):
    """Allow only admin users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"error": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/dashboard")
@login_required
@admin_only
def dashboard():
    """Admin dashboard."""
    total_requests = CertRequest.query.count()
    signed = CertRequest.query.filter_by(status="SIGNED").count()
    revoked = CertRequest.query.filter_by(status="REVOKED").count()
    pending = CertRequest.query.filter_by(status="PENDING").count()
    manager_approved = CertRequest.query.filter_by(status="MANAGER_APPROVED").count()

    thirty_days = datetime.utcnow() + timedelta(days=30)
    expiring_soon = (
        CertRequest.query
        .filter(CertRequest.expiry_date < thirty_days)
        .filter(CertRequest.expiry_date > datetime.utcnow())
        .filter(CertRequest.status == "SIGNED")
        .filter(CertRequest.revoked_at.is_(None))
        .count()
    )

    signed_certs = CertRequest.query.filter_by(status="SIGNED").all()
    times_to_sign = [
        (cert.signed_at - cert.created_at).total_seconds() / 3600
        for cert in signed_certs
        if cert.created_at and cert.signed_at
    ]
    avg_time_to_sign = sum(times_to_sign) / len(times_to_sign) if times_to_sign else 0

    ready_to_sign = CertRequest.query.filter_by(status="MANAGER_APPROVED").all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()

    dept_stats = (
        db.session.query(User.department, func.count(CertRequest.id))
        .join(CertRequest, CertRequest.user_id == User.id)
        .filter(CertRequest.status == "SIGNED")
        .filter(CertRequest.revoked_at.is_(None))
        .group_by(User.department)
        .all()
    )

    return render_template(
        "admin_dashboard.html",
        total_requests=total_requests,
        signed=signed,
        revoked=revoked,
        pending=pending,
        manager_approved=manager_approved,
        expiring_soon=expiring_soon,
        avg_time_to_sign=round(avg_time_to_sign, 1),
        ready_to_sign=ready_to_sign,
        recent_logs=recent_logs,
        dept_stats=dept_stats,
    )


@admin_bp.route("/certificates")
@login_required
@admin_only
def certificates():
    """Manage all certificates."""
    status = request.args.get("status", "all")
    department = request.args.get("department", "all")
    page = request.args.get("page", 1, type=int)

    query = CertRequest.query

    if status != "all":
        query = query.filter_by(status=status)

    if department != "all":
        query = query.join(User, CertRequest.user_id == User.id).filter(User.department == department)

    certs = query.paginate(page=page, per_page=20, error_out=False)
    departments = db.session.query(User.department).distinct().all()

    return render_template(
        "certificates_list.html",
        certs=certs,
        current_status=status,
        current_department=department,
        departments=[d[0] for d in departments],
    )


@admin_bp.route("/certificates/<request_id>/revoke", methods=["POST"])
@login_required
@admin_only
def revoke_certificate(request_id):
    """Revoke a certificate."""
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "")

    cert_request = CertRequest.query.filter_by(request_id=request_id).first()

    if not cert_request:
        return jsonify({"error": "Not found"}), 404
    if cert_request.status != "SIGNED":
        return jsonify({"error": "Certificate not signed"}), 400
    if cert_request.revoked_at:
        return jsonify({"error": "Already revoked"}), 400

    try:
        openssl = current_app.config["OPENSSL_BIN"]
        ca_config = current_app.config["INTERMEDIATE_CA_CONFIG"]
        cert_path = cert_request.certificate_path

        subprocess.run(
            [openssl, "ca", "-batch", "-config", ca_config, "-revoke", cert_path],
            check=True,
            capture_output=True,
            text=True,
        )

        subprocess.run(
            [openssl, "ca", "-batch", "-config", ca_config, "-gencrl", "-crlexts", "crl_ext", "-out", current_app.config["INTERMEDIATE_CRL"]],
            check=True,
            capture_output=True,
            text=True,
        )

        # In this project, also rebuild combined CRL and reload Nginx.
        # Example helper:
        # rebuild_combined_crl()
        # reload_nginx()

        cert_request.status = "REVOKED"
        cert_request.revoked_at = datetime.utcnow()
        cert_request.revocation_reason = reason
        cert_request.revoked_by_id = current_user.id

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="REVOKE_CERT",
            request_id=request_id,
            details=f"Revoked: {reason}",
            status="SUCCESS",
            timestamp=datetime.utcnow(),
        ))
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as exc:
        db.session.rollback()
        logging.error("Revocation error: %s", exc)
        return jsonify({"error": str(exc)}), 500
```

Corrections:

- Do not assume the certificate path is `pki/certs/{serial}.crt`; store the actual path in the database.
- Use configured OpenSSL path instead of assuming `openssl` is on `PATH`.
- Add `-crlexts crl_ext`, matching the project CRL config.
- Rebuild combined CRL and reload Nginx after revocation.
- Add audit log with `db.session.add(...)`.
- Roll back DB changes on failure.

## Best Direction For This Project

The Flask blueprint structure is good if you want the project to look more professional. But migrating the current project to Flask would require adding:

```text
app.py / create_app()
models.py
routes/auth.py
routes/portal.py
routes/manager.py
routes/admin.py
templates/
static/
requirements.txt
```

For the current CV/demo version, the existing standard-library app is simpler and already working. The best next upgrade would be to migrate to Flask only if you want the project to look like a real web application codebase.
