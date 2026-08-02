"""GDPR privacy endpoints: export package, irreversible delete, audit trail."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from io import BytesIO
from werkzeug.security import check_password_hash

from ..extensions import db
from ..models import User
from ..services.gdpr import (
    DELETE_CONFIRMATION_PHRASE,
    build_export_zip_bytes,
    collect_user_export_data,
    delete_user_permanently,
    export_preview_counts,
    list_user_audit_logs,
    write_gdpr_audit,
)

bp = Blueprint("gdpr", __name__)
logger = logging.getLogger("finmind.gdpr")


def _client_meta():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",", 1)[0].strip()
    ua = request.headers.get("User-Agent")
    return ip, ua


def _current_user():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    return uid, user


@bp.get("/export/preview")
@jwt_required()
def export_preview():
    uid, user = _current_user()
    if not user:
        return jsonify(error="not found"), 404
    counts = export_preview_counts(uid)
    return jsonify(counts=counts), 200


@bp.get("/export")
@jwt_required()
def export_package():
    uid, user = _current_user()
    if not user:
        return jsonify(error="not found"), 404

    fmt = (request.args.get("format") or "zip").strip().lower()
    package = collect_user_export_data(user)
    ip, ua = _client_meta()
    write_gdpr_audit(
        action="PII_EXPORT",
        user_id=uid,
        email=user.email,
        ip_address=ip,
        user_agent=ua,
        details={"format": fmt, "counts": package["counts"]},
    )
    db.session.commit()
    logger.info("PII export user_id=%s format=%s", uid, fmt)

    if fmt == "json":
        return jsonify(package), 200

    zip_bytes = build_export_zip_bytes(package)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"finmind-export-{uid}-{stamp}.zip"
    return send_file(
        BytesIO(zip_bytes),
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
    )


@bp.post("/delete-account")
@jwt_required()
def delete_account():
    uid, user = _current_user()
    if not user:
        return jsonify(error="not found"), 404

    data = request.get_json() or {}
    password = data.get("password")
    confirm = (data.get("confirm") or "").strip()

    if not password:
        return jsonify(error="password required"), 400
    if confirm != DELETE_CONFIRMATION_PHRASE:
        return (
            jsonify(
                error=(
                    "confirmation required; "
                    f'set confirm to "{DELETE_CONFIRMATION_PHRASE}"'
                )
            ),
            400,
        )
    if not check_password_hash(user.password_hash, password):
        logger.warning("Delete account rejected: bad password user_id=%s", uid)
        return jsonify(error="incorrect password"), 401

    email = user.email
    ip, ua = _client_meta()
    preview = export_preview_counts(uid)

    # Audit BEFORE cascade so the compliance record is durable.
    write_gdpr_audit(
        action="ACCOUNT_DELETE",
        user_id=uid,
        email=email,
        ip_address=ip,
        user_agent=ua,
        details={"counts": preview, "irreversible": True},
    )
    deleted = delete_user_permanently(user)
    db.session.commit()
    logger.info("Account deleted user_id=%s", uid)
    return (
        jsonify(
            message="account permanently deleted",
            deleted=deleted,
        ),
        200,
    )


@bp.get("/audit-log")
@jwt_required()
def audit_log():
    uid, user = _current_user()
    if not user:
        return jsonify(error="not found"), 404
    try:
        limit = int(request.args.get("limit") or 50)
    except ValueError:
        limit = 50
    return jsonify(items=list_user_audit_logs(uid, limit=limit)), 200
