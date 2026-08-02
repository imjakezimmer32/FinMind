import io
import json
import logging

from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash

from ..extensions import db
from ..models import GdprAuditLog, User
from ..services.privacy import (
    DELETE_CONFIRMATION,
    DELETE_TOKEN_TTL_SECONDS,
    build_export_zip,
    consume_deletion_token,
    create_deletion_token,
    email_hash,
    permanently_delete_user,
    record_gdpr_audit,
)

bp = Blueprint("privacy", __name__)
logger = logging.getLogger("finmind.privacy")


@bp.get("/export")
@jwt_required()
def export_personal_data():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404

    archive, filename, manifest = build_export_zip(user)
    record_gdpr_audit(
        user_id=uid,
        email=user.email,
        action="privacy.export",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        details={"tables": manifest["tables"], "filename": filename},
    )
    db.session.commit()
    logger.info("Exported personal data user_id=%s tables=%s", uid, manifest["tables"])

    return send_file(
        io.BytesIO(archive),
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
        max_age=0,
    )


@bp.post("/delete/request")
@jwt_required()
def request_account_deletion():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404

    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if not password:
        return jsonify(error="password required"), 400
    if not check_password_hash(user.password_hash, password):
        return jsonify(error="incorrect password"), 401

    token = create_deletion_token(uid)
    record_gdpr_audit(
        user_id=uid,
        email=user.email,
        action="privacy.delete.requested",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        details={"expires_in_seconds": DELETE_TOKEN_TTL_SECONDS},
    )
    db.session.commit()
    logger.info("Deletion requested user_id=%s", uid)

    return jsonify(
        message="deletion confirmation required",
        confirmation_token=token,
        expires_in_seconds=DELETE_TOKEN_TTL_SECONDS,
        confirm_phrase=DELETE_CONFIRMATION,
    )


@bp.post("/delete/confirm")
@jwt_required()
def confirm_account_deletion():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404

    data = request.get_json(silent=True) or {}
    token = data.get("confirmation_token") or data.get("token")
    confirm = data.get("confirm")
    if not token:
        return jsonify(error="confirmation_token required"), 400
    if confirm != DELETE_CONFIRMATION:
        return jsonify(error=f"confirm must be {DELETE_CONFIRMATION}"), 400
    if not consume_deletion_token(str(token), uid):
        return jsonify(error="invalid or expired confirmation token"), 400

    result = permanently_delete_user(user)
    record_gdpr_audit(
        user_id=result["user_id"],
        email=result["email"],
        action="privacy.delete.completed",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        details={
            "deleted_records": result["deleted_records"],
            "anonymized_audit_logs": result["anonymized_audit_logs"],
            "deleted_cache_keys": result["deleted_cache_keys"],
            "revoked_refresh_sessions": result["revoked_refresh_sessions"],
        },
    )
    db.session.commit()
    logger.info(
        "Account permanently deleted user_id=%s records=%s",
        result["user_id"],
        result["deleted_records"],
    )

    return jsonify(
        message="account permanently deleted",
        deleted_records=result["deleted_records"],
        anonymized_audit_logs=result["anonymized_audit_logs"],
        deleted_cache_keys=result["deleted_cache_keys"],
        revoked_refresh_sessions=result["revoked_refresh_sessions"],
    )


@bp.get("/audit")
@jwt_required()
def list_privacy_audit():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404

    hashed = email_hash(user.email)
    rows = (
        db.session.query(GdprAuditLog)
        .filter(
            (GdprAuditLog.user_id == uid) | (GdprAuditLog.email_hash == hashed),
        )
        .order_by(GdprAuditLog.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify(
        [
            {
                "id": row.id,
                "action": row.action,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "details": json.loads(row.details) if row.details else None,
                "created_at": row.created_at.isoformat() + "Z",
            }
            for row in rows
        ]
    )
