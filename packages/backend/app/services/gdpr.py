"""GDPR-ready PII export, irreversible deletion, and audit trail helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from ..extensions import db, redis_client
from ..models import (
    AdImpression,
    AuditLog,
    Bill,
    Category,
    Expense,
    GdprAuditLog,
    RecurringExpense,
    Reminder,
    User,
    UserSubscription,
)
from .cache import cache_delete_patterns

logger = logging.getLogger("finmind.gdpr")

DELETE_CONFIRMATION_PHRASE = "DELETE_MY_ACCOUNT"
EXPORT_SCHEMA_VERSION = "1.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _serialize_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return value


def hash_email(email: str) -> str:
    normalized = (email or "").strip().lower().encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def write_gdpr_audit(
    *,
    action: str,
    user_id: int | None,
    email: str | None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> GdprAuditLog:
    entry = GdprAuditLog(
        action=action,
        user_id=user_id,
        email_hash=hash_email(email) if email else None,
        ip_address=(ip_address or "")[:64] or None,
        user_agent=(user_agent or "")[:512] or None,
        details=json.dumps(details) if details is not None else None,
        created_at=_utcnow(),
    )
    db.session.add(entry)
    return entry


def collect_user_export_data(user: User) -> dict[str, Any]:
    """Build a JSON-serializable export package for one user (no secrets)."""
    uid = user.id
    categories = (
        db.session.query(Category).filter_by(user_id=uid).order_by(Category.id).all()
    )
    expenses = (
        db.session.query(Expense).filter_by(user_id=uid).order_by(Expense.id).all()
    )
    recurring = (
        db.session.query(RecurringExpense)
        .filter_by(user_id=uid)
        .order_by(RecurringExpense.id)
        .all()
    )
    bills = db.session.query(Bill).filter_by(user_id=uid).order_by(Bill.id).all()
    reminders = (
        db.session.query(Reminder).filter_by(user_id=uid).order_by(Reminder.id).all()
    )
    subscriptions = (
        db.session.query(UserSubscription)
        .filter_by(user_id=uid)
        .order_by(UserSubscription.id)
        .all()
    )

    package = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "id": user.id,
            "email": user.email,
            "preferred_currency": user.preferred_currency or "INR",
            "role": user.role,
            "created_at": _serialize_value(user.created_at),
        },
        "categories": [
            {
                "id": c.id,
                "name": c.name,
                "created_at": _serialize_value(c.created_at),
            }
            for c in categories
        ],
        "expenses": [
            {
                "id": e.id,
                "category_id": e.category_id,
                "amount": _serialize_value(e.amount),
                "currency": e.currency,
                "expense_type": e.expense_type,
                "notes": e.notes,
                "spent_at": _serialize_value(e.spent_at),
                "source_recurring_id": e.source_recurring_id,
                "created_at": _serialize_value(e.created_at),
            }
            for e in expenses
        ],
        "recurring_expenses": [
            {
                "id": r.id,
                "category_id": r.category_id,
                "amount": _serialize_value(r.amount),
                "currency": r.currency,
                "expense_type": r.expense_type,
                "notes": r.notes,
                "cadence": _serialize_value(r.cadence),
                "start_date": _serialize_value(r.start_date),
                "end_date": _serialize_value(r.end_date),
                "active": r.active,
                "created_at": _serialize_value(r.created_at),
            }
            for r in recurring
        ],
        "bills": [
            {
                "id": b.id,
                "name": b.name,
                "amount": _serialize_value(b.amount),
                "currency": b.currency,
                "next_due_date": _serialize_value(b.next_due_date),
                "cadence": _serialize_value(b.cadence),
                "autopay_enabled": b.autopay_enabled,
                "channel_whatsapp": b.channel_whatsapp,
                "channel_email": b.channel_email,
                "active": b.active,
                "created_at": _serialize_value(b.created_at),
            }
            for b in bills
        ],
        "reminders": [
            {
                "id": rem.id,
                "bill_id": rem.bill_id,
                "message": rem.message,
                "send_at": _serialize_value(rem.send_at),
                "sent": rem.sent,
                "channel": rem.channel,
            }
            for rem in reminders
        ],
        "subscriptions": [
            {
                "id": s.id,
                "plan_id": s.plan_id,
                "active": s.active,
                "started_at": _serialize_value(s.started_at),
            }
            for s in subscriptions
        ],
    }
    package["counts"] = {
        "categories": len(package["categories"]),
        "expenses": len(package["expenses"]),
        "recurring_expenses": len(package["recurring_expenses"]),
        "bills": len(package["bills"]),
        "reminders": len(package["reminders"]),
        "subscriptions": len(package["subscriptions"]),
    }
    return package


def export_preview_counts(user_id: int) -> dict[str, int]:
    return {
        "categories": db.session.query(Category).filter_by(user_id=user_id).count(),
        "expenses": db.session.query(Expense).filter_by(user_id=user_id).count(),
        "recurring_expenses": db.session.query(RecurringExpense)
        .filter_by(user_id=user_id)
        .count(),
        "bills": db.session.query(Bill).filter_by(user_id=user_id).count(),
        "reminders": db.session.query(Reminder).filter_by(user_id=user_id).count(),
        "subscriptions": db.session.query(UserSubscription)
        .filter_by(user_id=user_id)
        .count(),
    }


def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def build_export_zip_bytes(package: dict[str, Any]) -> bytes:
    """Create a ZIP package with manifest JSON + CSV sections."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": package["schema_version"],
                    "exported_at": package["exported_at"],
                    "counts": package["counts"],
                    "files": [
                        "user.json",
                        "categories.csv",
                        "expenses.csv",
                        "recurring_expenses.csv",
                        "bills.csv",
                        "reminders.csv",
                        "subscriptions.csv",
                        "export.json",
                    ],
                },
                indent=2,
            ),
        )
        zf.writestr("user.json", json.dumps(package["user"], indent=2))
        zf.writestr("export.json", json.dumps(package, indent=2))
        for key in (
            "categories",
            "expenses",
            "recurring_expenses",
            "bills",
            "reminders",
            "subscriptions",
        ):
            zf.writestr(f"{key}.csv", _rows_to_csv(package[key]))
    return buffer.getvalue()


def revoke_user_sessions(user_id: int) -> int:
    """Revoke all Redis refresh sessions belonging to the user."""
    revoked = 0
    try:
        cursor = 0
        pattern = "auth:refresh:*"
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=100)
            for key in keys or []:
                try:
                    stored = redis_client.get(key)
                    if stored is None:
                        continue
                    value = (
                        stored.decode("utf-8")
                        if isinstance(stored, (bytes, bytearray))
                        else str(stored)
                    )
                    if value == str(user_id):
                        redis_client.delete(key)
                        revoked += 1
                except Exception:
                    logger.exception("Failed revoking refresh key=%s", key)
            if cursor == 0:
                break
    except Exception:
        logger.exception("Redis session revoke failed for user_id=%s", user_id)
    return revoked


def clear_user_caches(user_id: int) -> None:
    try:
        cache_delete_patterns(
            [
                f"user:{user_id}:*",
                f"insights:{user_id}:*",
            ]
        )
    except Exception:
        logger.exception("Cache clear failed for user_id=%s", user_id)


def delete_user_permanently(user: User) -> dict[str, int]:
    """
    Irreversibly delete all personal data for the user.

    Order matters for SQLite test DBs that may not enforce FK cascades.
    GDPR audit rows are retained (no user FK cascade) with email_hash only.
    """
    uid = user.id
    counts = export_preview_counts(uid)

    # Null out ad impressions / legacy audit logs linked to the user.
    db.session.query(AdImpression).filter_by(user_id=uid).update(
        {"user_id": None}, synchronize_session=False
    )
    db.session.query(AuditLog).filter_by(user_id=uid).update(
        {"user_id": None}, synchronize_session=False
    )

    # Clear dependent rows explicitly for SQLite compatibility.
    db.session.query(Reminder).filter_by(user_id=uid).delete(synchronize_session=False)
    db.session.query(Expense).filter_by(user_id=uid).delete(synchronize_session=False)
    db.session.query(RecurringExpense).filter_by(user_id=uid).delete(
        synchronize_session=False
    )
    db.session.query(Bill).filter_by(user_id=uid).delete(synchronize_session=False)
    db.session.query(UserSubscription).filter_by(user_id=uid).delete(
        synchronize_session=False
    )
    db.session.query(Category).filter_by(user_id=uid).delete(synchronize_session=False)

    db.session.delete(user)
    db.session.flush()

    revoked = revoke_user_sessions(uid)
    clear_user_caches(uid)

    logger.info(
        "Permanently deleted user_id=%s records=%s sessions_revoked=%s",
        uid,
        counts,
        revoked,
    )
    return {**counts, "sessions_revoked": revoked}


def list_user_audit_logs(user_id: int, limit: int = 50) -> list[dict[str, Any]]:
    rows = (
        db.session.query(GdprAuditLog)
        .filter_by(user_id=user_id)
        .order_by(GdprAuditLog.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [
        {
            "id": row.id,
            "action": row.action,
            "ip_address": row.ip_address,
            "user_agent": row.user_agent,
            "details": json.loads(row.details) if row.details else None,
            "created_at": _serialize_value(row.created_at),
        }
        for row in rows
    ]
