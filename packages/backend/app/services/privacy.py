"""GDPR-ready personal data export and irreversible deletion helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
import zipfile
from datetime import date, datetime
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
    SubscriptionPlan,
    User,
    UserSubscription,
)

DELETE_CONFIRMATION = "DELETE_MY_DATA"
DELETE_TOKEN_TTL_SECONDS = 15 * 60
PRIVACY_DELETE_KEY_PREFIX = "privacy:delete:"


def email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def record_gdpr_audit(
    *,
    user_id: int | None,
    email: str,
    action: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> GdprAuditLog:
    entry = GdprAuditLog(
        user_id=user_id,
        email_hash=email_hash(email),
        action=action,
        ip_address=(ip_address or "")[:64] or None,
        user_agent=(user_agent or "")[:255] or None,
        details=json.dumps(details, sort_keys=True) if details else None,
    )
    db.session.add(entry)
    return entry


def collect_user_export(user: User) -> dict[str, Any]:
    uid = user.id
    tables = {
        "categories": _model_rows(
            Category, uid, ["id", "name", "created_at"], order_by=Category.id
        ),
        "expenses": _model_rows(
            Expense,
            uid,
            [
                "id",
                "category_id",
                "amount",
                "currency",
                "expense_type",
                "notes",
                "spent_at",
                "source_recurring_id",
                "created_at",
            ],
            order_by=Expense.id,
        ),
        "recurring_expenses": _model_rows(
            RecurringExpense,
            uid,
            [
                "id",
                "category_id",
                "amount",
                "currency",
                "expense_type",
                "notes",
                "cadence",
                "start_date",
                "end_date",
                "active",
                "created_at",
            ],
            order_by=RecurringExpense.id,
        ),
        "bills": _model_rows(
            Bill,
            uid,
            [
                "id",
                "name",
                "amount",
                "currency",
                "next_due_date",
                "cadence",
                "autopay_enabled",
                "channel_whatsapp",
                "channel_email",
                "active",
                "created_at",
            ],
            order_by=Bill.id,
        ),
        "reminders": _model_rows(
            Reminder,
            uid,
            ["id", "bill_id", "message", "send_at", "sent", "channel"],
            order_by=Reminder.id,
        ),
        "ad_impressions": _model_rows(
            AdImpression,
            uid,
            ["id", "placement", "created_at"],
            order_by=AdImpression.id,
        ),
        "user_subscriptions": _subscription_rows(uid),
        "audit_logs": _model_rows(
            AuditLog, uid, ["id", "action", "created_at"], order_by=AuditLog.id
        ),
    }
    profile = {
        "id": user.id,
        "email": user.email,
        "preferred_currency": user.preferred_currency,
        "role": user.role,
        "created_at": _export_value(user.created_at),
    }
    generated_at = datetime.utcnow()
    manifest = {
        "format_version": 1,
        "generated_at": generated_at.isoformat() + "Z",
        "profile_fields": sorted(profile.keys()),
        "tables": {name: len(rows) for name, rows in tables.items()},
    }
    return {
        "generated_at": generated_at,
        "manifest": manifest,
        "profile": profile,
        "tables": tables,
        "package": {
            "manifest": manifest,
            "profile": profile,
            "tables": tables,
        },
    }


def build_export_zip(user: User) -> tuple[bytes, str, dict[str, Any]]:
    export = collect_user_export(user)
    generated_at: datetime = export["generated_at"]
    out = io.BytesIO()
    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(export["manifest"], indent=2, sort_keys=True) + "\n",
        )
        archive.writestr(
            "profile.json",
            json.dumps(export["profile"], indent=2, sort_keys=True) + "\n",
        )
        archive.writestr(
            "data.json",
            json.dumps(export["package"], indent=2, sort_keys=True) + "\n",
        )
        for table_name, rows in export["tables"].items():
            archive.writestr(f"{table_name}.csv", _rows_to_csv(rows))
    filename = f"finmind-data-export-{generated_at.strftime('%Y%m%dT%H%M%SZ')}.zip"
    return out.getvalue(), filename, export["manifest"]


def create_deletion_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    redis_client.setex(
        f"{PRIVACY_DELETE_KEY_PREFIX}{token}",
        DELETE_TOKEN_TTL_SECONDS,
        str(user_id),
    )
    return token


def consume_deletion_token(token: str, expected_user_id: int) -> bool:
    key = f"{PRIVACY_DELETE_KEY_PREFIX}{token}"
    stored = redis_client.get(key)
    if stored is None:
        return False
    value = stored.decode("utf-8") if isinstance(stored, bytes) else str(stored)
    if value != str(expected_user_id):
        return False
    redis_client.delete(key)
    return True


def permanently_delete_user(user: User) -> dict[str, Any]:
    uid = user.id
    email = user.email
    deleted_cache_keys = _delete_user_cache_keys(uid)
    revoked_refresh_sessions = _revoke_refresh_sessions(uid)
    deleted_records = _delete_user_owned_records(uid)
    anonymized_audits = (
        db.session.query(AuditLog)
        .filter(AuditLog.user_id == uid)
        .update({AuditLog.user_id: None}, synchronize_session=False)
    )
    db.session.delete(user)
    return {
        "user_id": uid,
        "email": email,
        "deleted_records": deleted_records,
        "anonymized_audit_logs": anonymized_audits,
        "deleted_cache_keys": deleted_cache_keys,
        "revoked_refresh_sessions": revoked_refresh_sessions,
    }


def _model_rows(model, uid: int, fields: list[str], *, order_by) -> list[dict]:
    rows = db.session.query(model).filter(model.user_id == uid).order_by(order_by).all()
    return [
        {field: _export_value(getattr(row, field)) for field in fields} for row in rows
    ]


def _subscription_rows(uid: int) -> list[dict]:
    rows = (
        db.session.query(UserSubscription, SubscriptionPlan)
        .outerjoin(SubscriptionPlan, UserSubscription.plan_id == SubscriptionPlan.id)
        .filter(UserSubscription.user_id == uid)
        .order_by(UserSubscription.id)
        .all()
    )
    result = []
    for subscription, plan in rows:
        result.append(
            {
                "id": subscription.id,
                "plan_id": subscription.plan_id,
                "plan_name": plan.name if plan else None,
                "plan_price_cents": plan.price_cents if plan else None,
                "plan_interval": plan.interval if plan else None,
                "active": subscription.active,
                "started_at": _export_value(subscription.started_at),
            }
        )
    return result


def _rows_to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def _export_value(value):
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    return value


def _delete_user_owned_records(uid: int) -> dict[str, int]:
    deleted: dict[str, int] = {}
    # Order matters for SQLite FK checks in tests.
    for table_name, model in [
        ("reminders", Reminder),
        ("expenses", Expense),
        ("recurring_expenses", RecurringExpense),
        ("bills", Bill),
        ("categories", Category),
        ("ad_impressions", AdImpression),
        ("user_subscriptions", UserSubscription),
    ]:
        deleted[table_name] = (
            db.session.query(model)
            .filter(model.user_id == uid)
            .delete(synchronize_session=False)
        )
    return deleted


def _revoke_refresh_sessions(uid: int) -> int:
    target_uid = str(uid)
    revoked = 0
    cursor = 0
    while True:
        cursor, keys = redis_client.scan(
            cursor=cursor, match="auth:refresh:*", count=100
        )
        for key in keys:
            stored = redis_client.get(key)
            if stored is None:
                continue
            value = stored.decode("utf-8") if isinstance(stored, bytes) else str(stored)
            if value == target_uid:
                redis_client.delete(key)
                revoked += 1
        if cursor == 0:
            break
    return revoked


def _delete_user_cache_keys(uid: int) -> int:
    deleted = 0
    for pattern in [f"user:{uid}:*", f"insights:{uid}:*"]:
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                redis_client.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
    return deleted
