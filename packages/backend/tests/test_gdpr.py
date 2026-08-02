import io
import json
import zipfile
from datetime import date, datetime, timedelta

from app.extensions import db
from app.models import (
    Bill,
    BillCadence,
    Category,
    Expense,
    GdprAuditLog,
    RecurringCadence,
    RecurringExpense,
    Reminder,
    User,
)
from app.services.gdpr import DELETE_CONFIRMATION_PHRASE, hash_email


def _register_login(client, email="gdpr@example.com", password="password123"):
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code in (201, 409)
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    tokens = r.get_json()
    return {
        "Authorization": f"Bearer {tokens['access_token']}",
        "refresh": tokens["refresh_token"],
        "email": email,
        "password": password,
    }


def _seed_user_data(app_fixture, email="gdpr@example.com"):
    with app_fixture.app_context():
        user = db.session.query(User).filter_by(email=email).first()
        assert user is not None
        cat = Category(user_id=user.id, name="Food")
        db.session.add(cat)
        db.session.flush()
        db.session.add(
            Expense(
                user_id=user.id,
                category_id=cat.id,
                amount=12.5,
                currency="INR",
                notes="lunch",
                spent_at=date.today(),
            )
        )
        db.session.add(
            RecurringExpense(
                user_id=user.id,
                category_id=cat.id,
                amount=9.99,
                currency="INR",
                notes="streaming",
                cadence=RecurringCadence.MONTHLY,
                start_date=date.today(),
                active=True,
            )
        )
        bill = Bill(
            user_id=user.id,
            name="Internet",
            amount=40,
            currency="INR",
            next_due_date=date.today() + timedelta(days=7),
            cadence=BillCadence.MONTHLY,
        )
        db.session.add(bill)
        db.session.flush()
        db.session.add(
            Reminder(
                user_id=user.id,
                bill_id=bill.id,
                message="Pay internet",
                send_at=datetime.now() + timedelta(days=1),
                channel="email",
            )
        )
        db.session.commit()
        return user.id


def test_export_requires_auth(client):
    r = client.get("/gdpr/export")
    assert r.status_code == 401


def test_export_preview_counts(client, app_fixture):
    auth = _register_login(client)
    _seed_user_data(app_fixture, auth["email"])
    r = client.get(
        "/gdpr/export/preview", headers={"Authorization": auth["Authorization"]}
    )
    assert r.status_code == 200
    counts = r.get_json()["counts"]
    assert counts["categories"] == 1
    assert counts["expenses"] == 1
    assert counts["recurring_expenses"] == 1
    assert counts["bills"] == 1
    assert counts["reminders"] == 1


def test_export_json_excludes_password_hash(client, app_fixture):
    auth = _register_login(client, email="export-json@example.com")
    _seed_user_data(app_fixture, auth["email"])
    r = client.get(
        "/gdpr/export?format=json",
        headers={"Authorization": auth["Authorization"]},
    )
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["schema_version"] == "1.0"
    assert payload["user"]["email"] == auth["email"]
    assert "password_hash" not in payload["user"]
    assert "password" not in json.dumps(payload)
    assert payload["counts"]["expenses"] == 1
    assert len(payload["expenses"]) == 1
    assert payload["expenses"][0]["notes"] == "lunch"

    with app_fixture.app_context():
        logs = db.session.query(GdprAuditLog).filter_by(action="PII_EXPORT").all()
        assert len(logs) >= 1
        assert logs[-1].email_hash == hash_email(auth["email"])


def test_export_zip_package(client, app_fixture):
    auth = _register_login(client, email="export-zip@example.com")
    _seed_user_data(app_fixture, auth["email"])
    r = client.get("/gdpr/export", headers={"Authorization": auth["Authorization"]})
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/zip")
    assert "attachment" in r.headers.get("Content-Disposition", "")
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "export.json" in names
        assert "expenses.csv" in names
        export = json.loads(zf.read("export.json"))
        assert export["user"]["email"] == auth["email"]
        assert "password_hash" not in export["user"]


def test_delete_requires_password_and_confirmation(client):
    auth = _register_login(client, email="delete-guard@example.com")
    headers = {"Authorization": auth["Authorization"]}

    r = client.post("/gdpr/delete-account", json={}, headers=headers)
    assert r.status_code == 400
    assert "password" in r.get_json()["error"]

    r = client.post(
        "/gdpr/delete-account",
        json={"password": auth["password"], "confirm": "nope"},
        headers=headers,
    )
    assert r.status_code == 400
    assert "confirmation" in r.get_json()["error"]

    r = client.post(
        "/gdpr/delete-account",
        json={
            "password": "wrong-password",
            "confirm": DELETE_CONFIRMATION_PHRASE,
        },
        headers=headers,
    )
    assert r.status_code == 401


def test_delete_is_irreversible_and_keeps_audit_trail(client, app_fixture):
    auth = _register_login(client, email="delete-me@example.com")
    user_id = _seed_user_data(app_fixture, auth["email"])
    headers = {"Authorization": auth["Authorization"]}

    # Create an export audit first
    r = client.get("/gdpr/export?format=json", headers=headers)
    assert r.status_code == 200

    r = client.post(
        "/gdpr/delete-account",
        json={
            "password": auth["password"],
            "confirm": DELETE_CONFIRMATION_PHRASE,
        },
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["message"] == "account permanently deleted"
    assert body["deleted"]["expenses"] == 1

    # User is gone
    r = client.get("/auth/me", headers=headers)
    assert r.status_code == 404

    with app_fixture.app_context():
        assert db.session.get(User, user_id) is None
        assert db.session.query(Expense).filter_by(user_id=user_id).count() == 0
        assert db.session.query(Category).filter_by(user_id=user_id).count() == 0
        assert db.session.query(Bill).filter_by(user_id=user_id).count() == 0
        assert db.session.query(Reminder).filter_by(user_id=user_id).count() == 0

        delete_logs = (
            db.session.query(GdprAuditLog)
            .filter_by(action="ACCOUNT_DELETE", user_id=user_id)
            .all()
        )
        assert len(delete_logs) == 1
        assert delete_logs[0].email_hash == hash_email(auth["email"])
        assert delete_logs[0].details is not None

        export_logs = (
            db.session.query(GdprAuditLog)
            .filter_by(action="PII_EXPORT", user_id=user_id)
            .all()
        )
        assert len(export_logs) >= 1


def test_audit_log_endpoint(client, app_fixture):
    auth = _register_login(client, email="audit@example.com")
    headers = {"Authorization": auth["Authorization"]}
    client.get("/gdpr/export?format=json", headers=headers)
    r = client.get("/gdpr/audit-log", headers=headers)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert len(items) >= 1
    assert items[0]["action"] == "PII_EXPORT"
    assert "email_hash" not in items[0]


def test_delete_revokes_refresh_session(client, app_fixture):
    auth = _register_login(client, email="revoke@example.com")
    headers = {"Authorization": auth["Authorization"]}
    refresh = auth["refresh"]

    r = client.post(
        "/gdpr/delete-account",
        json={
            "password": auth["password"],
            "confirm": DELETE_CONFIRMATION_PHRASE,
        },
        headers=headers,
    )
    assert r.status_code == 200

    r = client.post("/auth/refresh", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401
