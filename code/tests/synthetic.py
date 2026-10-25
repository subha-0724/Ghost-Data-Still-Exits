"""Builds a tiny synthetic dataset (fictional people) used by tests and custom evaluation cases."""
import csv
import json
from pathlib import Path

REQ = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]


def w(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(header)
        cw.writerows(rows)


def build(d):
    d = Path(d)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    w(d / "user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"], [
        ["user_901", "Ada Test", "ada.test@example.com", "+1 555 0101", "a" * 64, "2026-01-01T00:00:00Z"],
        ["user_902", "Ben Test", "ben.new@example.com", "+1 555 0102", "b" * 64, "2026-01-01T00:00:00Z"],
        ["user_903", "Cy Test", "cy.test@example.com", "+1 555 0103", "c" * 64, "2026-01-01T00:00:00Z"],
        ["user_904", "Di Test", "di.test@example.com", "+1 555 0104", "d" * 64, "2026-01-01T00:00:00Z"]])
    w(d / "user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
      [["audit_9", "user_902", "2026-02-01T00:00:00Z", "email", "ben.old@example.com", "ben.new@example.com"]])
    w(d / "system_activity.csv", ["activity_id", "event_time", "event_type", "source_system", "target_system",
                                  "resource_id", "reported_result", "details"], [])
    w(d / "deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [])
    w(d / "evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [
        ["evidence_01", "evidence/s.json", "t", "2026-09-10T12:00:00Z"],
        ["evidence_02", "evidence/late.json", "t", "2026-09-20T12:00:00Z"]])
    snap = {"captured_at": "2026-09-10T12:00:00Z", "records": [
        {"resource_id": "account_9001", "profile": None, "status_code": 404, "observed_at": "2026-09-10T11:00:00Z",
         "email": "ada.test@example.com"},
        {"resource_id": "search_9001", "email": "ada.test@example.com", "observed_at": "2026-09-10T11:00:00Z"},
        {"resource_id": "data_flow_9001", "customer_email": "ada.test@example.com", "enabled": True,
         "observed_at": "2026-09-10T11:00:00Z"},
        {"resource_id": "audit_record_9001", "subject_reference": "user_901", "observed_at": "2026-09-10T11:00:00Z"},
        {"resource_id": "account_9002", "profile": None, "status_code": 404, "observed_at": "2026-09-10T11:00:00Z",
         "email": "ben.old@example.com"},
        {"resource_id": "tombstone_9002", "subject_reference": "user_902", "name": None, "email": None,
         "phone": None, "email_hash": None, "observed_at": "2026-09-10T11:00:00Z"},
        {"resource_id": "audit_record_9002", "subject_reference": "user_902", "observed_at": "2026-09-10T11:00:00Z"}]}
    late = {"captured_at": "2026-09-20T12:00:00Z", "records": [
        {"resource_id": "search_9004", "email": "di.test@example.com", "observed_at": "2026-09-20T11:00:00Z"}]}
    (d / "evidence/s.json").write_text(json.dumps(snap), encoding="utf-8")
    (d / "evidence/late.json").write_text(json.dumps(late), encoding="utf-8")
    txt = "Please delete my account and personal data."
    w(d / "deletion_requests.csv", REQ, [
        ["c1", "ada.test@example.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-10T12:00:00Z", txt],
        ["c2", "ben.old@example.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-10T12:00:00Z", txt],
        ["c3", "cy.test@example.com", "2026-09-01T00:00:00Z", "NOT_STARTED", "2026-09-02T00:00:00Z", "2026-09-10T12:00:00Z",
         "Please stop the promotional emails. I still need the account, so I am not asking for deletion."],
        ["c4", "di.test@example.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-10T12:00:00Z", txt]])
