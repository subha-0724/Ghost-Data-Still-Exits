"""Small shared helpers: time parsing, identifier normalisation, resource-id -> system map."""
import re
from datetime import datetime, timezone

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
RID_RE = re.compile(
    r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|legal_hold|"
    r"marketing|object|email_delivery|cache|identifier)_(\d+)\b")

PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service", "support": "support_platform",
    "analytics": "analytics_platform", "export": "export_service", "data_flow": "integration_service",
    "backup": "backup_service", "audit_record": "security_service", "tombstone": "identity_service",
    "legal_hold": "legal_service", "marketing": "marketing_platform", "object": "object_storage",
    "email_delivery": "email_delivery_service", "cache": "cache_service",
}


def prefix_of(rid):
    m = re.match(r"([a-z_]+?)_\d+$", rid or "")
    return m.group(1) if m else ""


def system_of(rid):
    return PREFIX_SYSTEM.get(prefix_of(rid), "")


def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""


def norm_email(e):
    return (e or "").strip().lower()


def norm_phone(p):
    d = re.sub(r"\D", "", p or "")
    return d if len(d) >= 7 else ""


def norm_name(n):
    return re.sub(r"\s+", " ", (n or "").strip().lower())
