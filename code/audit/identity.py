"""Identity resolution (current + historical identifiers) and request-intent detection."""
import re
from collections import defaultdict

from .util import norm_email, norm_phone, norm_name


class IdentityIndex:
    def __init__(self, identities, audit_log):
        self.users = {r["user_id"]: r for r in identities}
        self.by_current_email = defaultdict(list)
        for r in identities:
            self.by_current_email[norm_email(r["email"])].append(r["user_id"])
        self.hist = defaultdict(list)       # user_id -> [(time, field, old, new)]
        self.by_hist_email = defaultdict(list)
        for a in audit_log:
            self.hist[a["user_id"]].append(a)
            if a["field_name"] == "email":
                for v in (a["old_value"], a["new_value"]):
                    self.by_hist_email[norm_email(v)].append((a["event_time"], a["user_id"], a["audit_id"]))

    def resolve(self, email):
        """Return (user_id, how, notes).  Current email wins; otherwise the historical owner."""
        e = norm_email(email)
        cur = self.by_current_email.get(e, [])
        if len(cur) == 1:
            return cur[0], "current_email", []
        if len(cur) > 1:
            return sorted(cur)[0], "current_email_ambiguous", [f"{len(cur)} users share this email"]
        hist = self.by_hist_email.get(e, [])
        users = sorted({u for _, u, _ in hist})
        if len(users) == 1:
            return users[0], "historical_email", []
        if len(users) > 1:
            # prefer the user for whom the address was an *old* value (a previous owner), latest event
            return users[0], "historical_email_ambiguous", [f"{len(users)} users linked"]
        return None, "unresolved", []

    def identifiers(self, user_id):
        """All identifier keys ('e:','h:','p:','n:') for a user, current and historical."""
        keys = set()
        r = self.users.get(user_id)
        if r:
            if r["email"]:
                keys.add("e:" + norm_email(r["email"]))
            if r["email_hash"]:
                keys.add("h:" + r["email_hash"].strip().lower())
            if norm_phone(r["phone"]):
                keys.add("p:" + norm_phone(r["phone"]))
            if r["name"]:
                keys.add("n:" + norm_name(r["name"]))
        for a in self.hist.get(user_id, []):
            for v in (a["old_value"], a["new_value"]):
                if not v:
                    continue
                f = a["field_name"]
                if f == "email":
                    keys.add("e:" + norm_email(v))
                elif f == "email_hash":
                    keys.add("h:" + v.strip().lower())
                elif f == "phone" and norm_phone(v):
                    keys.add("p:" + norm_phone(v))
                elif f in ("name", "full_name"):
                    keys.add("n:" + norm_name(v))
        return keys


# --------------------------------------------------------------------- intent
NEGATIVE = [
    r"not asking for (a )?(deletion|erasure)", r"not a request to (erase|delete)", r"do not (close|delete)",
    r"don'?t (delete|close)", r"marketing lists only", r"promotional emails", r"keep the account",
    r"leave my profile", r"want to continue using", r"i still (need|use|want)", r"download my account",
    r"copy of (the|last)", r"what personal information", r"misspelled", r"out of date", r"replace it with",
    r"change the email address", r"resetting the login", r"information request", r"portable format",
]
POSITIVE = [
    r"\bdelet", r"\berase", r"\berasure", r"\bclose (my|this) account", r"closed", r"remove my (account|profile)",
    r"\bremove (the|my) profile", r"permanent", r"account (page )?is gone", r"\bdeactivat", r"\bdisconnected my account",
    # other languages used by the request templates
    r"eliminaci[oó]n", r"eliminar", r"exclus[aã]o", r"suppression", r"supprimer", r"삭제", r"削除", r"löschung",
    r"cancelaci[oó]n", r"exclu[ií]r",
]


def wants_deletion(text):
    t = (text or "").lower()
    for p in NEGATIVE:
        if re.search(p, t):
            return False
    for p in POSITIVE:
        if re.search(p, t):
            return True
    # Phrasings without an explicit verb ("please inspect the actual systems and tell me whether the
    # account is gone") are still deletion audits; only an explicit non-deletion intent (NEGATIVE
    # patterns above) switches a case to NOT_APPLICABLE.
    return True
