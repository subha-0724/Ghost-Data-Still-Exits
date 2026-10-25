"""Case reasoning: link evidence to a person, rebuild state at audit_at, apply deletion_rules.csv,
and emit ordered findings / remediation / verification steps.

Everything is derived from dataset/ files.  No labels, case ids or resource ids are hard-coded.
"""
import re
from collections import defaultdict
from datetime import timedelta

from .identity import IdentityIndex, wants_deletion
from .util import parse_ts, norm_email, prefix_of, system_of, RID_RE

# ---- fixed vocabulary from problem_statement.md --------------------------------------------
FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFY_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
# remediation op -> verification op (the "required final state")
VERIFY_FOR = {"DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
              "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
              "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED"}


def rules_by_category(rules):
    return {r["data_category"]: r["required_action"] for r in rules}


class CaseResult:
    def __init__(self, case_id):
        self.case_id = case_id
        self.status = ""
        self.steps = []
        self.notes = []


class Engine:
    def __init__(self, store):
        self.s = store
        self.idx = IdentityIndex(store.identities, store.audit_log)
        self.rules = rules_by_category(store.rules)
        self._add_catalog_links()
        self.by_rid = defaultdict(list)
        for o in self.s.obs:
            self.by_rid[o["rid"]].append(o)
        self._acct_events = [a for a in store.activity if a["event_type"] == "DELETE_RECORD"
                             and a["source_system"] == "deletion_worker" and a["target_system"] == "account_service"
                             and a["resource_id"].startswith("account_")]
        self._anon_events = [a for a in store.activity if a["event_type"] == "ANONYMIZE_RECORD"
                             and a["target_system"] == "analytics_platform"]

    # ------------------------------------------------------------------ catalog link rows
    def _add_catalog_links(self):
        """LINK_RESOURCE_IDENTITY activity rows tie a resource to an email + user id.  They are the only
        textual bridge for evidence that exists as screenshots / PDFs, so they become observations tied to
        the evidence file captured just before the catalog entry."""
        from .evidence import make_obs
        files = sorted(self.s.files.items(), key=lambda kv: kv[1]["captured"])
        for a in self.s.activity:
            if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            m = re.search(r"linked (\S+) \(.*?\) to (\S+@\S+) and (user_\d+)", a["details"]) or \
                re.search(r"belongs only to (\S+@\S+) and (user_\d+)", a["details"])
            if not m:
                continue
            rid = a["resource_id"]
            groups = m.groups()
            email, user = (groups[-2], groups[-1])
            t = a["_ts"]
            best, bd = None, None
            for fid, f in files:
                d = abs((t - f["captured"]).total_seconds())
                if f["captured"] <= t and (bd is None or d < bd):
                    best, bd = fid, d
            if best is None or bd > 1800:
                continue
            o = make_obs(best, self.s.files[best]["captured"], rid, {"email": email}, "catalog")
            o["link"] |= {"u:" + user}
            o["present"] = True
            o["catalog"] = True
            o["kind_hint"] = "attachment" if "belongs only" in a["details"] else ""
            self.s.obs.append(o)

    # ------------------------------------------------------------------ helpers
    def _identity(self, case):
        uid, how, notes = self.idx.resolve(case["email"])
        keys = set()
        if uid:
            keys = self.idx.identifiers(uid)
            keys.add("u:" + uid)
        keys.add("e:" + norm_email(case["email"]))
        return uid, how, notes, keys

    @staticmethod
    def _strong(keys):
        return {k for k in keys if k[:2] in ("e:", "h:", "p:", "u:")}

    def _visible(self, o, case):
        # the observation itself must pre-date the audit cutoff (a later-exported log may still contain
        # earlier events; citing such a file is handled separately in _state)
        return o["ts"] is not None and o["ts"] <= case["_audit"]

    # ------------------------------------------------------------------ preparation (global)
    def prepare(self, cases):
        self.cases = cases
        for c in cases:
            c["_audit"] = parse_ts(c["audit_at"])
            c["_reported"] = parse_ts(c["reported_at"])
            c["_requested"] = parse_ts(c["requested_at"])
            c["_deletion"] = wants_deletion(c["request_text"])
            c["_uid"], c["_how"], c["_notes"], c["_keys"] = self._identity(c)
            c["_strong"] = self._strong(c["_keys"])
            c["_rids"] = self._linked_rids(c)
        self._assign_accounts()
        self._assign_anonymised_analytics()
        self._assign_orphan_controls()

    def _linked_rids(self, c):
        rids = set()
        for o in self.s.obs:
            if not self._visible(o, c):
                continue
            if o["link"] & c["_strong"]:
                rids.add(o["rid"])
        return rids

    def _assign_accounts(self):
        taken = set()
        for c in self.cases:
            c["_account"] = None
            accs = sorted(r for r in c["_rids"] if prefix_of(r) == "account")
            if c["_deletion"] and accs:
                c["_account"] = accs[0]
                c["_accounts"] = accs
                taken |= set(accs)
        pending = sorted((c for c in self.cases if c["_deletion"] and not c["_account"]),
                         key=lambda c: (c["_reported"], c["case_id"]))
        events = sorted((a for a in self._acct_events if a["resource_id"] not in taken), key=lambda a: a["_ts"])
        used = set()
        want = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}

        def result_ok(c, a):
            w = want.get(c["reported_status"])
            return w is None or a["reported_result"] == w

        def give(c, a):
            used.add(a["activity_id"])
            c["_account"] = a["resource_id"]
            c["_accounts"] = [a["resource_id"]]
            c["_account_event"] = a

        # pass 1: a deletion event reported within minutes of the workflow's reported_at
        for c in pending:
            near = [a for a in events if a["activity_id"] not in used and result_ok(c, a)
                    and abs((a["_ts"] - c["_reported"]).total_seconds()) <= 15 * 60]
            if near:
                give(c, min(near, key=lambda a: abs((a["_ts"] - c["_reported"]).total_seconds())))
        # pass 2: otherwise the earliest unclaimed event in the run-up to reported_at (order-preserving)
        for c in pending:
            if c["_account"]:
                continue
            lo, hi = c["_reported"] - timedelta(hours=3), c["_reported"] + timedelta(hours=1)
            for a in events:
                if a["activity_id"] not in used and lo <= a["_ts"] <= hi and result_ok(c, a):
                    give(c, a)
                    break

        # pass 3: relax the reported-result consistency check if nothing else fits
        for c in pending:
            if c["_account"]:
                continue
            lo, hi = c["_reported"] - timedelta(hours=3), c["_reported"] + timedelta(hours=1)
            for a in events:
                if a["activity_id"] not in used and lo <= a["_ts"] <= hi:
                    give(c, a)
                    break

    def _assign_anonymised_analytics(self):
        """Anonymised analytics profiles carry no identifier; the only bridge is the deletion worker's
        ANONYMIZE_RECORD event right after the case's account deletion."""
        linked_elsewhere = set()
        for c in self.cases:
            linked_elsewhere |= {r for r in c["_rids"] if prefix_of(r) == "analytics"}
        used = set()
        cs = sorted((c for c in self.cases if c["_deletion"] and c.get("_account_event")), key=lambda c: c["_account_event"]["_ts"])
        evs = sorted((a for a in self._anon_events if a["resource_id"] not in linked_elsewhere), key=lambda a: a["_ts"])
        for c in cs:
            t0 = c["_account_event"]["_ts"]
            c["_extra_rids"] = set()
            for a in evs:
                if a["activity_id"] in used:
                    continue
                if t0 <= a["_ts"] <= t0 + timedelta(hours=2):
                    # only usable if some evidence actually shows that profile
                    if self.by_rid.get(a["resource_id"]):
                        used.add(a["activity_id"])
                        c["_extra_rids"].add(a["resource_id"])
                        break

    def _assign_orphan_controls(self):
        """Backups / data flows whose evidence line carries no identifier are tied to the case through the
        deletion worker's CHECK_* event that follows the workflow's report ("remains enabled/restorable")."""
        linked = set()
        for c in self.cases:
            linked |= c["_rids"]
        evs = sorted((a for a in self.s.activity if a["event_type"] in ("CHECK_RESTORE_ACCESS", "CHECK_DATA_FLOW")
                      and a["resource_id"] not in linked and self.by_rid.get(a["resource_id"])), key=lambda a: a["_ts"])
        used = set()
        def n_controls(c):
            return sum(prefix_of(r) in ("backup", "data_flow") for r in c["_rids"])

        # cases that have no control resource yet are the likeliest owners of an unattributed one
        for c in sorted((c for c in self.cases if c["_deletion"]),
                        key=lambda c: (c["_reported"], n_controls(c), c["case_id"])):
            c.setdefault("_extra_rids", set())
            for a in evs:
                if a["activity_id"] in used:
                    continue
                if c["_reported"] <= a["_ts"] <= c["_reported"] + timedelta(hours=3):
                    kind = prefix_of(a["resource_id"])
                    if any(prefix_of(r) == kind for r in c["_rids"]):
                        continue
                    used.add(a["activity_id"])
                    c["_extra_rids"].add(a["resource_id"])
                    break

    # ------------------------------------------------------------------ state reconstruction
    def _state(self, rid, c):
        """Latest observation(s) of rid visible at audit_at."""
        obs = [o for o in self.by_rid.get(rid, []) if self._visible(o, c)]
        if not obs:
            return None
        citable = [o for o in obs if o.get("file_cap", o["ts"]) <= c["_audit"]]
        t = max(o["ts"] for o in obs)
        last = [o for o in obs if o["ts"] == t]
        st = {"rid": rid, "ts": t, "obs": last, "file": None}
        st["present"] = any(o["present"] is True for o in last) if any(o["present"] is not None for o in last) else None
        st["stored"] = set().union(*[o["stored"] for o in last])
        st["stored"] = {k for k in st["stored"] if k[:2] in ("e:", "h:", "p:", "n:", "x:")}
        en = [o["enabled"] for o in last if o["enabled"] is not None]
        st["enabled"] = any(en) if en else None
        rs = [o["restore"] for o in last if o["restore"] is not None]
        st["restore"] = any(rs) if rs else None
        # the kind of record (message vs attachment ...) is a property of the resource, not of one snapshot
        hints = {o["kind_hint"] for o in obs if o["kind_hint"]}
        st["hints"] = hints
        st["kinds"] = {o["src"] for o in obs}
        st["doc"] = " ".join(o.get("doc_text", "") for o in last).lower()
        # evidence to cite: latest observation in a file captured at/before audit_at (never later evidence);
        # among equals prefer the one that shows the worst-case (present / identifiers / active)
        st["file"] = None
        if citable:
            tc = max(o["ts"] for o in citable)
            cl = [o for o in citable if o["ts"] == tc]
            pick = sorted(cl, key=lambda o: (0 if (o["present"] or o["stored"] or o["enabled"] or o["restore"]) else 1,
                                             o["file_id"]))
            st["file"] = pick[0]["file_id"]
        return st

    def _classify(self, rid, st):
        """Return (violation, ok_state) for one resource per deletion_rules.csv."""
        p = prefix_of(rid)
        stored = st["stored"] if st else set()
        if p == "account":
            if st and st["present"]:
                return "REMAINING", None
            return None, "ABSENT"
        if p in ("search", "export", "marketing", "cache", "email_delivery"):
            if st and st["present"]:
                return "REMAINING", None
            return None, "ABSENT"
        if p == "support":
            if st is None or st["present"] is False:
                return None, "ABSENT"
            hints, kinds = st["hints"], st["kinds"]
            is_attachment = "attachment" in hints or bool(kinds & {"pdf", "image"})
            is_message = "message" in hints or "sql" in kinds
            if is_message and not is_attachment:
                return ("EXPOSED", None) if stored else (None, "REDACTED")
            # attachments / stand-alone support records belonging only to the subject are deleted whole
            return ("REMAINING", None) if (stored or st["present"]) else (None, "ABSENT")
        if p == "analytics" and st and "secondary" in st["hints"] and st["present"]:
            return "REMAINING", None        # secondary-identifier record still resolvable -> delete whole record
        if p in ("analytics", "tombstone"):
            if st and stored:
                return "EXPOSED", None
            if st and st["present"] is not False:
                return None, "ANONYMIZED" if p == "analytics" else "REDACTED"
            return None, "ABSENT"
        if p == "data_flow":
            en = st["enabled"] if st else None
            if en is None and st and st["present"]:
                en = not re.search(r"disabled|paused|stopped", st["doc"] or "x")
            if en:
                return "FLOW", None
            return (None, "DISABLED") if st else (None, None)
        if p == "backup":
            rs = st["restore"] if st else None
            if rs is None and st and st["present"]:
                rs = "blocked" not in (st["doc"] or "")
            if rs:
                return "RESTORE", None
            return (None, "BLOCKED") if st else (None, None)
        if p in ("audit_record", "legal_hold"):
            if st and st["present"] is not False:
                return None, "RETAINED"
            return None, None
        return None, None

    # ------------------------------------------------------------------ main per-case audit
    def audit(self, c):
        res = CaseResult(c["case_id"])
        if not c["_deletion"]:
            res.status = "NOT_APPLICABLE"
            return res
        rids = set(c["_rids"]) | set(c.get("_extra_rids", set()))
        if c.get("_account"):
            rids.add(c["_account"])
        # evidence older than the request cannot show the post-request state
        items = {}
        for rid in sorted(rids):
            st = self._state(rid, c)
            if st is not None and st["ts"] < c["_requested"] and prefix_of(rid) != "audit_record":
                st = None
            viol, ok = self._classify(rid, st)
            items[rid] = {"rid": rid, "st": st, "viol": viol, "ok": ok, "sys": system_of(rid), "pfx": prefix_of(rid)}
        findings, remed, verif = [], [], []
        primary = self._primary_file(c, items)
        for rid, it in items.items():
            ev = (it["st"]["file"] if it["st"] else None) or primary
            viol, ok, p = it["viol"], it["ok"], it["pfx"]
            if viol == "REMAINING":
                findings.append(("REPORT_REMAINING_RECORD", it, ev)); remed.append(("DELETE_RECORD", it))
            elif viol == "EXPOSED":
                findings.append(("REPORT_EXPOSED_PII", it, ev))
                remed.append(("ANONYMIZE_RECORD" if p == "analytics" else "REDACT_RECORD", it))
            elif viol == "FLOW":
                findings.append(("REPORT_ACTIVE_DATA_FLOW", it, ev)); remed.append(("DISABLE_DATA_FLOW", it))
            elif viol == "RESTORE":
                findings.append(("REPORT_RESTORE_RISK", it, ev)); remed.append(("BLOCK_RESTORE", it))
        incomplete = bool(findings)
        res.status = "INCOMPLETE" if incomplete else "COMPLETE"
        steps = []

        def add(phase, op, rid, ev):
            steps.append({"phase": phase, "system_id": system_of(rid), "resource_id": rid, "operation": op,
                          "state": STATE[op], "evidence_id": ev})

        if incomplete:
            for op, it, ev in sorted(findings, key=lambda x: (FINDING_ORDER.index(x[0]), x[1]["sys"], x[1]["rid"])):
                add("FINDING", op, it["rid"], ev)
            for op, it in sorted(remed, key=lambda x: (REMEDIATION_ORDER.index(x[0]), x[1]["sys"], x[1]["rid"])):
                add("REMEDIATION", op, it["rid"], "")
            vset = {}
            for op, it in remed:
                vset[(VERIFY_FOR[op], it["rid"])] = it
            for rid, it in items.items():
                if it["pfx"] == "account":
                    vset.setdefault(("VERIFY_RECORD_ABSENT", rid), it)
                if it["ok"] == "RETAINED" and it["pfx"] == "audit_record":
                    vset[("VERIFY_RECORD_PRESENT", rid)] = it
            for (op, rid), it in sorted(vset.items(), key=lambda x: (VERIFY_ORDER.index(x[0][0]), system_of(x[0][1]), x[0][1])):
                add("VERIFICATION", op, rid, "")
        else:
            vset = {}
            for rid, it in items.items():
                ok = it["ok"]
                if it["pfx"] == "account":
                    vset[("VERIFY_RECORD_ABSENT", rid)] = it
                elif ok == "RETAINED":
                    vset[("VERIFY_RECORD_PRESENT", rid)] = it
                elif ok == "REDACTED":
                    vset[("VERIFY_RECORD_REDACTED", rid)] = it
                elif ok == "ANONYMIZED":
                    vset[("VERIFY_RECORD_ANONYMIZED", rid)] = it
                elif ok == "DISABLED":
                    vset[("VERIFY_DATA_FLOW_DISABLED", rid)] = it
                elif ok == "BLOCKED":
                    vset[("VERIFY_RESTORE_BLOCKED", rid)] = it
            for (op, rid), it in sorted(vset.items(), key=lambda x: (VERIFY_ORDER.index(x[0][0]), system_of(x[0][1]), x[0][1])):
                ev = (it["st"]["file"] if it["st"] else None) or primary
                add("VERIFICATION", op, rid, ev)
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
        res.steps = [{"step_no": s["step_no"], "phase": s["phase"], "system_id": s["system_id"],
                      "resource_id": s["resource_id"], "operation": s["operation"], "state": s["state"],
                      "evidence_id": s["evidence_id"]} for s in steps]
        return res

    def _primary_file(self, c, items):
        """Evidence file that best represents the case: most observations of the case's resources."""
        cnt = defaultdict(int)
        latest = {}
        for it in items.values():
            if it["st"] and it["st"]["file"]:
                cnt[it["st"]["file"]] += 1
                latest[it["st"]["file"]] = it["st"]["ts"]
        if cnt:
            return sorted(cnt, key=lambda f: (-cnt[f], -latest[f].timestamp()))[0]
        # no observation at all: latest account-system snapshot not after audit_at
        best = None
        for fid, f in self.s.files.items():
            if f["captured"] <= c["_audit"] and ("account" in f["origin"] or "customer_accounts" in str(f["path"])):
                if best is None or f["captured"] > self.s.files[best]["captured"]:
                    best = fid
        return best or ""
