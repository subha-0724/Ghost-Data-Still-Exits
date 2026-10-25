"""Turn every supplied evidence file into a flat list of observations.

An observation says: "at time ts, evidence file F showed resource R in this state,
associated with these identifiers".  Nothing here knows about cases or policy; it only
normalises formats (logs, JSON, SQLite SQL snapshots, handover text, PDF/PNG text).
"""
import json
import re
import sqlite3
from pathlib import Path

from .util import (EMAIL_RE, USER_RE, HASH_RE, RID_RE, parse_ts, norm_email, norm_phone,
                   norm_name, system_of, prefix_of)

# keys whose values are only the *query* used to find a record, not data stored in it
LOOKUP_KEYS = {"lookup_key", "match_key", "scan_key", "correlation_key"}
NAME_KEYS = {"name", "full_name", "display_name", "requester_name", "customer_name"}
PHONE_KEYS = {"phone", "requester_phone", "owner_phone", "customer_phone"}
TRUE = {"true", "1", "yes", "enabled", "active", "allowed", "hit", "found"}
FALSE = {"false", "0", "no", "disabled", "blocked", "stopped", "miss", "not_found", "none", "null", ""}

KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\[[^\]]*\]|[^\s"]+)')


def _clean(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = v.strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        v = v.replace('\\"', '"')
        if v.lower() in ("null", "none", ""):
            return None
    return v


def flatten(obj, out=None):
    """Leaf scalars of nested dicts (first non-null value wins); lists of dicts are skipped."""
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                flatten(v, out)
            elif isinstance(v, list):
                if v and all(not isinstance(x, (dict, list)) for x in v):
                    out.setdefault(k, ",".join(str(x) for x in v))
            else:
                v = _clean(v)
                if k not in out or out[k] is None:
                    out[k] = v
    return out


def idents_from(fields):
    """Return (stored, link, refs) identifier sets from a flat field dict."""
    stored, link, refs = set(), set(), set()
    for k, v in fields.items():
        if v is None:
            continue
        s = str(v)
        keyl = k.lower()
        found = set()
        for e in EMAIL_RE.findall(s):
            found.add("e:" + norm_email(e))
        for h in HASH_RE.findall(s.lower()):
            found.add("h:" + h)
        if keyl in PHONE_KEYS and norm_phone(s):
            found.add("p:" + norm_phone(s))
        if keyl in NAME_KEYS and s and not s.startswith(("user_", "account_")):
            found.add("n:" + norm_name(s))
        for u in USER_RE.findall(s):
            refs.add(u)
        link |= found
        if keyl not in LOOKUP_KEYS and keyl not in ("subject_reference",):
            stored |= found
    link |= {"u:" + u for u in refs}
    return stored, link, refs


def _bool(v):
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in TRUE:
        return True
    if s in FALSE:
        return False
    return None


def make_obs(file_id, ts, rid, fields, src, table="", kind_hint=""):
    stored, link, refs = idents_from(fields)
    o = {"file_id": file_id, "ts": ts, "rid": rid, "system": system_of(rid), "src": src, "table": table,
         "stored": stored, "link": link, "refs": refs, "kind_hint": kind_hint, "state": None,
         "present": None, "enabled": None, "restore": None, "fields": fields}
    f = {k.lower(): v for k, v in fields.items()}
    # --- existence ---
    for key in ("http_status", "status_code"):
        if f.get(key) is not None:
            try:
                o["present"] = int(float(f[key])) < 400
            except ValueError:
                pass
    if f.get("rows") is not None:
        try:
            o["present"] = int(float(f["rows"])) > 0
        except ValueError:
            pass
    if f.get("total_hits") is not None:
        try:
            o["present"] = int(float(f["total_hits"])) > 0
        except ValueError:
            pass
    res = (f.get("result") or "").upper() if isinstance(f.get("result"), str) else ""
    if res in ("FOUND", "HIT"):
        o["present"] = True
    elif res in ("NOT_FOUND", "MISS"):
        o["present"] = False
    if "archive_present" in f and _bool(f["archive_present"]) is not None:
        o["present"] = _bool(f["archive_present"])
    # --- control state ---
    if "enabled" in f:
        o["enabled"] = _bool(f["enabled"])
    if "eligible" in f and "restore_allowed" not in f:
        o["restore"] = bool(_bool(f["eligible"]) and not _bool(f.get("deletion_block")))
    if "restore_allowed" in f:
        o["restore"] = _bool(f["restore_allowed"])
    if "download_available" in f:
        o["dl"] = _bool(f["download_available"])
    if "message_excerpt" in f:
        o["kind_hint"] = "message"
    st = f.get("state") or f.get("status_text") or (res if res not in ("FOUND", "HIT", "NOT_FOUND", "MISS") else "")
    if isinstance(st, str) and st:
        o["state"] = st.upper()
    return o


def _apply_state_word(o):
    """Handover / ledger style words: IDENTIFIABLE, ANONYMIZED, REDACTED, ACTIVE, BLOCKED, DISABLED..."""
    s = o.get("state") or ""
    if s in ("ACTIVE", "ENABLED"):
        pfx = prefix_of(o["rid"])
        if pfx == "backup":
            o["restore"] = True
        elif pfx == "data_flow":
            o["enabled"] = True
    elif s in ("BLOCKED",):
        o["restore"] = False
    elif s in ("DISABLED",):
        o["enabled"] = False
    if s in ("IDENTIFIABLE",):
        o["stored"] = o["stored"] | {"x:identifiable"}
    return o


# ----------------------------------------------------------------------------- JSON
def _walk_json(node, ctx, file_id, out, src):
    if isinstance(node, dict):
        c = dict(ctx)
        for k in ("captured_at", "exported_at", "observed_at", "recorded_at"):
            if isinstance(node.get(k), str) and parse_ts(node[k]):
                c["ts"] = parse_ts(node[k])
        if "data_store" in node:
            c["store"] = node["data_store"]
        if "collection" in node:
            c["collection"] = node["collection"]
        rid = node.get("resource_id")
        if isinstance(rid, str) and RID_RE.fullmatch(rid):
            fields = flatten(node)
            if "profile" in node and node["profile"] is None:
                fields["profile_null"] = "true"
            o = make_obs(file_id, c.get("ts"), rid, fields, src, table=str(c.get("collection", "")))
            if node.get("profile", 1) is None:
                o["present"] = False
            if "profile" in node and node["profile"] is None:
                o["present"] = False
            o["collection"] = c.get("collection", "")
            if o["present"] is None:
                o["present"] = True
            out.append(_apply_state_word(o))
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                _walk_json(v, c, file_id, out, src)
    elif isinstance(node, list):
        for v in node:
            _walk_json(v, ctx, file_id, out, src)


def parse_json_file(file_id, path, captured):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    _walk_json(data, {"ts": captured}, file_id, out, "json")
    return out


# ----------------------------------------------------------------------------- SQL
def parse_sql_file(file_id, path, captured):
    text = Path(path).read_text(encoding="utf-8")
    m = re.search(r"Captured at:\s*(\S+)", text) or re.search(r"snapshot_completed_at=(\S+)", text)
    ts = parse_ts(m.group(1)) if m else captured
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(text)
    except sqlite3.Error:
        # fall back: execute statement by statement, skipping failures
        for stmt in re.split(r";\s*\n", text):
            try:
                con.execute(stmt)
            except sqlite3.Error:
                pass
    con.row_factory = sqlite3.Row
    out = []
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    for t in tables:
        cols = [r[1] for r in con.execute(f'pragma table_info("{t}")')]
        if "resource_id" not in cols:
            continue
        for row in con.execute(f'select * from "{t}"'):
            d = dict(row)
            fields = {}
            for k, v in d.items():
                if isinstance(v, str) and v.startswith("{"):
                    try:
                        fields.update(flatten(json.loads(v)))
                        continue
                    except ValueError:
                        pass
                fields[k] = _clean(v) if isinstance(v, str) else v
            rid = d["resource_id"]
            if not isinstance(rid, str) or not RID_RE.fullmatch(rid):
                continue
            hint = ""
            if t == "support_records":
                hint = "support_record"
            o = make_obs(file_id, ts, rid, {k: v for k, v in fields.items() if k != "resource_id"}, "sql", table=t,
                         kind_hint=hint)
            o["present"] = True  # a row exists in this table
            if "account_status" in fields and str(fields["account_status"]).upper() == "DELETED" \
                    and prefix_of(rid) == "account":
                o["present"] = False
            out.append(_apply_state_word(o))
    con.close()
    return out


# ----------------------------------------------------------------------------- logs
def _kv(s):
    return {k: _clean(v) for k, v in KV_RE.findall(s)}


def parse_log_line(line):
    line = line.rstrip("\n")
    if not line.strip():
        return None
    ts_tok = line.split(None, 1)[0]
    ts = parse_ts(ts_tok)
    if ts is None:
        return None
    rest = line[len(ts_tok):].strip()
    d = {}
    event = None
    service = None
    trace = None
    jstart = rest.find("{")
    if rest.startswith("{") or (jstart >= 0 and rest[:jstart].strip() == ""):
        try:
            j = json.loads(rest[jstart:])
            d = {k: _clean(v) for k, v in j.items()}
            event = d.get("event")
            service = d.get("service")
            trace = d.get("trace_id")
        except ValueError:
            pass
    elif 'message="' in rest:  # cloud runtime export
        head, _, msg = rest.partition('message="')
        msg = msg.rstrip().rstrip('"').replace('\\"', '"')
        d = _kv(head)
        d.update(_kv(msg))
        event = d.get("event")
        service = d.get("function")
        trace = d.get("requestId")
    elif " | " in rest:  # operations stream
        parts = [p.strip() for p in rest.split(" | ")]
        d = _kv(parts[-1]) if len(parts) > 1 else {}
        if len(parts) >= 6:
            service, trace, event = parts[2], parts[3], parts[4]
            d.update(_kv(parts[5]))
        else:
            d.update(_kv(rest))
    elif re.match(r"\[[A-Z]+\] \[", rest):  # application trace
        m = re.match(r"\[(\w+)\] \[([^\]]+)\] \[([^\]]+)\] (\w+):\s*(.*)", rest)
        if m:
            service, trace, event = m.group(2), m.group(3), m.group(4)
            d = _kv(m.group(5))
    else:
        d = _kv(rest)
        m = re.match(r"<\d+>1 \S+ (\S+) (\S+) ", rest)  # syslog
        if m:
            service, trace = m.group(1), m.group(2)
        event = d.get("event")
        service = d.get("service") or service
        trace = d.get("trace_id") or trace
    d["_service"] = service
    d["_event"] = event
    d["_trace"] = trace
    return ts, d


def parse_log_file(file_id, path, captured):
    groups = {}
    order = []
    singles = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        r = parse_log_line(line)
        if not r:
            continue
        ts, d = r
        tr = d.get("_trace")
        if tr and tr not in ("-",) and not (d.get("_event") in ("export_started", "export_completed")):
            if tr not in groups:
                groups[tr] = []
                order.append(tr)
            groups[tr].append((ts, d))
        else:
            singles.append((ts, d))
    out = []

    def emit(ts, d, ctx):
        rid = d.get("resource_id")
        if not rid or not RID_RE.fullmatch(rid):
            return
        fields = dict(ctx)
        fields.update({k: v for k, v in d.items() if not k.startswith("_") and v is not None})
        ev = d.get("_event") or ""
        hint = ""
        if "attachment" in ev or "attachment" in str(ctx.get("_events", "")):
            hint = "attachment"
        elif "message" in ev or "ticket" in ev or "message_text" in fields:
            hint = "message"
        elif "contact_lookup" in ev:
            hint = "secondary"      # a lookup that still resolves by a secondary identifier (e.g. email hash)
        fields.pop("_events", None)
        o = make_obs(file_id, ts, rid, fields, "log", kind_hint=hint)
        if "message_excerpt" in fields:
            o["kind_hint"] = "message"
        o["event"] = ev
        if ev.endswith("_started") or ev in ("profile_lookup_started",):
            return
        if o["present"] is None and o["enabled"] is None and o["restore"] is None:
            o["present"] = True
        out.append(_apply_state_word(o))

    for tr in order:
        lines = groups[tr]
        ctx = {}
        evs = []
        for ts, d in lines:
            evs.append(d.get("_event") or "")
            for k in LOOKUP_KEYS:
                if d.get(k):
                    ctx[k] = d[k]
        ctx["_events"] = ",".join(evs)
        for ts, d in lines:
            emit(ts, d, ctx)
    for ts, d in singles:
        emit(ts, d, {})
    return out


# ----------------------------------------------------------------------------- handover text / OCR text
HANDOVER_RE = re.compile(r"^-\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(.*)$")


def parse_text_records(file_id, text, captured, src):
    out = []
    for line in text.splitlines():
        m = HANDOVER_RE.match(line.strip())
        if not m:
            continue
        ts, system, rid, rtype, state, ident = m.groups()
        fields = {"record_type": rtype, "state": state, "subject_reference": ident.strip()}
        o = make_obs(file_id, parse_ts(ts) or captured, rid, fields, src)
        o["state"] = state.upper()
        if state.upper() == "FOUND":
            o["present"] = True
        elif state.upper() == "NOT_FOUND":
            o["present"] = False
        if rtype == "SUPPORT_ATTACHMENT":
            o["kind_hint"] = "attachment"
        elif rtype == "SUPPORT_MESSAGE":
            o["kind_hint"] = "message"
        o["record_type"] = rtype
        out.append(_apply_state_word(o))
    return out


def parse_free_text(file_id, text, captured, src):
    """PDF / image text.  A resource id is associated only with identifiers on its own line (table
    row) -- or, for single-record documents, with the whole document -- never with every identifier."""
    out = []
    lines = text.splitlines()
    rid_lines = {}
    for i, ln in enumerate(lines):
        for m in RID_RE.finditer(ln):
            rid_lines.setdefault(m.group(0), []).append(i)
    n_rids = len(rid_lines)
    for rid, idxs in sorted(rid_lines.items()):
        if n_rids <= 2:
            scope = text
        else:
            scope = "\n".join(lines[j] for i in idxs for j in (i,))
        stored, link, refs = idents_from({"text": scope})
        o = make_obs(file_id, captured, rid, {}, src)
        o["stored"], o["link"], o["refs"] = set(stored), set(link), set(refs)
        o["present"] = True
        o["doc_text"] = scope
        out.append(o)
    return out
