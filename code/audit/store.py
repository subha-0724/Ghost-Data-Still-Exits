"""Load all participant-facing data from dataset/ and build the observation index."""
import csv
from collections import defaultdict
from pathlib import Path

from . import evidence as ev
from . import ocr
from .util import parse_ts


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class Store:
    def __init__(self, dataset_dir):
        d = Path(dataset_dir)
        self.dir = d
        self.identities = read_csv(d / "user_identities.csv")
        self.audit_log = read_csv(d / "user_audit_log.csv")
        self.activity = read_csv(d / "system_activity.csv")
        self.rules = read_csv(d / "deletion_rules.csv")
        self.manifest = read_csv(d / "evidence_files.csv")
        for a in self.activity:
            a["_ts"] = parse_ts(a["event_time"])
        self.files = {}
        self.obs = []
        self.warnings = []
        self._load_evidence()
        self.by_rid = defaultdict(list)
        for o in self.obs:
            self.by_rid[o["rid"]].append(o)

    def _load_evidence(self):
        for m in self.manifest:
            fid = m["file_id"]
            path = self.dir / m["file_path"]
            cap = parse_ts(m["captured_at"])
            self.files[fid] = {"path": path, "captured": cap, "origin": m["origin"]}
            if not path.exists():
                self.warnings.append(f"missing evidence file {path}")
                continue
            suf = path.suffix.lower()
            try:
                if suf == ".json":
                    obs = ev.parse_json_file(fid, path, cap)
                elif suf == ".sql":
                    obs = ev.parse_sql_file(fid, path, cap)
                elif suf == ".log":
                    obs = ev.parse_log_file(fid, path, cap)
                elif suf == ".txt":
                    obs = ev.parse_text_records(fid, path.read_text(encoding="utf-8"), cap, "text")
                elif suf == ".pdf":
                    obs = ev.parse_free_text(fid, ocr.pdf_text(path), cap, "pdf")
                elif suf in (".png", ".jpg", ".jpeg"):
                    obs = ev.parse_free_text(fid, ocr.image_text(path), cap, "image")
                else:
                    obs = []
            except Exception as e:  # keep going; record the problem
                self.warnings.append(f"{fid}: {type(e).__name__}: {e}")
                obs = []
            for o in obs:
                if o["ts"] is None:
                    o["ts"] = cap
                o["file_cap"] = cap
            self.obs.extend(obs)
