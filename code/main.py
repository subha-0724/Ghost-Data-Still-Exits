"""Entry point: python code/main.py  ->  writes output.csv at the repository root."""
import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from audit.store import Store, read_csv          # noqa: E402
from audit.engine import Engine                  # noqa: E402


def run(dataset, requests_csv, out_path):
    store = Store(dataset)
    eng = Engine(store)
    cases = read_csv(Path(dataset) / requests_csv)
    # All supplied requests (public samples + evaluation set) compete for the same activity-log events, so
    # the global matching in prepare() must see them all.  Only the requested file is written out.
    pool = list(cases)
    seen = {c["case_id"] for c in cases}
    for other in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        p = Path(dataset) / other
        if other != requests_csv and p.exists():
            pool += [c for c in read_csv(p) if c["case_id"] not in seen]
    eng.prepare(pool)
    rows = []
    for c in sorted(cases, key=lambda c: c["case_id"]):
        r = eng.audit(c)
        rows.append({"case_id": r.case_id, "deletion_status": r.status,
                     "steps_json": json.dumps(r.steps, ensure_ascii=False, separators=(",", ":"))})
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)
    return rows, store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "dataset"))
    ap.add_argument("--requests", default="deletion_requests.csv")
    ap.add_argument("--out", default=str(ROOT / "output.csv"))
    a = ap.parse_args()
    rows, store = run(a.dataset, a.requests, a.out)
    from collections import Counter
    print(f"wrote {len(rows)} rows to {a.out}", dict(Counter(r["deletion_status"] for r in rows)))
    for w in store.warnings:
        print("warning:", w)


if __name__ == "__main__":
    main()
