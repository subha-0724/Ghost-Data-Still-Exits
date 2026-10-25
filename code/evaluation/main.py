"""Compare predictions with sample_output.csv (reference answers supplied by the organisers).

This script is evaluation-only; the production pipeline never reads reference answers.
usage: python code/evaluation/main.py [--pred output_sample.csv] [--ref dataset/sample_output.csv] [--verbose]
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"] or "[]"))
    return out


def key(s):
    return tuple(s[k] for k in FIELDS)


def evaluate(pred, ref, verbose=False):
    cases = sorted(ref)
    m = Counter()
    per_status = defaultdict(Counter)
    field_hits, field_tot = Counter(), Counter()
    seq_ok = 0
    exact = 0
    for c in cases:
        rs, rsteps = ref[c]
        ps, psteps = pred.get(c, ("MISSING", []))
        m["cases"] += 1
        m["status_ok"] += rs == ps
        per_status[rs]["tp" if rs == ps else "fn"] += 1
        per_status[ps]["fp"] += rs != ps
        if rs != "COMPLETE" and ps == "COMPLETE":
            m["false_complete"] += 1
        rk, pk = [key(s) for s in rsteps], [key(s) for s in psteps]
        m["ref_steps"] += len(rk)
        m["pred_steps"] += len(pk)
        common = Counter(rk) & Counter(pk)
        m["step_match"] += sum(common.values())
        # identity-free match (ignore evidence id) to separate evidence errors from discovery errors
        rk2, pk2 = [k[:5] for k in rk], [k[:5] for k in pk]
        m["step_match_no_evidence"] += sum((Counter(rk2) & Counter(pk2)).values())
        rmap = {k[:3]: k for k in rk}
        for k in pk:
            if k[:3] in rmap:
                for i, f in enumerate(FIELDS):
                    field_tot[f] += 1
                    field_hits[f] += k[i] == rmap[k[:3]][i]
        if rk == pk and rs == ps:
            exact += 1
        # ordering: longest common subsequence ratio over matched steps
        seq_ok += lcs(rk, pk) / max(len(rk), len(pk), 1)
        if verbose and (rk != pk or rs != ps):
            print(f"\n{c}: ref={rs} pred={ps}")
            for k in rk:
                if k not in pk:
                    print("   missing :", k)
            for k in pk:
                if k not in rk:
                    print("   extra   :", k)
    n = m["cases"]
    return {
        "cases": n, "status_accuracy": m["status_ok"] / n, "false_complete": m["false_complete"],
        "exact_case_match": exact / n,
        "step_precision": m["step_match"] / max(m["pred_steps"], 1), "step_recall": m["step_match"] / max(m["ref_steps"], 1),
        "step_recall_ignoring_evidence_id": m["step_match_no_evidence"] / max(m["ref_steps"], 1),
        "field_accuracy": {f: field_hits[f] / max(field_tot[f], 1) for f in FIELDS},
        "sequence_accuracy": seq_ok / n,
        "per_status": {k: dict(v) for k, v in per_status.items()},
    }


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default=str(ROOT / "output_sample.csv"))
    ap.add_argument("--ref", default=str(ROOT / "dataset" / "sample_output.csv"))
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    print(json.dumps(evaluate(load(a.pred), load(a.ref), a.verbose), indent=2))
