import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import synthetic                                       # noqa: E402
from audit.identity import IdentityIndex, wants_deletion   # noqa: E402
from audit.engine import FINDING_ORDER                 # noqa: E402
from main import run                                   # noqa: E402

ALLOWED = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


class Synthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        synthetic.build(cls.tmp.name)
        out = Path(cls.tmp.name) / "out.csv"
        rows, _ = run(cls.tmp.name, "deletion_requests.csv", out)
        cls.rows = {r["case_id"]: r for r in rows}
        cls.out = out

    def steps(self, c):
        return json.loads(self.rows[c]["steps_json"])

    def test_schema_and_coverage(self):
        with open(self.out, newline="", encoding="utf-8") as f:
            rd = csv.DictReader(f)
            self.assertEqual(rd.fieldnames, ["case_id", "deletion_status", "steps_json"])
            got = list(rd)
        self.assertEqual([r["case_id"] for r in got], sorted(r["case_id"] for r in got))
        self.assertEqual(len(got), 4)
        for r in got:
            self.assertIn(r["deletion_status"], ALLOWED)
            for i, s in enumerate(json.loads(r["steps_json"]), 1):
                self.assertEqual(s["step_no"], i)
                self.assertEqual(set(s), {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"})

    def test_remaining_data_is_incomplete_with_ordered_plan(self):
        self.assertEqual(self.rows["c1"]["deletion_status"], "INCOMPLETE")
        ops = [(s["phase"], s["operation"], s["resource_id"]) for s in self.steps("c1")]
        self.assertIn(("FINDING", "REPORT_REMAINING_RECORD", "search_9001"), ops)
        self.assertIn(("FINDING", "REPORT_ACTIVE_DATA_FLOW", "data_flow_9001"), ops)
        phases = [p for p, _, _ in ops]
        self.assertEqual(phases, sorted(phases, key=["FINDING", "REMEDIATION", "VERIFICATION"].index))
        # data flows are disabled before records are deleted
        rem = [o for p, o, _ in ops if p == "REMEDIATION"]
        self.assertLess(rem.index("DISABLE_DATA_FLOW"), rem.index("DELETE_RECORD"))
        for s in self.steps("c1"):
            if s["phase"] != "FINDING":
                self.assertEqual(s["evidence_id"], "")
            else:
                self.assertTrue(s["evidence_id"])

    def test_historical_email_and_tombstone_retention(self):
        self.assertEqual(self.rows["c2"]["deletion_status"], "COMPLETE")
        ops = {(s["operation"], s["resource_id"]) for s in self.steps("c2")}
        self.assertIn(("VERIFY_RECORD_REDACTED", "tombstone_9002"), ops)
        self.assertIn(("VERIFY_RECORD_PRESENT", "audit_record_9002"), ops)
        self.assertNotIn("DELETE_RECORD", {o for o, _ in ops})

    def test_non_deletion_request(self):
        self.assertEqual(self.rows["c3"]["deletion_status"], "NOT_APPLICABLE")
        self.assertEqual(self.steps("c3"), [])

    def test_evidence_after_audit_is_ignored(self):
        # search_9004 only appears in a file captured after audit_at -> must not create a finding
        self.assertEqual(self.rows["c4"]["deletion_status"], "COMPLETE")
        self.assertNotIn("search_9004", self.rows["c4"]["steps_json"])


class Units(unittest.TestCase):
    def test_intent(self):
        self.assertTrue(wants_deletion("Please erase the account linked to this email address."))
        self.assertTrue(wants_deletion("Je demande la suppression définitive du compte."))
        self.assertFalse(wants_deletion("Please remove me from marketing lists only."))
        self.assertFalse(wants_deletion("This is an information request, not a request to erase it."))

    def test_identity_current_and_historical(self):
        idx = IdentityIndex([{"user_id": "u1", "name": "A", "email": "new@x.com", "phone": "+1 555 0100",
                              "email_hash": "h", "updated_at": ""}],
                            [{"audit_id": "a", "user_id": "u1", "event_time": "", "field_name": "email",
                              "old_value": "old@x.com", "new_value": "new@x.com"}])
        self.assertEqual(idx.resolve("NEW@x.com")[0], "u1")
        self.assertEqual(idx.resolve("old@x.com")[:2], ("u1", "historical_email"))
        self.assertIsNone(idx.resolve("zzz@x.com")[0])
        self.assertIn("e:old@x.com", idx.identifiers("u1"))

    def test_operation_order_constant(self):
        self.assertEqual(FINDING_ORDER[0], "REPORT_REMAINING_RECORD")


class RealDataset(unittest.TestCase):
    def test_full_run_if_dataset_present(self):
        ds = HERE.parents[1] / "dataset"
        if not (ds / "deletion_requests.csv").exists():
            self.skipTest("dataset/ not present")
        with tempfile.TemporaryDirectory() as t:
            rows, _ = run(ds, "deletion_requests.csv", Path(t) / "o.csv")
        n = sum(1 for _ in csv.DictReader(open(ds / "deletion_requests.csv", encoding="utf-8")))
        self.assertEqual(len(rows), n)
        self.assertEqual(len({r["case_id"] for r in rows}), n)


if __name__ == "__main__":
    unittest.main()
