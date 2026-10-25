# Evaluation report

Reference answers used: `dataset/sample_output.csv` (32 public cases, organiser-supplied). They are used **only** by
`code/evaluation/main.py`; the prediction pipeline never reads them. The 518 evaluation cases have no public labels, so
no accuracy number can be reported for them (stated limitation, not estimated).

Reproduce: `python code/main.py --requests sample_deletion_requests.csv --out output_sample.csv` then
`python code/evaluation/main.py --verbose`.

## Case-level (32 sample cases)
- Status accuracy: **100.0%** (32/32)
- False COMPLETE (INCOMPLETE predicted as COMPLETE): **0**
- Per status (tp/fp/fn): {"COMPLETE": {"tp": 10, "fp": 0}, "INCOMPLETE": {"tp": 22, "fp": 0}}
- Exact case match (status and every step identical): 56.2%

## Step-level
- Step precision: 95.7%; step recall: 92.7%
- Recall ignoring `evidence_id`: 92.7%

## Field-level (on steps matched by phase+system+resource)
phase 100.0%, system_id 100.0%, resource_id 100.0%, operation 100.0%,
state 100.0%, evidence_id 100.0%

## Sequence accuracy
Mean longest-common-subsequence ratio between predicted and reference step arrays: **88.3%**.
Steps are always emitted in phase -> operation -> system_id -> resource_id order from the problem statement.

## Additional evaluation cases (created by us, `code/tests/synthetic.py`, run by `python -m unittest discover -s code/tests`)
1. **c1 residual data + active flow**: deleted account but a search entry and an enabled connector remain -> INCOMPLETE; findings cite evidence,
   remediation disables the flow before deleting, remediation/verification steps carry empty evidence_id.
2. **c2 historical email + tombstone**: request uses a previous email; the tombstone has no direct identifiers and the audit record must stay ->
   COMPLETE with VERIFY_RECORD_REDACTED (tombstone) and VERIFY_RECORD_PRESENT (audit), no delete of retained records.
3. **c3 non-deletion request** (marketing opt-out) -> NOT_APPLICABLE with `[]`.
4. **c4 later evidence** : a leftover record exists only in a file captured after audit_at -> ignored, case stays COMPLETE.
All 9 automated tests pass.

## Failures found and improvements made
- Records without explicit status fields were treated as absent -> false COMPLETE. Fixed: a record that exists in a snapshot/log is present.
- Evidence captured after `audit_at` was cited. Fixed: citations only from files captured at/before audit_at (log lines are
  still judged by their own timestamp).
- Images linked every identifier to every resource (case with another person's connector). Fixed: per-row association in OCR text.
- Support records: JSON tickets were treated as attachments (DELETE) instead of messages (REDACT). Fixed via `message_excerpt` kind detection.
- Deleted accounts carry no identifier in evidence; they are tied to cases through the deletion worker's activity (time window + reported_status->result consistency).
  Public-sample + evaluation requests are matched jointly.
- Backups/flows with anonymous log lines are tied via CHECK_* activity events.

## Known limitations
- Where several cases share the same `reported_at` hour, the account / anonymised-analytics resource for already-deleted records can
  be swapped between cases (no identifier exists to separate them). Status is unaffected; a few verification steps may name a neighbour's resource.
- Retained security audit records that appear in no visible evidence cannot be found, so some INCOMPLETE rows miss the VERIFY_RECORD_PRESENT step.
- 10 deletion cases have no account step because no unclaimed deletion event fit the window.
