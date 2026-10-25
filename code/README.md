# Ghost Data Still Exists - deletion audit agent

Deterministic evidence-based audit agent (no paid API, no secrets).

## Approach
1. `audit/identity.py` resolves the request email to a user (current or historical email) and collects all current + historical
   emails, hashes, phones, names. Request text is classified (multilingual); explicit non-deletion intent -> `NOT_APPLICABLE`.
2. `audit/evidence.py` normalises every evidence format (logs of 6 styles, JSON, SQLite SQL replicas, handover text, PDF, PNG via OCR)
   into observations (resource, time, identifiers, present/enabled/restore flags).
3. `audit/engine.py` links observations to the person (identifiers, `user_N` references, catalog link rows, deletion-worker activity),
   rebuilds each resource's latest state at `audit_at` (later evidence ignored, never cited), applies `deletion_rules.csv`
   (delete / redact / anonymise / retain / tombstone) and emits ordered FINDING -> REMEDIATION -> VERIFICATION steps.
   `reported_status` and activity results are never trusted as proof of state. COMPLETE only if no violation is found.

## Run (Windows PowerShell, from the repo root)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r code\requirements.txt
python code\main.py                     # writes output.csv at the repo root
python -m unittest discover -s code\tests
python code\main.py --requests sample_deletion_requests.csv --out output_sample.csv
python code\evaluation\main.py --verbose
```
Images are read from `code/cache/ocr_cache.json` (keyed by file hash); install Tesseract + `pytesseract pillow` only if you add new images.

Layout: `code/main.py`, `code/audit/`, `code/evaluation/` (evaluator + reports), `code/tests/`.
