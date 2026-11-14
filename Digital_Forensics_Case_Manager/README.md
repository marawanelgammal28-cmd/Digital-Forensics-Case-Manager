# Digital Forensics Case Manager (DFCM)

A local-first educational Flask application for organising digital-forensics case records, evidence metadata, SHA-256 hashes and investigative notes.

## Features
- Create investigation cases and change case status.
- Register evidence files from a controlled extension allowlist.
- Calculate SHA-256 over each uploaded file and store the hash with evidence metadata.
- Store case records, evidence metadata and notes in SQLite.
- Store uploaded copies in a local evidence folder.
- Input validation, parameterised SQL queries, CSRF tokens, upload size limit, random stored filenames and safe download handling.
- Responsive dark dashboard.

## Important scope and limitations
This is a case-management and evidence-register prototype. It does **not** acquire forensic images, parse Windows EVTX logs, analyse memory dumps or PCAP files, create a verified chain of custody, or determine whether evidence is admissible. The hash is calculated after the file is uploaded to this application. Compare it with a trusted acquisition hash where one exists. Preserve original evidence and follow institutional/organisational procedures.

## Requirements
- Python 3.10 or later
- Flask 3.x

## Run on Windows
1. Extract the ZIP.
2. Open a terminal in this folder.
3. Run `run_windows.bat`, or execute:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```
4. Open `http://127.0.0.1:5000`.

## Run on Linux / macOS
```bash
chmod +x run_unix.sh
./run_unix.sh
```
Then open `http://127.0.0.1:5000`.

## Run tests
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Local data locations
On first run, Flask creates an `instance/` directory containing:
- `case_manager.sqlite3` — SQLite database.
- `evidence/` — uploaded evidence copies using random stored filenames.

Back up the database and evidence folder together. Do not edit the database while the application is running.

## Suggested demonstration
1. Create a case named `DF-2026-001 — Suspicious workstation activity`.
2. Upload a harmless sample `.log` or `.txt` file.
3. Confirm the SHA-256 digest appears on the case page.
4. Add an investigation note and change the case status.
5. Download the stored copy and compare its SHA-256 hash with the displayed value.
6. Run the unit tests and include the actual terminal output in the report.

## Security notes
- Keep the service bound to localhost for this student demonstration.
- Do not expose it to the public internet.
- Use a stable, secret `FLASK_SECRET_KEY` environment variable for persistent sessions in a longer-running deployment.
- The allowlist is a basic upload control, not a malware scanner. Only use test files or evidence you are authorised to handle.
