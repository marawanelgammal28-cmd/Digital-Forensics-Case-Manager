import hashlib
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_from_directory, session, url_for
)
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {
    ".evtx", ".mem", ".dmp", ".raw", ".dd", ".img", ".e01",
    ".aff4", ".pcap", ".pcapng", ".log", ".txt", ".csv", ".json"
}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.instance_path, "case_manager.sqlite3"),
        EVIDENCE_DIR=os.path.join(app.instance_path, "evidence"),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["EVIDENCE_DIR"]).mkdir(parents=True, exist_ok=True)

    def get_db():
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def init_db():
        with get_db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL CHECK(length(title) BETWEEN 3 AND 120),
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'Open'
                        CHECK(status IN ('Open', 'In Progress', 'Closed')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    extension TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 5000),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);
            """)

    with app.app_context():
        init_db()

    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def protect_post_requests():
        if request.method == "POST":
            submitted = request.form.get("_csrf_token", "")
            expected = session.get("_csrf_token", "")
            if not expected or not secrets.compare_digest(submitted, expected):
                abort(400, description="Invalid or missing security token. Reload the page and try again.")

    def valid_text(value, minimum, maximum):
        return isinstance(value, str) and minimum <= len(value.strip()) <= maximum

    def calculate_sha256(file_path):
        digest = hashlib.sha256()
        with open(file_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @app.errorhandler(413)
    def too_large(_error):
        flash("Upload rejected: the file exceeds the 50 MiB limit.", "error")
        return redirect(request.referrer or url_for("index"))

    @app.route("/")
    def index():
        with get_db() as db:
            cases = db.execute("""
                SELECT c.*,
                    (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidence_count,
                    (SELECT COUNT(*) FROM notes n WHERE n.case_id = c.id) AS note_count
                FROM cases c ORDER BY c.created_at DESC
            """).fetchall()
            totals = {
                "cases": db.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
                "evidence": db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
                "notes": db.execute("SELECT COUNT(*) FROM notes").fetchone()[0],
            }
        return render_template("index.html", cases=cases, totals=totals)

    @app.route("/cases/new", methods=["GET", "POST"])
    def new_case():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            if not valid_text(title, 3, 120):
                flash("Case title must contain 3–120 characters.", "error")
                return render_template("new_case.html")
            if len(description) > 2000:
                flash("Description must not exceed 2,000 characters.", "error")
                return render_template("new_case.html")
            with get_db() as db:
                cursor = db.execute(
                    "INSERT INTO cases(title, description, status, created_at) VALUES (?, ?, 'Open', ?)",
                    (title, description, utc_now())
                )
                case_id = cursor.lastrowid
            flash("Investigation case created.", "success")
            return redirect(url_for("case_detail", case_id=case_id))
        return render_template("new_case.html")

    @app.route("/cases/<int:case_id>")
    def case_detail(case_id):
        with get_db() as db:
            case = db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if case is None:
                abort(404)
            evidence = db.execute(
                "SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,)
            ).fetchall()
            notes = db.execute(
                "SELECT * FROM notes WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,)
            ).fetchall()
        return render_template("case_detail.html", case=case, evidence=evidence, notes=notes)

    @app.route("/cases/<int:case_id>/status", methods=["POST"])
    def update_status(case_id):
        status = request.form.get("status", "")
        if status not in {"Open", "In Progress", "Closed"}:
            flash("Invalid case status.", "error")
        else:
            with get_db() as db:
                cursor = db.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
                if cursor.rowcount == 0:
                    abort(404)
            flash("Case status updated.", "success")
        return redirect(url_for("case_detail", case_id=case_id))

    @app.route("/cases/<int:case_id>/notes", methods=["POST"])
    def add_note(case_id):
        body = request.form.get("body", "").strip()
        if not valid_text(body, 1, 5000):
            flash("Investigation note must contain 1–5,000 characters.", "error")
            return redirect(url_for("case_detail", case_id=case_id))
        with get_db() as db:
            exists = db.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
            if exists is None:
                abort(404)
            db.execute(
                "INSERT INTO notes(case_id, body, created_at) VALUES (?, ?, ?)",
                (case_id, body, utc_now())
            )
        flash("Investigation note saved.", "success")
        return redirect(url_for("case_detail", case_id=case_id))

    @app.route("/cases/<int:case_id>/evidence", methods=["POST"])
    def upload_evidence(case_id):
        uploaded = request.files.get("evidence_file")
        notes = request.form.get("notes", "").strip()
        if uploaded is None or not uploaded.filename:
            flash("Select an evidence file first.", "error")
            return redirect(url_for("case_detail", case_id=case_id))
        if len(notes) > 1000:
            flash("Evidence notes must not exceed 1,000 characters.", "error")
            return redirect(url_for("case_detail", case_id=case_id))

        original_name = secure_filename(uploaded.filename)
        extension = Path(original_name).suffix.lower()
        if not original_name or extension not in ALLOWED_EXTENSIONS:
            flash("Unsupported file type. Review the allowed extensions shown on this page.", "error")
            return redirect(url_for("case_detail", case_id=case_id))

        with get_db() as db:
            exists = db.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
            if exists is None:
                abort(404)

        stored_name = f"{uuid.uuid4().hex}{extension}"
        destination = Path(app.config["EVIDENCE_DIR"]) / stored_name
        uploaded.save(destination)
        size_bytes = destination.stat().st_size
        if size_bytes == 0:
            destination.unlink(missing_ok=True)
            flash("Empty evidence files are not accepted.", "error")
            return redirect(url_for("case_detail", case_id=case_id))
        if size_bytes > MAX_UPLOAD_BYTES:
            destination.unlink(missing_ok=True)
            flash("Upload rejected: the file exceeds the 50 MiB limit.", "error")
            return redirect(url_for("case_detail", case_id=case_id))

        sha256 = calculate_sha256(destination)
        try:
            with get_db() as db:
                db.execute("""
                    INSERT INTO evidence
                    (case_id, original_name, stored_name, extension, size_bytes, sha256, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (case_id, original_name, stored_name, extension, size_bytes,
                      sha256, notes, utc_now()))
        except Exception:
            destination.unlink(missing_ok=True)
            raise

        flash("Evidence registered and SHA-256 hash calculated.", "success")
        return redirect(url_for("case_detail", case_id=case_id))

    @app.route("/evidence/<int:evidence_id>/download")
    def download_evidence(evidence_id):
        with get_db() as db:
            item = db.execute(
                "SELECT stored_name, original_name FROM evidence WHERE id = ?",
                (evidence_id,)
            ).fetchone()
            if item is None:
                abort(404)
        response = send_from_directory(
            app.config["EVIDENCE_DIR"], item["stored_name"],
            as_attachment=True, download_name=item["original_name"]
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/health")
    def health():
        return {"status": "ok", "application": "Digital Forensics Case Manager"}

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
