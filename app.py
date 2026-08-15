from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pathlib import Path
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_FOLDER = DATA_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "subxero.db"

ALLOWED_EXTENSIONS = {"exe"}

# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            description TEXT NOT NULL,
            filename TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    # Create default admin if none exists
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        # CHANGE THESE CREDENTIALS
        email = "admin@subxero.local"
        password = "change-me-now"
        pw_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, pw_hash)
        )
        print(f"\n[subxero] Default admin created → {email} / {password}")
        print("          Change it immediately after first login.\n")
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/releases")
def releases():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM releases ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("releases.html", releases=rows)

@app.route("/download/<int:release_id>")
def download(release_id):
    conn = get_db()
    row = conn.execute(
        "SELECT filename FROM releases WHERE id = ?", (release_id,)
    ).fetchone()
    conn.close()
    if not row:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, row["filename"], as_attachment=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("admin"))
        flash("Invalid email or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if request.method == "POST":
        version = request.form.get("version", "").strip()
        description = request.form.get("description", "").strip()
        file = request.files.get("exe")

        if not version or not description or not file:
            flash("All fields are required.")
            return redirect(url_for("admin"))

        if not allowed_file(file.filename):
            flash("Only .exe files are allowed.")
            return redirect(url_for("admin"))

        # Make a safe unique filename
        original = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        filename = f"subxero_{version}_{timestamp}.exe"
        file.save(UPLOAD_FOLDER / filename)

        conn = get_db()
        conn.execute(
            "INSERT INTO releases (version, description, filename, created_at) VALUES (?, ?, ?, ?)",
            (version, description, filename, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        flash(f"Release {version} published.")
        return redirect(url_for("admin"))

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM releases ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("admin.html", releases=rows)

@app.route("/admin/delete/<int:release_id>", methods=["POST"])
@login_required
def delete_release(release_id):
    conn = get_db()
    row = conn.execute(
        "SELECT filename FROM releases WHERE id = ?", (release_id,)
    ).fetchone()
    if row:
        path = UPLOAD_FOLDER / row["filename"]
        if path.exists():
            path.unlink()
        conn.execute("DELETE FROM releases WHERE id = ?", (release_id,))
        conn.commit()
    conn.close()
    flash("Release deleted.")
    return redirect(url_for("admin"))

# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)