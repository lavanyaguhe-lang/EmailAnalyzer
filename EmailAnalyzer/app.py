import pymysql
pymysql.install_as_MySQLdb()
import os
import secrets
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from model_loader import analyze_email_text

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['DB_INITIALIZED'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
APP_START_TIME = datetime.now()

def classify_risk(risk_score):
    score = max(0, min(100, int(risk_score or 0)))
    if score >= 70:
        return "MALICIOUS", "pill-red", "danger"
    if score >= 25:
        return "SUSPICIOUS", "pill-amber", "warning"
    return "SECURE", "pill-green", "safe"


def classify_scan_verdict(risk_score):
    score = max(0, min(100, int(risk_score or 0)))
    if score >= 70:
        return "Phishing", "pill-red"
    if score >= 25:
        return "Suspicious", "pill-amber"
    return "Safe", "pill-green"


# Database Configuration
db_config = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'root'),
    'database': os.environ.get('DB_NAME', 'analyzer_db'),
    'port': int(os.environ.get('DB_PORT', '3306')),
}

def get_db_connection():
    return mysql.connector.connect(**db_config)


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(24)
        session["_csrf_token"] = token
    return token


def verify_csrf_token():
    sent_token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(sent_token and expected and secrets.compare_digest(sent_token, expected))


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped_view


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `user` (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                email_content TEXT NOT NULL,
                sentiment VARCHAR(100),
                is_spam TINYINT(1) NOT NULL DEFAULT 0,
                risk_score INT NOT NULL DEFAULT 0,
                explanation VARCHAR(500),
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_email_scans_user
                    FOREIGN KEY (user_id) REFERENCES `user`(id)
                    ON DELETE CASCADE
            )
        """)

        # Backward-compatible schema migration for existing databases.
        cursor.execute(
            """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'email_scans'
            """,
            (db_config['database'],),
        )
        existing_columns = {row[0] for row in cursor.fetchall()}
        if 'risk_score' not in existing_columns:
            cursor.execute("ALTER TABLE email_scans ADD COLUMN risk_score INT NOT NULL DEFAULT 0")
        if 'explanation' not in existing_columns:
            cursor.execute("ALTER TABLE email_scans ADD COLUMN explanation VARCHAR(500)")

        cursor.execute(
            """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'user'
            """,
            (db_config['database'],),
        )
        user_columns = {row[0] for row in cursor.fetchall()}
        if 'display_name' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN display_name VARCHAR(150)")
        if 'notification_email' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN notification_email VARCHAR(255)")
        if 'notify_on_high' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN notify_on_high TINYINT(1) NOT NULL DEFAULT 1")
        if 'notify_on_suspicious' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN notify_on_suspicious TINYINT(1) NOT NULL DEFAULT 1")
        if 'role' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'USER'")
        if 'is_active' not in user_columns:
            cursor.execute("ALTER TABLE `user` ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1")

        # Repair legacy schema: some installations may have email_scans.user_id
        # referencing `users` instead of `user`, which breaks inserts.
        cursor.execute(
            """
            SELECT CONSTRAINT_NAME, REFERENCED_TABLE_NAME
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'email_scans'
              AND COLUMN_NAME = 'user_id'
              AND REFERENCED_TABLE_NAME IS NOT NULL
            """,
            (db_config['database'],),
        )
        fk_rows = cursor.fetchall()
        wrong_fk_names = [row[0] for row in fk_rows if row[1] != 'user']
        has_correct_fk = any(row[1] == 'user' for row in fk_rows)

        for fk_name in wrong_fk_names:
            cursor.execute(f"ALTER TABLE email_scans DROP FOREIGN KEY `{fk_name}`")

        if not has_correct_fk:
            cursor.execute(
                """
                ALTER TABLE email_scans
                ADD CONSTRAINT fk_email_scans_user
                FOREIGN KEY (user_id) REFERENCES `user`(id)
                ON DELETE CASCADE
                """
            )
        default_admin_username = os.environ.get("DEFAULT_ADMIN_USERNAME", "").strip()
        default_admin_email = os.environ.get("DEFAULT_ADMIN_EMAIL", "").strip().lower()
        default_admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "").strip()
        if default_admin_username and default_admin_email and default_admin_password:
            cursor.execute("SELECT id FROM `user` WHERE username = %s", (default_admin_username,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO `user` (username, email, password, role, is_active)
                    VALUES (%s, %s, %s, 'ADMIN', 1)
                    """,
                    (
                        default_admin_username,
                        default_admin_email,
                        generate_password_hash(default_admin_password),
                    ),
                )

        conn.commit()
    finally:
        cursor.close()
        conn.close()

def build_report_context(scan_row):
    sentiment_text = (scan_row.get('sentiment') or '').lower()
    risk_score = int(scan_row.get('risk_score') or 0)
    explanation = scan_row.get('explanation')

    # Recompute for legacy rows that were saved before risk scoring existed.
    if risk_score == 0 and scan_row.get('email_content'):
        recalculated = analyze_email_text(scan_row.get('email_content', ''))
        risk_score = int(recalculated.get('risk_score', 0))
        explanation = recalculated.get('explanation')
        if recalculated.get('sentiment'):
            sentiment_text = str(recalculated.get('sentiment')).lower()

    risk_score = max(0, min(100, risk_score))
    spam_values = [risk_score, max(0, 100 - risk_score)]

    sentiment_labels = ["Positive", "Neutral", "Negative"]
    if "positive" in sentiment_text:
        sentiment_values = [100, 0, 0]
    elif "negative" in sentiment_text:
        sentiment_values = [0, 0, 100]
    else:
        sentiment_values = [0, 100, 0]

    threat_label, _, risk_class = classify_risk(risk_score)
    explanation = explanation or (
        f"This scan is classified as {threat_label}. "
        f"Detected sentiment: {scan_row.get('sentiment', 'Unknown')}."
    )

    return {
        "operator": session.get("username", "UNKNOWN"),
        "risk_score": risk_score,
        "risk_class": risk_class,
        "ai_explanation": explanation,
        "spam_labels": ["Spam", "Safe"],
        "spam_values": spam_values,
        "sentiment_labels": sentiment_labels,
        "sentiment_values": sentiment_values,
        "scan_id": scan_row.get("id"),
        "scan_time": scan_row.get("analysis_date"),
        "threat_label": threat_label,
        "email_preview": (scan_row.get("email_content", "")[:180] + "...") if scan_row.get("email_content") else "",
    }

def get_system_stats():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) AS c FROM `user`")
        total_users = int(cursor.fetchone()['c'])

        cursor.execute("SELECT COUNT(*) AS c FROM email_scans")
        total_scans = int(cursor.fetchone()['c'])

        cursor.execute("SELECT COUNT(*) AS c FROM email_scans WHERE is_spam = 1")
        active_alerts = int(cursor.fetchone()['c'])
    finally:
        cursor.close()
        conn.close()

    uptime_delta = datetime.now() - APP_START_TIME
    total_minutes = int(uptime_delta.total_seconds() // 60)
    hours, minutes = divmod(total_minutes, 60)
    uptime = f"{hours}h {minutes}m"

    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "active_alerts": active_alerts,
        "uptime": uptime,
    }


@app.before_request
def ensure_db_ready():
    if app.config['DB_INITIALIZED']:
        return
    init_db()
    app.config['DB_INITIALIZED'] = True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not verify_csrf_token():
            flash("Invalid security token. Please retry.", "danger")
            return render_template('login.html')
        username = request.form.get('username', '').strip()
        password_candidate = request.form.get('password', '')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM `user` WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password_candidate):
                if int(user.get('is_active') or 1) != 1:
                    flash("Account blocked. Contact an administrator.", "danger")
                    return render_template('login.html')
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.permanent = True
                return redirect(url_for('dashboard'))
            flash("Login Failed: Incorrect credentials.", "danger")
        finally:
            cursor.close()
            conn.close()
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if not verify_csrf_token():
            flash("Invalid security token. Please retry.", "danger")
            return render_template('signup.html')

        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "warning")
            return render_template('signup.html')
        if '@' not in email:
            flash("Enter a valid email address.", "warning")
            return render_template('signup.html')
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "warning")
            return render_template('signup.html')
        if password != confirm_password:
            flash("Passwords do not match.", "warning")
            return render_template('signup.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO `user` (username, email, password, role, is_active) VALUES (%s, %s, %s, 'USER', 1)",
                (username, email, generate_password_hash(password)),
            )
            conn.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            conn.rollback()
            if err.errno == 1062:
                flash("Username or email already exists.", "warning")
            else:
                flash(f"Database error during signup ({err}).", "danger")
        finally:
            cursor.close()
            conn.close()
    return render_template('signup.html')


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    result = None
    email_text = ""
    url_input = ""
    history = []

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        if not verify_csrf_token():
            flash("Invalid security token. Please retry.", "danger")
            return redirect(url_for('register'))
        email_text = request.form.get('email_text', '').strip()
        url_input = request.form.get('url_input', '').strip()

        if not email_text and not url_input:
            flash("Enter email text or URL before scanning.", "warning")
        else:
            result = analyze_email_text(email_text, url_input)
            risk_score = int(result.get('risk_score', 0))
            verdict, pill_class = classify_scan_verdict(risk_score)
            payload = f"Email Text:\n{email_text}\n\nURL:\n{url_input}".strip()
            explanation = str(result.get('explanation', 'No details available'))[:500]
            is_spam_val = 1 if verdict == "Phishing" else 0

            result['verdict'] = verdict
            result['pill_class'] = pill_class

            try:
                query = """
                    INSERT INTO email_scans (user_id, email_content, sentiment, is_spam, risk_score, explanation)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(
                    query,
                    (session['user_id'], payload, result['sentiment'], is_spam_val, risk_score, explanation),
                )
                conn.commit()
            except Exception as e:
                print(f"DATABASE ERROR: {e}")
                flash("Could not save scan result to database.", "danger")
                conn.rollback()

    cursor.execute("SELECT * FROM email_scans WHERE user_id = %s ORDER BY id DESC LIMIT 10", (session['user_id'],))
    history = cursor.fetchall()
    for row in history:
        verdict, pill_class = classify_scan_verdict(int(row.get('risk_score') or 0))
        row['verdict'] = verdict
        row['pill_class'] = pill_class

    cursor.close()
    conn.close()
    return render_template('register.html', result=result, history=history, email_text=email_text, url_input=url_input)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) 
    result = None
    email_text = ""
    url_input = ""

    if request.method == 'POST':
        if not verify_csrf_token():
            flash("Invalid security token. Please retry.", "danger")
            return redirect(url_for('dashboard'))
        email_text = request.form.get('email_content', '').strip()
        url_input = request.form.get('url_input', '').strip()
        if email_text or url_input:
            result = analyze_email_text(email_text, url_input)
            risk_score = int(result.get('risk_score', 0))
            is_spam_val = 1 if risk_score >= 70 else 0
            explanation = str(result.get('explanation', 'No details available'))[:500]
            verdict, pill_class = classify_scan_verdict(risk_score)
            result['verdict'] = verdict
            result['pill_class'] = pill_class
            payload = f"Email Text:\n{email_text}\n\nURL:\n{url_input}".strip()
            
            try:
                query = """
                    INSERT INTO email_scans (user_id, email_content, sentiment, is_spam, risk_score, explanation)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(
                    query,
                    (session['user_id'], payload, result['sentiment'], is_spam_val, risk_score, explanation),
                )
                conn.commit()
                flash("Analysis complete.", "success")
            except Exception as e:
                print(f"DATABASE ERROR: {e}")
                flash("Could not save analysis to history.", "warning")
                conn.rollback()
        else:
            flash("Enter email text or URL before analyzing.", "warning")

    cursor.close()
    conn.close()
    return render_template('dashboard.html', result=result, email_text=email_text, url_input=url_input)

@app.route("/report")
@login_required
def report():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM email_scans WHERE user_id = %s ORDER BY id DESC LIMIT 1",
            (session['user_id'],),
        )
        scan_row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not scan_row:
        flash("No scan history found. Please run an analysis first.", "warning")
        return redirect(url_for('dashboard'))

    return render_template("report.html", **build_report_context(scan_row))

@app.route("/report/<int:scan_id>")
@login_required
def report_by_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM email_scans WHERE id = %s AND user_id = %s",
            (scan_id, session['user_id']),
        )
        scan_row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not scan_row:
        flash("Requested report was not found.", "warning")
        return redirect(url_for('dashboard'))

    return render_template("report.html", **build_report_context(scan_row))

@app.route("/alerts")
@login_required
def alerts():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, risk_score, explanation, email_content, analysis_date
            FROM email_scans
            WHERE user_id = %s
            ORDER BY analysis_date DESC
            LIMIT 30
            """,
            (session["user_id"],),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    alerts_data = []
    for row in rows:
        score = int(row.get("risk_score") or 0)
        if score >= 85:
            level = "CRITICAL"
            title = "Critical Phishing Detected"
        elif score >= 70:
            level = "HIGH"
            title = "High-Risk Phishing Attempt"
        elif score >= 25:
            level = "MEDIUM"
            title = "Suspicious Content Detected"
        else:
            level = "LOW"
            title = "Safe Scan Logged"

        snippet = (row.get("email_content") or "").replace("\n", " ").strip()
        snippet = snippet[:120] + ("..." if len(snippet) > 120 else "")
        explanation = row.get("explanation") or "No detailed explanation available."

        alerts_data.append(
            {
                "id": row.get("id"),
                "title": title,
                "message": f"{explanation} | Snippet: {snippet}",
                "level": level,
                "time": row.get("analysis_date"),
                "risk_score": score,
            }
        )

    return render_template("alerts.html", alerts=alerts_data)

@app.route("/alerts/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete_alert(scan_id):
    if not verify_csrf_token():
        flash("Invalid security token. Please retry.", "danger")
        return redirect(url_for("alerts"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM email_scans WHERE id = %s AND user_id = %s",
            (scan_id, session["user_id"]),
        )
        conn.commit()
        if cursor.rowcount:
            flash("Alert deleted.", "success")
        else:
            flash("Alert not found.", "warning")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("alerts"))

@app.route("/alerts/delete-all", methods=["POST"])
@login_required
def delete_all_alerts():
    if not verify_csrf_token():
        flash("Invalid security token. Please retry.", "danger")
        return redirect(url_for("alerts"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM email_scans WHERE user_id = %s", (session["user_id"],))
        deleted_count = cursor.rowcount
        conn.commit()
        flash(f"Deleted {deleted_count} alert(s).", "success")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("alerts"))

@app.route("/users")
@login_required
def users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, username, role, is_active
            FROM `user`
            ORDER BY id ASC
            """
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    users_data = []
    for row in rows:
        role = (row.get("role") or "USER").upper()
        status = "ACTIVE" if int(row.get("is_active") or 0) == 1 else "BLOCKED"
        users_data.append(
            {
                "id": row.get("id"),
                "username": row.get("username"),
                "role": role,
                "status": status,
                "role_pill": "pill-red" if role == "ADMIN" else ("pill-amber" if role == "ANALYST" else "pill-green"),
                "status_pill": "pill-green" if status == "ACTIVE" else "pill-red",
            }
        )

    return render_template("users.html", users=users_data)

@app.route("/users/toggle/<int:user_id>", methods=["POST"])
@login_required
def toggle_user(user_id):
    if not verify_csrf_token():
        flash("Invalid security token. Please retry.", "danger")
        return redirect(url_for("users"))

    if user_id == session["user_id"]:
        flash("You cannot block your own account.", "warning")
        return redirect(url_for("users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE `user`
            SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END
            WHERE id = %s
            """,
            (user_id,),
        )
        conn.commit()
        if cursor.rowcount:
            flash("User status updated.", "success")
        else:
            flash("User not found.", "warning")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("users"))

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not verify_csrf_token():
        flash("Invalid security token. Please retry.", "danger")
        return redirect(url_for("users"))

    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM `user` WHERE id = %s", (user_id,))
        conn.commit()
        if cursor.rowcount:
            flash("User deleted successfully.", "success")
        else:
            flash("User not found.", "warning")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("users"))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/system")
def system():
    return render_template("system.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, username, email, display_name, notification_email,
                   notify_on_high, notify_on_suspicious, password
            FROM `user`
            WHERE id = %s
            """,
            (session["user_id"],),
        )
        user_row = cursor.fetchone()
        if not user_row:
            flash("User not found.", "warning")
            return redirect(url_for("login"))

        if request.method == "POST":
            if not verify_csrf_token():
                flash("Invalid security token. Please retry.", "danger")
                return redirect(url_for("settings"))

            form_type = request.form.get("form_type", "").strip().lower()

            if form_type == "profile":
                username = request.form.get("username", "").strip()
                email = request.form.get("email", "").strip().lower()
                display_name = request.form.get("display_name", "").strip()
                notification_email = request.form.get("notification_email", "").strip().lower()

                if not username or not email:
                    flash("Username and email are required.", "warning")
                    return redirect(url_for("settings"))

                if notification_email and "@" not in notification_email:
                    flash("Notification email is invalid.", "warning")
                    return redirect(url_for("settings"))

                try:
                    cursor.execute(
                        """
                        UPDATE `user`
                        SET username = %s, email = %s, display_name = %s, notification_email = %s
                        WHERE id = %s
                        """,
                        (username, email, display_name or None, notification_email or None, session["user_id"]),
                    )
                    conn.commit()
                    session["username"] = username
                    flash("Profile updated successfully.", "success")
                except mysql.connector.Error as err:
                    conn.rollback()
                    if err.errno == 1062:
                        flash("Username or email already exists.", "warning")
                    else:
                        flash(f"Database error while updating profile ({err}).", "danger")

            elif form_type == "password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")

                if not current_password or not new_password or not confirm_password:
                    flash("All password fields are required.", "warning")
                    return redirect(url_for("settings"))
                if not check_password_hash(user_row["password"], current_password):
                    flash("Current password is incorrect.", "danger")
                    return redirect(url_for("settings"))
                if len(new_password) < 8:
                    flash("New password must be at least 8 characters.", "warning")
                    return redirect(url_for("settings"))
                if new_password != confirm_password:
                    flash("New password and confirm password do not match.", "warning")
                    return redirect(url_for("settings"))

                try:
                    new_hash = generate_password_hash(new_password)
                    cursor.execute("UPDATE `user` SET password = %s WHERE id = %s", (new_hash, session["user_id"]))
                    conn.commit()
                    flash("Password changed successfully.", "success")
                except mysql.connector.Error as err:
                    conn.rollback()
                    flash(f"Database error while changing password ({err}).", "danger")

            elif form_type == "notifications":
                notify_on_high = 1 if request.form.get("notify_on_high") == "on" else 0
                notify_on_suspicious = 1 if request.form.get("notify_on_suspicious") == "on" else 0
                notification_email = request.form.get("notification_email_pref", "").strip().lower()
                if notification_email and "@" not in notification_email:
                    flash("Notification email is invalid.", "warning")
                    return redirect(url_for("settings"))

                try:
                    cursor.execute(
                        """
                        UPDATE `user`
                        SET notify_on_high = %s, notify_on_suspicious = %s, notification_email = %s
                        WHERE id = %s
                        """,
                        (notify_on_high, notify_on_suspicious, notification_email or None, session["user_id"]),
                    )
                    conn.commit()
                    flash("Notification settings updated.", "success")
                except mysql.connector.Error as err:
                    conn.rollback()
                    flash(f"Database error while saving notification settings ({err}).", "danger")
            else:
                flash("Unsupported settings form submission.", "warning")

            return redirect(url_for("settings"))

        # Refresh after updates/GET.
        cursor.execute(
            """
            SELECT id, username, email, display_name, notification_email,
                   notify_on_high, notify_on_suspicious
            FROM `user`
            WHERE id = %s
            """,
            (session["user_id"],),
        )
        user_view = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    return render_template("settings.html", user=user_view)

@app.route("/system/stats")
@login_required
def system_stats():
    return jsonify(get_system_stats())

@app.route('/logout')
def logout():
    # Clear session and redirect
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
