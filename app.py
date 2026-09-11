import importlib.util
import os
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for


DESKTOP_SOURCE = Path(__file__).with_name("ACT 7.py")
spec = importlib.util.spec_from_file_location("act7_desktop", DESKTOP_SOURCE)
if spec is None or spec.loader is None:
    raise ImportError(f"Could not load {DESKTOP_SOURCE}")
act7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(act7)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "act7-development-secret")

act7.init_db()
auth = act7.AuthController()
tracker = act7.TrackerController()


@app.template_filter("activity_time")
def activity_time(value):
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")


@app.route("/styles.css")
def styles():
    return send_file(Path(__file__).with_name("templates") / "styles.css", mimetype="text/css")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "ADMIN":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "username" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ok, result = auth.login_user(
            request.form.get("username", "").strip(),
            request.form.get("password", ""),
        )
        if ok and isinstance(result, dict):
            session.clear()
            session.update(
                username=result["username"],
                role=result["role"],
                password_reset_required=result.get("password_reset_required", False),
            )
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        flash(str(result), "danger")
    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
    role = request.form.get("role", "USER").strip().upper()
    name = request.form.get("student_name", "").strip()
    if role == "ADMIN":
        name = request.form.get("admin_name", "").strip()
    ok, message = auth.register_user(
        request.form.get("username", "").strip(),
        request.form.get("email", "").strip(),
        request.form.get("password", ""),
        role=role,
        student_name=name,
        student_number=request.form.get("student_number", "").strip(),
        section=request.form.get("section", "").strip(),
    )
    flash(message, "success" if ok else "danger")
    return redirect(url_for("login"))


@app.route("/reset-request", methods=["POST"])
def reset_request():
    ok, message = auth.request_password_reset(
        request.form.get("username", "").strip(),
        request.form.get("email", "").strip(),
    )
    flash(message, "success" if ok else "danger")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "").strip().lower()
    items = [item for item in tracker.fetch_all_items() if not search or search in item[1].lower() or search in item[2].lower()]
    all_items = tracker.fetch_all_items()
    profile = auth.get_user_profile(session["username"]) or {}
    data = {
        "items": items,
        "total_stocks": sum(item[3] for item in all_items),
        "total_price": tracker.get_total_inventory_value(),
        "profile": profile,
        "my_requests": tracker.get_user_borrow_requests_with_ids(session["username"]),
        "active_borrowed_items": tracker.get_user_active_borrowed_items(session["username"]),
        "user_reports": tracker.get_user_reports(session["username"]),
        "schedules": tracker.get_schedules(None if session["role"] == "ADMIN" else profile.get("section")),
    }
    if session["role"] == "ADMIN":
        data.update(
            borrow_requests=tracker.get_pending_borrow_requests(),
            reports=tracker.get_open_reports(),
            resets=auth.get_pending_reset_requests(),
            activity_records=tracker.get_activity_records(),
        )
    return render_template("dashboard.html", search=search, **data)


@app.route("/borrow", methods=["POST"])
@login_required
def borrow():
    if session["role"] != "USER":
        flash("Only USER accounts can borrow equipment.", "danger")
        return redirect(url_for("dashboard"))
    try:
        item_id = int(request.form["item_id"])
        quantity = int(request.form["quantity"])
    except (KeyError, ValueError):
        flash("Quantity must be a whole number.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.request_borrow(session["username"], item_id, quantity, request.form.get("purpose", "Student equipment request"))
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/return-request", methods=["POST"])
@login_required
def return_request():
    try:
        request_id = int(request.form["request_id"])
    except (KeyError, ValueError):
        flash("Invalid borrowing record.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.request_return(request_id, session["username"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/report", methods=["POST"])
@login_required
def report():
    if session["role"] != "USER":
        flash("Only USER accounts can submit equipment reports.", "danger")
        return redirect(url_for("dashboard"))
    item_id = request.form.get("item_id") or None
    try:
        item_id = int(item_id) if item_id else None
    except ValueError:
        item_id = None
    ok, message = tracker.submit_report(
        session["username"],
        request.form.get("report_type", ""),
        item_id,
        request.form.get("details", ""),
    )
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():
    try:
        quantity = int(request.form["quantity"])
        unit_price = float(request.form["unit_price"])
    except (KeyError, ValueError):
        flash("Quantity must be an integer and unit price must be numeric.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.add_item(request.form.get("item_name", ""), request.form.get("category", ""), quantity, unit_price, session["username"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/update", methods=["POST"])
@admin_required
def admin_update():
    try:
        item_id = int(request.form["item_id"])
        quantity = int(request.form["quantity"])
        unit_price = float(request.form["unit_price"])
    except (KeyError, ValueError):
        flash("Item ID, quantity, and unit price must be valid numbers.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.update_item(item_id, quantity, unit_price, session["username"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/delete", methods=["POST"])
@admin_required
def admin_delete():
    try:
        item_id = int(request.form["item_id"])
    except (KeyError, ValueError):
        flash("Invalid inventory item.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.delete_item(item_id, session["username"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/report-action", methods=["POST"])
@admin_required
def admin_report_action():
    try:
        report_id = int(request.form["report_id"])
    except (KeyError, ValueError):
        flash("Invalid report.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.close_report(report_id, session["username"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/schedule", methods=["POST"])
@admin_required
def admin_schedule():
    ok, message = tracker.add_schedule(
        request.form.get("section", ""),
        request.form.get("subject", ""),
        request.form.get("instructor", ""),
        request.form.get("room", ""),
        request.form.get("schedule_date", ""),
        request.form.get("start_time", ""),
        request.form.get("end_time", ""),
        session["username"],
    )
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/schedule/delete", methods=["POST"])
@admin_required
def admin_schedule_delete():
    try:
        schedule_id = int(request.form["schedule_id"])
    except (KeyError, ValueError):
        flash("Invalid schedule.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.delete_schedule(schedule_id)
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/borrow-action", methods=["POST"])
@admin_required
def admin_borrow_action():
    try:
        request_id = int(request.form["request_id"])
    except (KeyError, ValueError):
        flash("Invalid borrow request.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.decide_borrow_request(request_id, session["username"], request.form.get("action", "reject"))
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/return-action", methods=["POST"])
@admin_required
def admin_return_action():
    try:
        request_id = int(request.form["request_id"])
    except (KeyError, ValueError):
        flash("Invalid return request.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = tracker.decide_return_request(request_id, session["username"], request.form.get("action", "reject"))
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/admin/reset-action", methods=["POST"])
@admin_required
def admin_reset_action():
    try:
        request_id = int(request.form["request_id"])
    except (KeyError, ValueError):
        flash("Invalid reset request.", "danger")
        return redirect(url_for("dashboard"))
    ok, message = auth.approve_reset_request(request_id, session["username"], request.form.get("action", "reject"))
    flash(message, "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/export")
@login_required
def export():
    path = Path(__file__).with_name("inventory_report.csv")
    ok, message = tracker.export_inventory_csv(path)
    if not ok:
        flash(message, "danger")
        return redirect(url_for("dashboard"))
    return send_file(path, as_attachment=True, download_name="inventory_report.csv")


if __name__ == "__main__":
    print("=" * 58)
    print(" CAMPUS HARDWARE INVENTORY - WEB PORTAL")
    print("=" * 58)
    print()
    print(" Open Google Chrome and go to:")
    print(" http://127.0.0.1:5000")
    print()
    print(" Press CTRL+C to stop the server.")
    print("=" * 58)
    app.run(debug=True)
