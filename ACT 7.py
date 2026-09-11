import csv
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

import bcrypt
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


def setup_logger():
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_logging")
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(log_dir, "app.log"),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("AppLogger")


logger = setup_logger()

APP_BG = "#eef3f6"
APP_NAVY = "#17324d"
APP_BLUE = "#245b82"
APP_TEAL = "#087f8c"
APP_ORANGE = "#d97706"
APP_GREEN = "#218739"
APP_RED = "#c0392b"
APP_TEXT = "#243746"


def get_db_path(db_name="hardware_inventory.db"):
    if Path(db_name).is_absolute():
        return Path(db_name)
    project_root = Path(__file__).resolve().parents[1]
    supplementary_dir = project_root / "SUPPLEMENTARY ACTIVITIES"
    return supplementary_dir / db_name


def init_db(db_name="hardware_inventory.db"):
    try:
        db_path = get_db_path(db_name)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until REAL NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'USER',
                student_name TEXT NOT NULL DEFAULT '',
                student_number TEXT NOT NULL DEFAULT '',
                section TEXT NOT NULL DEFAULT ''
            )
            """
        )
        cursor.execute("PRAGMA table_info(users)")
        user_columns = {row[1] for row in cursor.fetchall()}
        if "role" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'USER'")
        for column in ("student_name", "student_number", "section"):
            if column not in user_columns:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hardware (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                status TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                requested_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                admin_comment TEXT DEFAULT '',
                approved_by TEXT DEFAULT ''
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                item_id INTEGER,
                item_name TEXT NOT NULL,
                username TEXT NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 0,
                quantity_delta INTEGER NOT NULL DEFAULT 0,
                occurred_at REAL NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (item_id) REFERENCES hardware(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS borrow_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                requested_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                decided_by TEXT DEFAULT '',
                decided_at REAL DEFAULT 0,
                FOREIGN KEY (item_id) REFERENCES hardware(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS laboratory_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                report_type TEXT NOT NULL,
                item_id INTEGER,
                details TEXT NOT NULL,
                reported_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                reviewed_by TEXT DEFAULT '',
                FOREIGN KEY (item_id) REFERENCES hardware(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS laboratory_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                section TEXT NOT NULL,
                subject TEXT NOT NULL,
                instructor TEXT NOT NULL,
                room TEXT NOT NULL,
                schedule_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

        cursor.execute("SELECT 1 FROM users WHERE username = ?", ("admin",))
        if cursor.fetchone() is None:
            admin_hash = bcrypt.hashpw("Admin@123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, failed_attempts, lockout_until) VALUES (?, ?, ?, 'ADMIN', 0, 0)",
                ("admin", "admin@campus.local", admin_hash),
            )
            logger.info("Seeded default administrator account 'admin' with password 'Admin@123'.")

        conn.commit()
        conn.close()
        logger.info("Hardware inventory database initialized successfully at %s", db_path)
    except sqlite3.Error as exc:
        logger.error("Database setup error: %s", exc)


class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: str = Field(...)
    password: str = Field(..., min_length=8)
    role: str = "USER"
    student_name: str = Field(default="", max_length=100)
    student_number: str = Field(default="", max_length=30)
    section: str = Field(default="", max_length=50)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValueError("Please enter a valid email address.")
        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value):
        if not re.match(r"^[a-zA-Z0-9_]+$", value):
            raise ValueError("Username must contain only letters, numbers, and underscores.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one number.")
        if not re.search(r"[@#$%^&*]", value):
            raise ValueError("Password must contain at least one special character (@#$%^&*).")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value):
        normalized = (value or "").strip().upper()
        if normalized not in {"ADMIN", "USER"}:
            raise ValueError("Role must be either ADMIN or USER.")
        return normalized

    @field_validator("student_name", "student_number", "section")
    @classmethod
    def validate_student_details(cls, value):
        return value.strip()

    @model_validator(mode="after")
    def validate_user_details(self):
        if self.role == "USER" and any(
            not value for value in (self.student_name, self.student_number, self.section)
        ):
            raise ValueError("Student details cannot be empty.")
        if self.role == "ADMIN" and not self.student_name:
            raise ValueError("Name cannot be empty.")
        return self


class HardwareSchema(BaseModel):
    item_name: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., min_length=2, max_length=50)
    quantity: int = Field(..., ge=0)
    unit_price: float = Field(..., ge=0)

    @field_validator("item_name", "category")
    @classmethod
    def strip_and_validate(cls, value):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be empty.")
        return cleaned

    @field_validator("quantity")
    @classmethod
    def validate_quantity(cls, value):
        if not isinstance(value, int):
            raise ValueError("Quantity must be an integer.")
        return value

    @field_validator("unit_price")
    @classmethod
    def validate_unit_price(cls, value):
        if value < 0:
            raise ValueError("Unit price must not be negative.")
        return value


class AuthController:
    LOCKOUT_THRESHOLD = 3

    def __init__(self, db_name="hardware_inventory.db"):
        self.db_name = str(get_db_path(db_name))

    @staticmethod
    def friendly_validation_message(raw_messages):
        messages = raw_messages if isinstance(raw_messages, list) else [(raw_messages or "")]
        combined = " ".join(str(message or "") for message in messages).lower()

        if "email" in combined:
            return "Please enter a valid email address."
        if "username" in combined:
            return "Username can only use letters, numbers, and underscores."
        if "uppercase" in combined:
            return "Password needs at least one uppercase letter."
        if "number" in combined:
            return "Password needs at least one number."
        if "special" in combined:
            return "Password needs at least one special character like @, #, $, %, ^, &, or *."
        if "at least 8" in combined or ("8" in combined and "characters" in combined):
            return "Password must be at least 8 characters long."
        if "empty" in combined or "cannot be empty" in combined:
            return "Please fill in all required fields."
        if "role" in combined:
            return "Role must be either ADMIN or USER."
        return "Please check your details and try again."

    def _connect(self):
        conn = sqlite3.connect(self.db_name, timeout=10)
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def register_user(self, username, email, password, role="USER", student_name="", student_number="", section=""):
        try:
            validated = UserRegisterSchema(
                username=username,
                email=email,
                password=password,
                role=role,
                student_name=student_name,
                student_number=student_number,
                section=section,
            )
        except ValidationError as exc:
            raw_messages = [error.get("msg", "") for error in exc.errors()]
            user_message = self.friendly_validation_message(raw_messages)
            logger.warning("Registration validation failed: %s", raw_messages)
            return False, user_message

        hashed_pw = bcrypt.hashpw(validated.password.encode("utf-8"), bcrypt.gensalt())
        try:
            conn = self._connect()
            cursor = conn.cursor()

            cursor.execute("SELECT 1 FROM users WHERE username = ?", (validated.username,))
            if cursor.fetchone():
                conn.close()
                logger.warning("Registration failed. Username already taken: %s", validated.username)
                return False, "Username already taken."

            cursor.execute("SELECT 1 FROM users WHERE email = ?", (validated.email,))
            if cursor.fetchone():
                conn.close()
                logger.warning("Registration failed. Email already taken: %s", validated.email)
                return False, "Email already taken."

            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, student_name, student_number, section) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    validated.username,
                    validated.email,
                    hashed_pw.decode("utf-8"),
                    validated.role,
                    validated.student_name,
                    validated.student_number,
                    validated.section,
                ),
            )
            conn.commit()
            conn.close()
            logger.info("Account created: '%s' with role '%s'", validated.username, validated.role)
            return True, "Registration successful! You may now log in."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock during registration for username '%s': %s", validated.username, exc)
            return False, "Database is busy. Please try again."
        except sqlite3.IntegrityError:
            if "conn" in locals():
                conn.close()
            logger.warning("Registration failed due to database integrity issue for username: %s", validated.username)
            return False, "Registration failed due to a data conflict."

    def login_user(self, username, password):
        if not username or not password:
            logger.warning("Login attempt with missing username or password.")
            return False, "Please enter both username and password."

        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, failed_attempts, lockout_until, role FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()

            if not row:
                conn.close()
                logger.warning("Failed login attempt for username: %s", username)
                return False, "Username not found. Please register first or check the spelling."

            password_hash, failed_attempts, lockout_until, role = row
            now = time.time()

            if lockout_until and now < lockout_until:
                conn.close()
                logger.warning("Login blocked for '%s' - account is locked pending reset/unlock.", username)
                return False, "This account is locked after repeated failed attempts. Please use Reset / Unlock Password to request access."

            if bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
                cursor.execute(
                    "SELECT 1 FROM password_reset_requests WHERE username = ? AND status = 'APPROVED' ORDER BY id DESC LIMIT 1",
                    (username,),
                )
                password_reset_required = cursor.fetchone() is not None
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?",
                    (username,),
                )
                conn.commit()
                conn.close()
                logger.info("User '%s' logged in with role '%s'.", username, role)
                return True, {
                    "username": username,
                    "role": role,
                    "password_reset_required": password_reset_required,
                }

            failed_attempts += 1
            if failed_attempts >= self.LOCKOUT_THRESHOLD:
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?",
                    (failed_attempts, 1.0, username),
                )
                conn.commit()
                conn.close()
                logger.warning("User '%s' locked after %d failed attempts.", username, failed_attempts)
                return False, "Account locked after 3 unsuccessful login attempts. Please use Reset / Unlock Password to request access."

            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (failed_attempts, username),
            )
            conn.commit()
            conn.close()
            logger.warning("Failed login attempt for username: %s (%d/%d)", username, failed_attempts, self.LOCKOUT_THRESHOLD)
            return False, "Password is incorrect. Please try again."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock during login for username '%s': %s", username, exc)
            return False, "The system is busy right now. Please try again in a moment."

    def get_user_profile(self, username):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, email, role, student_name, student_number, section FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                return {
                    "username": row[0],
                    "email": row[1],
                    "role": row[2],
                    "student_name": row[3],
                    "student_number": row[4],
                    "section": row[5],
                }
            return None
        except sqlite3.OperationalError as exc:
            logger.error("Failed to fetch user profile for '%s': %s", username, exc)
            return None

    def change_password(self, username, new_password):
        try:
            validated = UserRegisterSchema(username=username, email="placeholder@example.com", password=new_password, role="USER")
        except ValidationError as exc:
            raw_messages = [error.get("msg", "") for error in exc.errors()]
            return False, self.friendly_validation_message(raw_messages)

        hashed_pw = bcrypt.hashpw(validated.password.encode("utf-8"), bcrypt.gensalt())
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, failed_attempts = 0, lockout_until = 0 WHERE username = ?",
                (hashed_pw.decode("utf-8"), username),
            )
            cursor.execute(
                "UPDATE password_reset_requests SET status = 'COMPLETED' WHERE username = ? AND status = 'APPROVED'",
                (username,),
            )
            conn.commit()
            conn.close()
            logger.info("Password changed for user '%s'", username)
            return True, "Password updated successfully."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while changing password for '%s': %s", username, exc)
            return False, "The system is busy right now. Please try again in a moment."

    def request_password_reset(self, username, email):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM users WHERE username = ? AND email = ?",
                (username, email),
            )
            if not cursor.fetchone():
                conn.close()
                return False, "The username and email do not match an account."

            cursor.execute(
                "INSERT INTO password_reset_requests (username, email, requested_at, status) VALUES (?, ?, ?, 'PENDING')",
                (username, email, time.time()),
            )
            conn.commit()
            conn.close()
            logger.info("Password reset requested by '%s'", username)
            return True, "Password reset request submitted. Please wait for admin approval."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while requesting reset for '%s': %s", username, exc)
            return False, "The system is busy right now. Please try again in a moment."

    def get_latest_reset_status(self, username, email):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status FROM password_reset_requests WHERE username = ? AND email = ? ORDER BY id DESC LIMIT 1",
                (username, email),
            )
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except sqlite3.OperationalError as exc:
            logger.error("Failed to check reset status for '%s': %s", username, exc)
            return None

    def get_pending_reset_requests(self):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, requested_at, status FROM password_reset_requests WHERE status = 'PENDING' ORDER BY requested_at DESC"
            )
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError as exc:
            logger.error("Failed to fetch pending reset requests: %s", exc)
            return []

    def get_all_users(self):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, role, failed_attempts, lockout_until FROM users ORDER BY username")
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError as exc:
            logger.error("Failed to fetch user list: %s", exc)
            return []

    def unlock_user_account(self, username):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?",
                (username,),
            )
            conn.commit()
            conn.close()
            logger.info("Account manually unlocked for '%s'", username)
            return True, f"Account unlocked for {username}."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while unlocking user '%s': %s", username, exc)
            return False, "The system is busy right now. Please try again in a moment."

    def approve_reset_request(self, request_id, admin_username, decision):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, email FROM password_reset_requests WHERE id = ?",
                (request_id,),
            )
            row = cursor.fetchone()
            if not row:
                conn.close()
                return False, "The request is no longer available."

            username, email = row
            new_status = "APPROVED" if decision.lower() == "approve" else "REJECTED"
            cursor.execute(
                "UPDATE password_reset_requests SET status = ?, approved_by = ?, admin_comment = ? WHERE id = ?",
                (new_status, admin_username, f"{decision.capitalize()} by {admin_username}", request_id),
            )
            if new_status == "APPROVED":
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?",
                    (username,),
                )
            conn.commit()
            conn.close()
            if new_status == "APPROVED":
                logger.info("Password reset request %s approved for '%s' by '%s'", request_id, username, admin_username)
                return True, f"Request approved for {username}. Their account has been unlocked."
            logger.info("Password reset request %s rejected for '%s' by '%s'", request_id, username, admin_username)
            return True, f"Request rejected for {username}."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while approving request %s: %s", request_id, exc)
            return False, "The system is busy right now. Please try again in a moment."

    def get_lockout_remaining(self, username):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("SELECT lockout_until FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            conn.close()
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while checking lockout for username '%s': %s", username, exc)
            return 0
        if not row or not row[0]:
            return 0
        remaining = row[0] - time.time()
        return int(remaining) + 1 if remaining > 0 else 0

    def reset_lockout(self, username):
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?",
                (username,),
            )
            conn.commit()
            conn.close()
            logger.info("Lockout reset for '%s'", username)
            return True, "Account lockout cleared."
        except sqlite3.OperationalError as exc:
            logger.error("Database lock while resetting lockout for '%s': %s", username, exc)
            return False, "The system is busy right now. Please try again in a moment."


class TrackerController:
    def __init__(self, db_name="hardware_inventory.db"):
        self.db_name = str(get_db_path(db_name))

    def fetch_all_items(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id AS item_id, name AS item_name, category, quantity, unit_price, status FROM hardware ORDER BY id"
            )
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch inventory records: %s", exc)
            return []

    def get_total_inventory_value(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(SUM(quantity * unit_price), 0) FROM hardware")
            total = cursor.fetchone()[0]
            conn.close()
            return float(total or 0)
        except sqlite3.Error as exc:
            logger.error("Failed to compute inventory value: %s", exc)
            return 0.0

    @staticmethod
    def friendly_validation_message(raw_messages):
        messages = raw_messages if isinstance(raw_messages, list) else [(raw_messages or "")]
        combined = " ".join(str(message or "") for message in messages).lower()

        if "field cannot be empty" in combined or "empty" in combined:
            return "Please fill in all required fields."
        if "quantity" in combined:
            return "Quantity must be a whole number greater than or equal to zero."
        if "unit price" in combined or "price" in combined:
            return "Unit price must be zero or more."
        if "item_name" in combined or "category" in combined:
            return "Please enter a valid item name and category."
        return "Please check the values and try again."

    def add_item(self, item_name, category, quantity, unit_price, changed_by="ADMIN"):
        try:
            validated = HardwareSchema(item_name=item_name, category=category, quantity=quantity, unit_price=unit_price)
        except ValidationError as exc:
            raw_msgs = [error.get("msg", "") for error in exc.errors()]
            logger.warning("Add inventory validation failed: %s", raw_msgs)
            return False, self.friendly_validation_message(raw_msgs)

        status = self.stock_status(validated.quantity)
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO hardware (name, category, quantity, unit_price, status) VALUES (?, ?, ?, ?, ?)",
                (validated.item_name, validated.category, validated.quantity, validated.unit_price, status),
            )
            cursor.execute(
                """
                INSERT INTO activity_records
                (event_type, item_id, item_name, username, quantity, quantity_delta, occurred_at, details)
                VALUES ('STOCK_ADD', ?, ?, ?, ?, ?, ?, ?)
                """,
                (cursor.lastrowid, validated.item_name, changed_by, validated.quantity, validated.quantity, time.time(), "Item added to inventory"),
            )
            conn.commit()
            conn.close()
            logger.info("New inventory item added: '%s' (%s)", validated.item_name, status)
            return True, f"Saved '{validated.item_name}' with status '{status}'."
        except sqlite3.IntegrityError:
            logger.warning("Duplicate inventory item attempted: %s", item_name)
            return False, f"An item named '{item_name}' already exists."

    def update_item(self, item_id, quantity, unit_price, changed_by="ADMIN"):
        try:
            validated = HardwareSchema(item_name="placeholder", category="placeholder", quantity=quantity, unit_price=unit_price)
        except ValidationError as exc:
            raw_msgs = [error.get("msg", "") for error in exc.errors()]
            logger.warning("Update inventory validation failed: %s", raw_msgs)
            return False, self.friendly_validation_message(raw_msgs)

        status = self.stock_status(validated.quantity)
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT name, quantity FROM hardware WHERE id = ?", (item_id,))
            existing = cursor.fetchone()
            if not existing:
                conn.close()
                return False, f"No record found with ID {item_id}."
            old_name, old_quantity = existing
            cursor.execute(
                "UPDATE hardware SET quantity = ?, unit_price = ?, status = ? WHERE id = ?",
                (validated.quantity, validated.unit_price, status, item_id),
            )
            if cursor.rowcount == 0:
                conn.close()
                logger.warning("Inventory item ID %s was not found for update", item_id)
                return False, f"No record found with ID {item_id}."
            quantity_delta = validated.quantity - old_quantity
            if quantity_delta:
                cursor.execute(
                    """
                    INSERT INTO activity_records
                    (event_type, item_id, item_name, username, quantity, quantity_delta, occurred_at, details)
                    VALUES ('STOCK_UPDATE', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (item_id, old_name, changed_by, validated.quantity, quantity_delta, time.time(), "Inventory quantity updated"),
                )
            conn.commit()
            conn.close()
            logger.info("Inventory item ID %s updated to '%s'", item_id, status)
            return True, f"Updated item ID {item_id}."
        except sqlite3.Error as exc:
            logger.error("Error updating inventory item %s: %s", item_id, exc)
            return False, f"Failed to update item ID {item_id}."

    def delete_item(self, item_id, changed_by="ADMIN"):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT name, quantity FROM hardware WHERE id = ?", (item_id,))
            existing = cursor.fetchone()
            if not existing:
                conn.close()
                return False, f"No record found with ID {item_id}."
            item_name, old_quantity = existing
            cursor.execute("DELETE FROM hardware WHERE id = ?", (item_id,))
            cursor.execute(
                """
                INSERT INTO activity_records
                (event_type, item_id, item_name, username, quantity, quantity_delta, occurred_at, details)
                VALUES ('STOCK_DELETE', ?, ?, ?, ?, ?, ?, ?)
                """,
                (item_id, item_name, changed_by, 0, -old_quantity, time.time(), "Item removed from inventory"),
            )
            conn.commit()
            conn.close()
            if cursor.rowcount > 0:
                logger.info("Inventory item ID %s deleted.", item_id)
                return True, "Record deleted successfully!"
            return False, f"No record found with ID {item_id}."
        except sqlite3.Error as exc:
            logger.error("Error deleting inventory item %s: %s", item_id, exc)
            return False, "Failed to delete record."

    def request_borrow(self, username, item_id, quantity, purpose):
        if quantity < 1 or not purpose.strip():
            return False, "Enter a valid quantity and borrowing purpose."
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT name, quantity FROM hardware WHERE id = ?", (item_id,))
            item = cursor.fetchone()
            if not item:
                conn.close()
                return False, "The selected equipment no longer exists."
            if item[1] < quantity:
                conn.close()
                return False, f"Only {item[1]} unit(s) of '{item[0]}' are available."
            cursor.execute(
                "SELECT 1 FROM borrow_requests WHERE username = ? AND item_id = ? AND status = 'PENDING'",
                (username, item_id),
            )
            if cursor.fetchone():
                conn.close()
                return False, "You already have a pending request for this equipment."
            cursor.execute(
                "INSERT INTO borrow_requests (username, item_id, quantity, purpose, requested_at) VALUES (?, ?, ?, ?, ?)",
                (username, item_id, quantity, purpose.strip(), time.time()),
            )
            conn.commit()
            conn.close()
            logger.info("Borrow request submitted by '%s' for item ID %s", username, item_id)
            return True, "Borrow request submitted for admin approval."
        except sqlite3.Error as exc:
            logger.error("Error creating borrow request: %s", exc)
            return False, "Could not submit the borrow request."

    def get_pending_borrow_requests(self):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT br.id, br.username, COALESCE(u.student_name, ''), COALESCE(u.student_number, ''), COALESCE(u.section, ''), h.name, br.quantity, br.purpose, br.requested_at, br.status
                FROM borrow_requests br JOIN hardware h ON h.id = br.item_id
                LEFT JOIN users u ON u.username = br.username
                WHERE br.status IN ('PENDING', 'APPROVED', 'RETURN_PENDING') ORDER BY br.requested_at DESC
                """
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch borrow requests: %s", exc)
            return []

    def request_return(self, request_id, username):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE borrow_requests
                SET status = 'RETURN_PENDING', requested_at = ?
                WHERE id = ? AND username = ? AND status = 'APPROVED'
                """,
                (time.time(), request_id, username),
            )
            changed = cursor.rowcount
            conn.commit()
            conn.close()
            if changed:
                return True, "Return request submitted for admin approval."
            return False, "Only approved borrowed equipment can be returned."
        except sqlite3.Error as exc:
            logger.error("Error creating return request %s: %s", request_id, exc)
            return False, "Could not submit the return request."

    def decide_return_request(self, request_id, admin_username, decision):
        if decision == "approve":
            return self.return_borrowed_equipment(request_id, admin_username)
        if decision != "reject":
            return False, "Invalid return decision."
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE borrow_requests
                SET status = 'APPROVED', decided_by = ?, decided_at = ?
                WHERE id = ? AND status = 'RETURN_PENDING'
                """,
                (admin_username, time.time(), request_id),
            )
            changed = cursor.rowcount
            conn.commit()
            conn.close()
            if changed:
                return True, "Return request rejected; the equipment remains borrowed."
            return False, "The return request is no longer available."
        except sqlite3.Error as exc:
            logger.error("Error deciding return request %s: %s", request_id, exc)
            return False, "Could not process the return request."

    def get_user_borrow_requests(self, username):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT h.name, br.quantity, br.status, br.requested_at
                FROM borrow_requests br JOIN hardware h ON h.id = br.item_id
                WHERE br.username = ? ORDER BY br.requested_at DESC
                """,
                (username,),
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch borrow history for '%s': %s", username, exc)
            return []

    def get_user_borrow_requests_with_ids(self, username):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT br.id, h.name, br.quantity, br.status, br.requested_at
                FROM borrow_requests br JOIN hardware h ON h.id = br.item_id
                WHERE br.username = ? ORDER BY br.requested_at DESC
                """,
                (username,),
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch borrow history with IDs for '%s': %s", username, exc)
            return []

    def get_user_active_borrowed_items(self, username):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT br.item_id, h.name, br.quantity
                FROM borrow_requests br JOIN hardware h ON h.id = br.item_id
                WHERE br.username = ? AND br.status = 'APPROVED'
                ORDER BY h.name
                """,
                (username,),
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch active borrowed items for '%s': %s", username, exc)
            return []

    def get_user_reports(self, username):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT lr.report_type, COALESCE(h.name, 'Equipment not specified'),
                       lr.details, lr.status, lr.reported_at
                FROM laboratory_reports lr
                LEFT JOIN hardware h ON h.id = lr.item_id
                WHERE lr.username = ? ORDER BY lr.reported_at DESC
                """,
                (username,),
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch reports for '%s': %s", username, exc)
            return []

    def decide_borrow_request(self, request_id, admin_username, decision):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, item_id, quantity FROM borrow_requests WHERE id = ? AND status = 'PENDING'",
                (request_id,),
            )
            request = cursor.fetchone()
            if not request:
                conn.close()
                return False, "The borrow request is no longer available."
            username, item_id, quantity = request
            new_status = "APPROVED" if decision == "approve" else "REJECTED"
            if new_status == "APPROVED":
                cursor.execute("SELECT name, quantity FROM hardware WHERE id = ?", (item_id,))
                item = cursor.fetchone()
                if not item or item[1] < quantity:
                    conn.close()
                    return False, "The request cannot be approved because there is not enough stock."
                new_quantity = item[1] - quantity
                cursor.execute(
                    "UPDATE hardware SET quantity = ?, status = ? WHERE id = ?",
                    (new_quantity, self.stock_status(new_quantity), item_id),
                )
                cursor.execute(
                    """
                    INSERT INTO activity_records
                    (event_type, item_id, item_name, username, quantity, quantity_delta, occurred_at, details)
                    VALUES ('BORROW', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (item_id, item[0], username, quantity, -quantity, time.time(), "Borrow approved"),
                )
            cursor.execute(
                "UPDATE borrow_requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                (new_status, admin_username, time.time(), request_id),
            )
            conn.commit()
            conn.close()
            return True, f"Borrow request {new_status.lower()} for {username}."
        except sqlite3.Error as exc:
            logger.error("Error deciding borrow request %s: %s", request_id, exc)
            return False, "Could not process the borrow request."

    def return_borrowed_equipment(self, request_id, admin_username):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT br.item_id, br.quantity, br.username, h.name
                FROM borrow_requests br JOIN hardware h ON h.id = br.item_id
                WHERE br.id = ? AND br.status IN ('APPROVED', 'RETURN_PENDING')
                """,
                (request_id,),
            )
            request = cursor.fetchone()
            if not request:
                conn.close()
                return False, "Only approved borrowed equipment can be returned."
            item_id, quantity, username, item_name = request
            cursor.execute("SELECT quantity FROM hardware WHERE id = ?", (item_id,))
            item = cursor.fetchone()
            if not item:
                conn.close()
                return False, "The equipment record no longer exists."
            new_quantity = item[0] + quantity
            cursor.execute(
                "UPDATE hardware SET quantity = ?, status = ? WHERE id = ?",
                (new_quantity, self.stock_status(new_quantity), item_id),
            )
            cursor.execute(
                "UPDATE borrow_requests SET status = 'RETURNED', decided_by = ?, decided_at = ? WHERE id = ?",
                (admin_username, time.time(), request_id),
            )
            cursor.execute(
                """
                INSERT INTO activity_records
                (event_type, item_id, item_name, username, quantity, quantity_delta, occurred_at, details)
                VALUES ('RETURN', ?, ?, ?, ?, ?, ?, ?)
                """,
                (item_id, item_name, username, quantity, quantity, time.time(), "Return approved"),
            )
            conn.commit()
            conn.close()
            return True, f"Equipment returned by {username}. Inventory restored."
        except sqlite3.Error as exc:
            logger.error("Error returning borrow request %s: %s", request_id, exc)
            return False, "Could not process the equipment return."

    def get_activity_records(self, limit=100):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                SELECT event_type, item_name, username, quantity, quantity_delta, occurred_at, details
                FROM activity_records ORDER BY occurred_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch activity records: %s", exc)
            return []

    def submit_report(self, username, report_type, item_id, details):
        if report_type not in {"Broken", "Missing"}:
            return False, "Reports can only be submitted for broken or missing equipment."
        if item_id is None:
            return False, "Select equipment that you are currently borrowing."
        if not details.strip():
            return False, "Please describe the broken or missing equipment."
        try:
            conn = sqlite3.connect(self.db_name)
            borrowed = conn.execute(
                "SELECT 1 FROM borrow_requests WHERE username = ? AND item_id = ? AND status = 'APPROVED'",
                (username, item_id),
            ).fetchone()
            if not borrowed:
                conn.close()
                return False, "You can only report equipment that you are currently borrowing."
            conn.execute(
                "INSERT INTO laboratory_reports (username, report_type, item_id, details, reported_at) VALUES (?, ?, ?, ?, ?)",
                (username, report_type, item_id, details.strip(), time.time()),
            )
            conn.commit()
            conn.close()
            return True, "Report submitted to the administrator."
        except sqlite3.Error as exc:
            logger.error("Error submitting laboratory report: %s", exc)
            return False, "Could not submit the report."

    def get_open_reports(self):
        try:
            conn = sqlite3.connect(self.db_name)
            rows = conn.execute(
                """
                    SELECT lr.id, lr.username, COALESCE(u.student_name, ''), COALESCE(u.student_number, ''),
                         lr.report_type, COALESCE(h.name, 'Equipment not specified'),
                      lr.details, lr.reported_at
                    FROM laboratory_reports lr
                    LEFT JOIN users u ON u.username = lr.username
                    LEFT JOIN hardware h ON h.id = lr.item_id
                WHERE lr.status = 'OPEN' ORDER BY lr.reported_at DESC
                """
            ).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch laboratory reports: %s", exc)
            return []

    def close_report(self, report_id, admin_username):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE laboratory_reports SET status = 'RESOLVED', reviewed_by = ? WHERE id = ? AND status = 'OPEN'",
                (admin_username, report_id),
            )
            conn.commit()
            changed = cursor.rowcount
            conn.close()
            return (True, "Report marked as resolved.") if changed else (False, "The report is no longer open.")
        except sqlite3.Error as exc:
            logger.error("Error closing laboratory report %s: %s", report_id, exc)
            return False, "Could not update the report."

    def add_schedule(self, section, subject, instructor, room, schedule_date, start_time, end_time, admin_username):
        values = [section, subject, instructor, room, schedule_date, start_time, end_time]
        if any(not str(value).strip() for value in values):
            return False, "Please complete all schedule fields."
        weekdays = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
        if schedule_date.strip().lower() not in weekdays:
            return False, "Day must be Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, or Saturday."
        schedule_date = schedule_date.strip().capitalize()
        if start_time >= end_time:
            return False, "End time must be later than start time."
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 1 FROM laboratory_schedules
                WHERE room = ? AND schedule_date = ? AND start_time < ? AND end_time > ?
                """,
                (room.strip(), schedule_date.strip(), end_time.strip(), start_time.strip()),
            )
            if cursor.fetchone():
                conn.close()
                return False, "That room already has an overlapping schedule."
            cursor.execute(
                """
                INSERT INTO laboratory_schedules
                (section, subject, instructor, room, schedule_date, start_time, end_time, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*[str(value).strip() for value in values], admin_username, time.time()),
            )
            conn.commit()
            conn.close()
            return True, "Laboratory schedule added successfully."
        except sqlite3.Error as exc:
            logger.error("Error adding laboratory schedule: %s", exc)
            return False, "Could not add the laboratory schedule."

    def get_schedules(self, section=None):
        try:
            conn = sqlite3.connect(self.db_name)
            query = "SELECT id, section, subject, instructor, room, schedule_date, start_time, end_time FROM laboratory_schedules"
            params = ()
            if section:
                query += " WHERE section = ?"
                params = (section,)
            query += " ORDER BY CASE schedule_date WHEN 'Sunday' THEN 1 WHEN 'Monday' THEN 2 WHEN 'Tuesday' THEN 3 WHEN 'Wednesday' THEN 4 WHEN 'Thursday' THEN 5 WHEN 'Friday' THEN 6 WHEN 'Saturday' THEN 7 ELSE 8 END, start_time"
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return rows
        except sqlite3.Error as exc:
            logger.error("Failed to fetch laboratory schedules: %s", exc)
            return []

    def delete_schedule(self, schedule_id):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM laboratory_schedules WHERE id = ?", (schedule_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            conn.close()
            if deleted:
                return True, "Schedule deleted successfully."
            return False, "The selected schedule no longer exists."
        except sqlite3.Error as exc:
            logger.error("Failed to delete laboratory schedule %s: %s", schedule_id, exc)
            return False, "Could not delete the schedule."

    def export_inventory_csv(self, path):
        rows = self.fetch_all_items()
        try:
            with open(path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["ID", "Name", "Category", "Qty", "Price ($)", "Status"])
                for row in rows:
                    writer.writerow(row)
            logger.info("Inventory report exported to %s", path)
            return True, f"Inventory exported to {Path(path).name}."
        except OSError as exc:
            logger.error("Inventory export failed: %s", exc)
            return False, "Failed to export inventory report."

    @staticmethod
    def stock_status(quantity):
        if quantity > 5:
            return "In Stock"
        if 1 <= quantity <= 5:
            return "Low Stock"
        return "Out of Stock"


class LoginWindow:
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.auth = AuthController()
        self.root.title("System Auth")
        self.root.geometry("460x700")
        self.root.resizable(False, False)
        self.root.configure(bg=APP_BG)

        tk.Label(root, text="CAMPUS HARDWARE INVENTORY", bg=APP_NAVY, fg="white", font=("Segoe UI", 15, "bold"), pady=14).pack(fill="x")
        tk.Label(root, text="Computer Engineering Laboratory Portal", bg=APP_BG, fg=APP_TEXT, font=("Segoe UI", 10)).pack(pady=(12, 4))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        self.login_tab = ttk.Frame(self.notebook)
        self.register_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.register_tab, text="Register")

        self._build_login_tab()
        self._build_register_tab()

    def _build_login_tab(self):
        tk.Label(self.login_tab, text="Username:").pack(anchor="w", padx=30, pady=(20, 0))
        self.entry_user = tk.Entry(self.login_tab, width=32)
        self.entry_user.pack(padx=30, pady=(0, 10))

        tk.Label(self.login_tab, text="Password:").pack(anchor="w", padx=30)
        self.entry_pass = tk.Entry(self.login_tab, show="*", width=32)
        self.entry_pass.pack(padx=30, pady=(0, 5))

        self.login_show_password_var = tk.BooleanVar(value=False)
        self.login_show_password_button = tk.Checkbutton(
            self.login_tab,
            text="Show Password",
            variable=self.login_show_password_var,
            onvalue=True,
            offvalue=False,
            command=self.toggle_login_password_visibility,
        )
        self.login_show_password_button.pack(anchor="w", padx=30, pady=(0, 12))

        self.login_button = tk.Button(
            self.login_tab,
            text="Login",
            command=self.handle_login,
            bg=APP_GREEN,
            fg="white",
            width=18,
        )
        self.login_button.pack(pady=(0, 8))

        self.forgot_button = tk.Button(
            self.login_tab,
            text="Reset / Unlock Password",
            command=self.handle_password_reset_request,
            bg=APP_ORANGE,
            fg="white",
            width=18,
        )
        self.forgot_button.pack(pady=(0, 8))

    def _build_register_tab(self):
        tk.Label(self.register_tab, text="Username:").pack(anchor="w", padx=30, pady=(20, 0))
        self.entry_reg_user = tk.Entry(self.register_tab, width=32)
        self.entry_reg_user.pack(padx=30, pady=(0, 10))

        tk.Label(self.register_tab, text="Email:").pack(anchor="w", padx=30)
        self.entry_email = tk.Entry(self.register_tab, width=32)
        self.entry_email.pack(padx=30, pady=(0, 10))

        tk.Label(self.register_tab, text="Student Name:").pack(anchor="w", padx=30)
        self.entry_student_name = tk.Entry(self.register_tab, width=32)
        self.entry_student_name.pack(padx=30, pady=(0, 10))

        tk.Label(self.register_tab, text="Student Number:").pack(anchor="w", padx=30)
        self.entry_student_number = tk.Entry(self.register_tab, width=32)
        self.entry_student_number.pack(padx=30, pady=(0, 10))

        tk.Label(self.register_tab, text="Section:").pack(anchor="w", padx=30)
        self.entry_section = tk.Entry(self.register_tab, width=32)
        self.entry_section.pack(padx=30, pady=(0, 10))

        tk.Label(self.register_tab, text="Password:").pack(anchor="w", padx=30)
        self.entry_reg_pass = tk.Entry(self.register_tab, show="*", width=32)
        self.entry_reg_pass.pack(padx=30, pady=(0, 5))

        tk.Label(self.register_tab, text="Role:").pack(anchor="w", padx=30, pady=(8, 0))
        self.role_var = tk.StringVar(value="USER")
        tk.OptionMenu(self.register_tab, self.role_var, "USER", "ADMIN").pack(anchor="w", padx=30, pady=(0, 8))

        self.register_show_password_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            self.register_tab,
            text="Show Password",
            variable=self.register_show_password_var,
            command=self.toggle_register_password_visibility,
        ).pack(anchor="w", padx=30, pady=(0, 12))

        self.register_button = tk.Button(
            self.register_tab,
            text="Register",
            command=self.handle_register,
            bg=APP_BLUE,
            fg="white",
            width=18,
        )
        self.register_button.pack()

    def toggle_login_password_visibility(self):
        if self.login_show_password_var.get():
            self.entry_pass.configure(show="")
        else:
            self.entry_pass.configure(show="*")
        self.entry_pass.focus_set()

    def toggle_register_password_visibility(self):
        self.entry_reg_pass.config(show="" if self.register_show_password_var.get() else "*")

    def handle_login(self):
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        success, msg = self.auth.login_user(username, password)
        if success:
            if isinstance(msg, dict):
                messagebox.showinfo("Login successful", f"Welcome, {msg.get('username', username)} ({msg.get('role', 'USER')}).")
                self.on_login_success(msg)
            else:
                messagebox.showinfo("Login successful", msg)
                self.on_login_success({"username": username, "role": "USER"})
        elif "locked" in str(msg).lower():
            messagebox.showwarning("Account locked", str(msg))
        elif "username not found" in str(msg).lower():
            messagebox.showerror("Username not found", str(msg))
        elif "password is incorrect" in str(msg).lower():
            messagebox.showerror("Incorrect password", str(msg))
        else:
            messagebox.showerror("Login problem", str(msg))

    def handle_register(self):
        username = self.entry_reg_user.get().strip()
        email = self.entry_email.get().strip()
        student_name = self.entry_student_name.get().strip()
        student_number = self.entry_student_number.get().strip()
        section = self.entry_section.get().strip()
        password = self.entry_reg_pass.get().strip()
        role = self.role_var.get().strip().upper()

        success, msg = self.auth.register_user(
            username,
            email,
            password,
            role,
            student_name,
            student_number,
            section,
        )
        if success:
            messagebox.showinfo("Account created", msg)
            self.notebook.select(0)
            self.entry_user.delete(0, tk.END)
            self.entry_user.insert(0, username)
            self.entry_pass.delete(0, tk.END)
            self.entry_reg_user.delete(0, tk.END)
            self.entry_email.delete(0, tk.END)
            self.entry_student_name.delete(0, tk.END)
            self.entry_student_number.delete(0, tk.END)
            self.entry_section.delete(0, tk.END)
            self.entry_reg_pass.delete(0, tk.END)
            self.role_var.set("USER")
        else:
            messagebox.showwarning("Registration issue", msg)

    def handle_password_reset_request(self):
        username = self.entry_user.get().strip()
        if not username:
            messagebox.showwarning("Missing username", "Please enter your username first.")
            return

        email = simpledialog.askstring("Password reset", "Enter your email to request a reset:", parent=self.root)
        if not email:
            messagebox.showwarning("Missing details", "Please enter your email to request a reset.")
            return

        reset_status = self.auth.get_latest_reset_status(username, email)
        if reset_status == "APPROVED":
            new_password = simpledialog.askstring(
                "Password reset approved",
                "Your reset request was approved. Enter your new password:",
                show="*",
                parent=self.root,
            )
            if new_password is None:
                return
            success, msg = self.auth.change_password(username, new_password.strip())
            if success:
                messagebox.showinfo("Password updated", msg)
            else:
                messagebox.showerror("Password update failed", msg)
            return

        success, msg = self.auth.request_password_reset(username, email)
        if success:
            messagebox.showinfo("Reset request sent", msg)
        else:
            messagebox.showerror("Reset request failed", msg)


class TrackerWindow:
    def __init__(self, root, on_logout=None, current_user=None):
        self.root = root
        self.on_logout = on_logout
        self.current_user = current_user or {"username": "user", "role": "USER"}
        self.controller = TrackerController()
        self.auth_controller = AuthController()
        self.refresh_job = None

        self.root.title("Campus Hardware Inventory")
        self.root.geometry("1180x860")
        self.root.resizable(True, True)
        self.root.configure(bg=APP_BG)

        self.summary_var = tk.StringVar(value="Inventory Value: $0.00")
        self.user_label_var = tk.StringVar(value=f"User: {self.current_user.get('username', 'user')} | Role: {str(self.current_user.get('role', 'USER')).upper()}")

        self.summary_bar = tk.Label(
            self.root,
            textvariable=self.summary_var,
            bg=APP_NAVY,
            fg="white",
            font=("Segoe UI", 13, "bold"),
            pady=8,
        )
        self.summary_bar.pack(fill="x", padx=10, pady=(8, 0))

        self.user_bar = tk.Label(
            self.root,
            textvariable=self.user_label_var,
            bg=APP_BLUE,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            pady=6,
        )
        self.user_bar.pack(fill="x", padx=10, pady=(0, 8))

        form_frame = tk.LabelFrame(self.root, text="  Add Hardware  ", fg=APP_NAVY, padx=12, pady=10)
        form_frame.pack(fill="x", padx=14, pady=8)

        tk.Label(form_frame, text="Item Name:").grid(row=0, column=0, sticky="e")
        self.entry_name = tk.Entry(form_frame, width=28)
        self.entry_name.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Category:").grid(row=0, column=2, sticky="e")
        self.entry_category = tk.Entry(form_frame, width=22)
        self.entry_category.grid(row=0, column=3, padx=5, pady=5)

        tk.Label(form_frame, text="Quantity:").grid(row=1, column=0, sticky="e")
        self.entry_quantity = tk.Entry(form_frame, width=15)
        self.entry_quantity.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Unit Price ($):").grid(row=1, column=2, sticky="e")
        self.entry_unit_price = tk.Entry(form_frame, width=15)
        self.entry_unit_price.grid(row=1, column=3, padx=5, pady=5)

        self.add_item_button = tk.Button(form_frame, text="Save Item", command=self.add_item, bg=APP_GREEN, fg="white", width=14)
        self.add_item_button.grid(row=0, column=4, rowspan=2, padx=10, pady=5, sticky="ns")
        self.add_schedule_button = tk.Button(form_frame, text="Add Schedule", command=self.add_schedule, bg=APP_BLUE, fg="white", width=14)
        self.add_schedule_button.grid(row=0, column=5, padx=5, pady=5)
        self.view_schedule_button = tk.Button(form_frame, text="View Schedule", command=self.view_schedule, bg=APP_TEAL, fg="white", width=14)
        self.view_schedule_button.grid(row=1, column=5, padx=5, pady=5)

        workspace_row = tk.Frame(self.root, bg=APP_BG)
        workspace_row.pack(fill="x", expand=False, padx=14, pady=5)

        table_frame = tk.Frame(workspace_row)
        table_frame.pack(side=tk.LEFT, fill="both", padx=(0, 6))
        table_frame.configure(width=650)
        table_frame.configure(height=220)
        table_frame.pack_propagate(False)

        self.tree = ttk.Treeview(
            table_frame,
            columns=("item_id", "item_name", "category", "quantity", "unit_price", "status"),
            show="headings",
        )
        self.tree.heading("item_id", text="ID", anchor="center", command=lambda: self.sort_inventory("item_id"))
        self.tree.heading("item_name", text="Name", anchor="center", command=lambda: self.sort_inventory("item_name"))
        self.tree.heading("category", text="Category", anchor="center", command=lambda: self.sort_inventory("category"))
        self.tree.heading("quantity", text="Qty", anchor="center", command=lambda: self.sort_inventory("quantity"))
        self.tree.heading("unit_price", text="Price ($)", anchor="center")
        self.tree.heading("status", text="Status", anchor="center", command=lambda: self.sort_inventory("status"))

        self.inventory_sort_column = None
        self.inventory_sort_reverse = False

        self.tree.column("item_id", width=45, anchor="center")
        self.tree.column("item_name", width=145, anchor="center")
        self.tree.column("category", width=115, anchor="center")
        self.tree.column("quantity", width=55, anchor="center")
        self.tree.column("unit_price", width=90, anchor="center")
        self.tree.column("status", width=100, anchor="center")

        self.tree.tag_configure("Out of Stock", background="#fbe4e2", foreground="#8b2e25")
        self.tree.tag_configure("Low Stock", background="#fff1cf", foreground="#795b12")
        self.tree.tag_configure("In Stock", background="#d9eee6", foreground="#176044")

        scrollbar_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        self.tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        action_row = tk.Frame(self.root)
        action_row.pack(fill="x", padx=10, pady=(0, 5))
        self.borrow_button = tk.Button(action_row, text="Borrow Selected", command=self.request_borrow, bg=APP_TEAL, fg="white", width=17)
        self.borrow_button.pack(side=tk.LEFT, padx=5)
        self.report_button = tk.Button(action_row, text="Report Equipment", command=self.submit_report, bg=APP_ORANGE, fg="white", width=20)
        self.report_button.pack(side=tk.LEFT, padx=5)
        self.delete_item_button = tk.Button(action_row, text="Delete Selected Item", command=self.delete_item, bg=APP_RED, fg="white", width=20)
        self.delete_item_button.pack(side=tk.LEFT, padx=5)
        tk.Button(action_row, text="Export Inventory to CSV", command=self.export_report, bg="#6f42c1", fg="white", width=22).pack(side=tk.LEFT, padx=5)

        utility_row = tk.Frame(self.root, bg=APP_BG)
        utility_row.pack(fill="x", padx=14, pady=5)

        update_frame = tk.LabelFrame(utility_row, text="  Edit Selected Equipment  ", fg=APP_NAVY, padx=12, pady=10)
        update_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=(0, 6))

        tk.Label(update_frame, text="New Quantity:").grid(row=0, column=0, sticky="e")
        self.entry_update_quantity = tk.Entry(update_frame, width=15)
        self.entry_update_quantity.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(update_frame, text="New Unit Price ($):").grid(row=0, column=2, sticky="e")
        self.entry_update_unit_price = tk.Entry(update_frame, width=15)
        self.entry_update_unit_price.grid(row=0, column=3, padx=5, pady=5)

        self.update_item_button = tk.Button(update_frame, text="Update Item", command=self.update_item, bg="#2196F3", fg="white", width=14)
        self.update_item_button.grid(row=1, column=1, padx=10, pady=(2, 5), sticky="w")

        self.security_frame = tk.LabelFrame(utility_row, text="  Account & Security  ", fg=APP_NAVY, padx=12, pady=10)
        self.security_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=(6, 0))

        self.profile_var = tk.StringVar(value="Profile: not loaded")
        tk.Label(self.security_frame, textvariable=self.profile_var, anchor="w").pack(fill="x", padx=5, pady=(0, 8))

        self.password_entry = tk.Entry(self.security_frame, width=25, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self.security_frame, text="Change Password", command=self.change_password, bg="#4CAF50", fg="white", width=16).pack(side=tk.LEFT, padx=5)

        self.reset_request_button = tk.Button(self.security_frame, text="Request Reset", command=self.request_reset, bg="#FF9800", fg="white", width=16)
        self.reset_request_button.pack(side=tk.LEFT, padx=5)

        self.logout_button = tk.Button(self.security_frame, text="Logout", command=self.logout, bg="#555555", fg="white", width=12)
        self.logout_button.pack(side=tk.LEFT, padx=5)

        if str(self.current_user.get("role", "")).upper() == "ADMIN":
            borrow_panel = tk.LabelFrame(workspace_row, text="Borrow Requests", padx=8, pady=8)
            borrow_panel.pack(side=tk.LEFT, fill="both", expand=True, padx=(6, 0))
            borrow_controls = tk.Frame(borrow_panel)
            borrow_controls.pack(fill="x", pady=(0, 4))
            tk.Button(borrow_controls, text="Accept Borrow", command=self.approve_borrow_request, bg="#2E7D32", fg="white", width=15).pack(side=tk.LEFT, padx=5)
            tk.Button(borrow_controls, text="Reject Borrow", command=self.reject_borrow_request, bg="#C62828", fg="white", width=15).pack(side=tk.LEFT, padx=5)
            tk.Button(borrow_controls, text="Equipment Returned", command=self.return_borrowed_equipment, bg="#1565C0", fg="white", width=18).pack(side=tk.LEFT, padx=5)
            self.borrow_student_mode = "name"
            self.borrow_tree = ttk.Treeview(borrow_panel, columns=("student", "section", "item", "quantity", "requested_at", "status"), show="headings", height=5)
            for column, heading in (("student", "Student"), ("section", "Section"), ("item", "Equipment"), ("quantity", "Qty"), ("requested_at", "Requested At"), ("status", "Status")):
                self.borrow_tree.heading(column, text=heading, anchor="center")
            self.borrow_tree.heading("student", command=self.toggle_borrow_student_column)
            self.borrow_tree.column("student", width=125, anchor="center")
            self.borrow_tree.column("section", width=60, anchor="center")
            self.borrow_tree.column("item", width=95, anchor="center")
            self.borrow_tree.column("quantity", width=35, anchor="center")
            self.borrow_tree.column("requested_at", width=145, anchor="center")
            self.borrow_tree.column("status", width=70, anchor="center")
            self.borrow_tree.pack(fill="x", expand=True, padx=5)

            self.admin_frame = tk.LabelFrame(self.root, text="Admin Requests and Reports", fg=APP_NAVY, padx=10, pady=10)
            self.admin_frame.pack(fill="x", padx=14, pady=5)

            admin_columns = tk.Frame(self.admin_frame)
            admin_columns.pack(fill="x", expand=True)

            reset_panel = tk.LabelFrame(admin_columns, text="Password Reset Requests", padx=5, pady=5)
            reset_panel.pack(side=tk.LEFT, fill="both", expand=True, padx=(0, 5))

            self.admin_controls = tk.Frame(reset_panel)
            self.admin_controls.pack(fill="x", pady=(0, 8))
            self.approve_button = tk.Button(self.admin_controls, text="Approve", command=self.approve_reset_request, bg="#2E7D32", fg="white", width=12)
            self.approve_button.pack(side=tk.LEFT, padx=5)
            self.reject_button = tk.Button(self.admin_controls, text="Reject", command=self.reject_reset_request, bg="#C62828", fg="white", width=12)
            self.reject_button.pack(side=tk.LEFT, padx=5)

            self.admin_tree = ttk.Treeview(reset_panel, columns=("id", "username", "email", "status"), show="headings", height=5)
            self.admin_tree.heading("id", text="ID", anchor="center")
            self.admin_tree.heading("username", text="Username", anchor="center")
            self.admin_tree.heading("email", text="Email", anchor="center")
            self.admin_tree.heading("status", text="Status", anchor="center")
            self.admin_tree.pack(fill="x", expand=True, padx=5)
            self.admin_tree.column("id", width=60, anchor="center")
            self.admin_tree.column("username", width=160, anchor="center")
            self.admin_tree.column("email", width=220, anchor="center")
            self.admin_tree.column("status", width=100)
            self.refresh_admin_requests()

            report_panel = tk.LabelFrame(admin_columns, text="Open Reports", padx=5, pady=5)
            report_panel.pack(side=tk.LEFT, fill="both", expand=True, padx=(5, 0))
            report_controls = tk.Frame(report_panel)
            report_controls.pack(fill="x", pady=(0, 4))
            tk.Button(report_controls, text="Mark Report Resolved", command=self.resolve_report, bg="#1565C0", fg="white", width=20).pack(side=tk.LEFT, padx=5)
            self.report_student_mode = "name"
            self.report_tree = ttk.Treeview(report_panel, columns=("student", "type", "item", "details"), show="headings", height=5)
            for column, heading in (("student", "Reporter"), ("type", "Type"), ("item", "Equipment"), ("details", "Details")):
                self.report_tree.heading(column, text=heading, anchor="center")
            self.report_tree.heading("student", command=self.toggle_report_student_column)
            self.report_tree.column("student", width=135, anchor="center")
            self.report_tree.column("type", width=130, anchor="center")
            self.report_tree.column("item", width=150, anchor="center")
            self.report_tree.column("details", width=260, anchor="center")
            self.report_tree.pack(fill="x", expand=True, padx=5)
            self.refresh_borrow_requests()
            self.refresh_reports()
        else:
            self.my_borrow_panel = tk.LabelFrame(workspace_row, text="My Borrowed Equipment", padx=8, pady=8)
            self.my_borrow_panel.pack(side=tk.LEFT, fill="both", expand=True, padx=(6, 0))
            self.my_borrow_tree = ttk.Treeview(
                self.my_borrow_panel,
                columns=("item", "quantity", "status", "requested_at"),
                show="headings",
                height=5,
            )
            for column, heading in (("item", "Equipment"), ("quantity", "Qty"), ("status", "Status"), ("requested_at", "Requested At")):
                self.my_borrow_tree.heading(column, text=heading, anchor="center")
            self.my_borrow_tree.column("item", width=135, anchor="center")
            self.my_borrow_tree.column("quantity", width=50, anchor="center")
            self.my_borrow_tree.column("status", width=90, anchor="center")
            self.my_borrow_tree.column("requested_at", width=125, anchor="center")
            self.my_borrow_tree.tag_configure("APPROVED", background="#d9eee6", foreground="#176044")
            self.my_borrow_tree.tag_configure("PENDING", background="#fff1cf", foreground="#795b12")
            self.my_borrow_tree.tag_configure("REJECTED", background="#fbe4e2", foreground="#8b2e25")
            self.my_borrow_tree.pack(fill="both", expand=True, padx=5)
            self.refresh_my_borrow_requests()

        button_row = tk.Frame(self.root)
        button_row.pack(fill="x", padx=10, pady=(0, 10))

        self.apply_role_permissions()
        self.refresh_table()
        self.refresh_total_value()
        self.load_profile()
        self.schedule_auto_refresh()
        if self.current_user.get("password_reset_required"):
            self.root.after(100, self.prompt_password_reset)

    def apply_role_permissions(self):
        is_admin = str(self.current_user.get("role", "USER")).upper() == "ADMIN"
        self.borrow_button.config(state="disabled" if is_admin else "normal")
        self.report_button.config(state="disabled" if is_admin else "normal")
        self.add_schedule_button.config(state="normal" if is_admin else "disabled")
        self.add_item_button.config(state="normal" if is_admin else "disabled")
        self.update_item_button.config(state="normal" if is_admin else "disabled")
        self.delete_item_button.config(state="normal" if is_admin else "disabled")
        self.password_entry.config(state="normal")
        if not is_admin:
            self.entry_name.config(state="disabled")
            self.entry_category.config(state="disabled")
            self.entry_quantity.config(state="disabled")
            self.entry_unit_price.config(state="disabled")
            self.entry_update_quantity.config(state="disabled")
            self.entry_update_unit_price.config(state="disabled")
        else:
            self.entry_name.config(state="normal")
            self.entry_category.config(state="normal")
            self.entry_quantity.config(state="normal")
            self.entry_unit_price.config(state="normal")
            self.entry_update_quantity.config(state="normal")
            self.entry_update_unit_price.config(state="normal")

    def load_profile(self):
        profile = self.auth_controller.get_user_profile(self.current_user.get("username"))
        if profile:
            self.profile_var.set(
                f"Profile: {profile.get('username')} | {profile.get('email')} | {profile.get('role')} | "
                f"{profile.get('student_name') or 'No student name'} | "
                f"{profile.get('student_number') or 'No student number'} | "
                f"{profile.get('section') or 'No section'}"
            )
        else:
            self.profile_var.set("Profile: unavailable")

    def change_password(self):
        new_password = self.password_entry.get().strip()
        if not new_password:
            messagebox.showwarning("Missing password", "Please enter a new password.")
            return
        success, msg = self.auth_controller.change_password(self.current_user.get("username"), new_password)
        if success:
            self.password_entry.delete(0, tk.END)
            messagebox.showinfo("Password updated", msg)
        else:
            messagebox.showerror("Password update failed", msg)

    def prompt_password_reset(self):
        while True:
            new_password = simpledialog.askstring(
                "Password reset required",
                "An administrator approved your reset request. Enter a new password:",
                show="*",
                parent=self.root,
            )
            if new_password is None:
                messagebox.showwarning(
                    "Password reset required",
                    "You can reset your password later using Change Password.",
                    parent=self.root,
                )
                return
            success, msg = self.auth_controller.change_password(
                self.current_user.get("username"), new_password.strip()
            )
            if success:
                self.current_user["password_reset_required"] = False
                messagebox.showinfo("Password updated", msg, parent=self.root)
                return
            messagebox.showerror("Password update failed", msg, parent=self.root)

    def request_reset(self):
        profile = self.auth_controller.get_user_profile(self.current_user.get("username"))
        if not profile:
            messagebox.showerror("Profile missing", "Could not locate your account profile.")
            return
        success, msg = self.auth_controller.request_password_reset(profile["username"], profile["email"])
        if success:
            messagebox.showinfo("Reset request", msg)
        else:
            messagebox.showerror("Reset request failed", msg)

    def refresh_admin_requests(self):
        if not hasattr(self, "admin_tree"):
            return
        for row in self.admin_tree.get_children():
            self.admin_tree.delete(row)
        requests = self.auth_controller.get_pending_reset_requests()
        for request_id, username, email, requested_at, status in requests:
            self.admin_tree.insert("", "end", values=(request_id, username, email, status))

    def refresh_borrow_requests(self):
        if not hasattr(self, "borrow_tree"):
            return
        for row in self.borrow_tree.get_children():
            self.borrow_tree.delete(row)
        for request_id, username, student_name, student_number, section, item_name, quantity, purpose, requested_at, status in self.controller.get_pending_borrow_requests():
            request_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(requested_at))
            student_value = student_name or username if self.borrow_student_mode == "name" else student_number or username
            self.borrow_tree.insert("", "end", iid=str(request_id), values=(student_value, section, item_name, quantity, request_time, status), tags=(status,))

    def toggle_borrow_student_column(self):
        self.borrow_student_mode = "number" if self.borrow_student_mode == "name" else "name"
        self.borrow_tree.heading("student", text="Student Number" if self.borrow_student_mode == "number" else "Student")
        self.refresh_borrow_requests()

    def refresh_my_borrow_requests(self):
        if not hasattr(self, "my_borrow_tree"):
            return
        for row in self.my_borrow_tree.get_children():
            self.my_borrow_tree.delete(row)
        for item_name, quantity, status, requested_at in self.controller.get_user_borrow_requests(self.current_user.get("username")):
            request_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(requested_at))
            self.my_borrow_tree.insert(
                "",
                "end",
                values=(item_name, quantity, status, request_time),
                tags=(status,),
            )

    def refresh_reports(self):
        if not hasattr(self, "report_tree"):
            return
        selected = self.report_tree.selection()
        selected_report_id = self.report_tree.item(selected[0], "iid") if selected else None
        for row in self.report_tree.get_children():
            self.report_tree.delete(row)
        for report_id, username, student_name, student_number, report_type, item_name, details, reported_at in self.controller.get_open_reports():
            student_value = student_name or username if self.report_student_mode == "name" else student_number or username
            self.report_tree.insert(
                "",
                "end",
                iid=str(report_id),
                values=(student_value, report_type, item_name, details),
            )
        if selected_report_id is not None and self.report_tree.exists(str(selected_report_id)):
            self.report_tree.selection_set(str(selected_report_id))
            self.report_tree.focus(str(selected_report_id))

    def toggle_report_student_column(self):
        self.report_student_mode = "number" if self.report_student_mode == "name" else "name"
        self.report_tree.heading(
            "student",
            text="Student Number" if self.report_student_mode == "number" else "Reporter",
        )
        self.refresh_reports()

    def request_borrow(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No equipment selected", "Choose equipment from the inventory first.")
            return
        values = self.tree.item(selected[0], "values")
        try:
            quantity = int(simpledialog.askstring("Borrow equipment", "How many units do you need?", parent=self.root) or "")
        except ValueError:
            messagebox.showerror("Invalid quantity", "Quantity must be a whole number.")
            return
        purpose = "Student equipment request"
        success, msg = self.controller.request_borrow(self.current_user.get("username"), values[0], quantity, purpose)
        (messagebox.showinfo if success else messagebox.showerror)("Borrow request", msg)

    def choose_report_type(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Report type")
        dialog.geometry("360x180")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="What would you like to report?",
            fg=APP_NAVY,
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(18, 12))

        report_type = tk.StringVar(value="")
        options = (
            ("Broken Equipment", "Broken"),
            ("Missing Equipment", "Missing"),
        )
        for label, value in options:
            tk.Button(
                dialog,
                text=label,
                command=lambda selected=value: (report_type.set(selected), dialog.destroy()),
                bg=APP_ORANGE,
                fg="white",
                width=24,
            ).pack(pady=3)

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        self.root.wait_window(dialog)
        return report_type.get() or None

    def submit_report(self):
        selected = self.tree.selection()
        item_id = selected and self.tree.item(selected[0], "values")[0] or None
        report_type = self.choose_report_type()
        if not report_type:
            return
        details = simpledialog.askstring("Laboratory report", "Describe the broken or missing equipment:", parent=self.root)
        if details is None:
            return
        success, msg = self.controller.submit_report(self.current_user.get("username"), report_type.strip(), item_id, details)
        (messagebox.showinfo if success else messagebox.showerror)("Laboratory report", msg)

    def decide_borrow_request(self, decision):
        selected = self.borrow_tree.selection()
        if not selected:
            messagebox.showwarning("No request selected", "Choose a borrow request first.")
            return
        request_id = self.borrow_tree.item(selected[0], "iid")
        success, msg = self.controller.decide_borrow_request(request_id, self.current_user["username"], decision)
        if success:
            self.refresh_borrow_requests()
            self.refresh_table()
            self.refresh_total_value()
            messagebox.showinfo("Borrow request", msg)
        else:
            messagebox.showerror("Borrow request", msg)

    def approve_borrow_request(self):
        self.decide_borrow_request("approve")

    def reject_borrow_request(self):
        self.decide_borrow_request("reject")

    def return_borrowed_equipment(self):
        selected = self.borrow_tree.selection()
        if not selected:
            messagebox.showwarning("No equipment selected", "Choose an approved borrowed item to return.")
            return
        request_id = self.borrow_tree.item(selected[0], "iid")
        success, msg = self.controller.return_borrowed_equipment(request_id, self.current_user["username"])
        if success:
            self.refresh_borrow_requests()
            self.refresh_table()
            self.refresh_total_value()
            messagebox.showinfo("Equipment returned", msg)
        else:
            messagebox.showerror("Return failed", msg)

    def resolve_report(self):
        selected = self.report_tree.selection()
        if not selected:
            messagebox.showwarning("No report selected", "Choose an open report first.")
            return
        report_id = self.report_tree.item(selected[0], "iid")
        success, msg = self.controller.close_report(report_id, self.current_user["username"])
        if success:
            self.refresh_reports()
            messagebox.showinfo("Report updated", msg)
        else:
            messagebox.showerror("Report update", msg)

    def approve_reset_request(self):
        selected = self.admin_tree.selection()
        if not selected:
            messagebox.showwarning("No request selected", "Choose a password reset request to approve.")
            return
        request_id = self.admin_tree.item(selected[0], "values")[0]
        success, msg = self.auth_controller.approve_reset_request(request_id, self.current_user["username"], "approve")
        if success:
            self.refresh_admin_requests()
            messagebox.showinfo("Request approved", msg)
        else:
            messagebox.showerror("Approval failed", msg)

    def reject_reset_request(self):
        selected = self.admin_tree.selection()
        if not selected:
            messagebox.showwarning("No request selected", "Choose a password reset request to reject.")
            return
        request_id = self.admin_tree.item(selected[0], "values")[0]
        success, msg = self.auth_controller.approve_reset_request(request_id, self.current_user["username"], "reject")
        if success:
            self.refresh_admin_requests()
            messagebox.showinfo("Request rejected", msg)
        else:
            messagebox.showerror("Rejection failed", msg)

    def refresh_table(self, update_form=True):
        selected = self.tree.selection()
        selected_item_id = self.tree.item(selected[0], "values")[0] if selected else None
        self.refresh_selection_to_ignore = None

        self.suppress_row_select = True
        for row in self.tree.get_children():
            self.tree.delete(row)
        for item in self.controller.fetch_all_items():
            item_id, item_name, category, quantity, unit_price, status = item
            item_iid = str(item_id)
            self.tree.insert(
                "",
                "end",
                iid=item_iid,
                values=(item_id, item_name, category, quantity, f"{float(unit_price):.2f}", status),
                tags=(status,),
            )

        if self.inventory_sort_column is not None:
            self.apply_inventory_sort()

        if selected_item_id is not None and self.tree.exists(str(selected_item_id)):
            self.tree.selection_set(str(selected_item_id))
            self.tree.focus(str(selected_item_id))
            if not update_form:
                self.refresh_selection_to_ignore = str(selected_item_id)
        self.suppress_row_select = False

        if update_form and selected_item_id is not None and self.tree.exists(str(selected_item_id)):
            self.on_row_select()

    def sort_inventory(self, column):
        if self.inventory_sort_column == column:
            self.inventory_sort_reverse = not self.inventory_sort_reverse
        else:
            self.inventory_sort_column = column
            self.inventory_sort_reverse = False

        self.apply_inventory_sort()

    def apply_inventory_sort(self):
        selected = self.tree.selection()
        selected_item_id = self.tree.item(selected[0], "values")[0] if selected else None
        rows = [
            (self.tree.set(item_id, self.inventory_sort_column), item_id)
            for item_id in self.tree.get_children("")
        ]

        if self.inventory_sort_column in {"item_id", "quantity"}:
            rows.sort(key=lambda row: int(row[0]), reverse=self.inventory_sort_reverse)
        else:
            rows.sort(key=lambda row: row[0].lower(), reverse=self.inventory_sort_reverse)

        for position, (_, item_id) in enumerate(rows):
            self.tree.move(item_id, "", position)

        if selected_item_id is not None and self.tree.exists(str(selected_item_id)):
            self.tree.selection_set(str(selected_item_id))
            self.tree.focus(str(selected_item_id))

    def refresh_total_value(self):
        total_value = self.controller.get_total_inventory_value()
        self.summary_var.set(f"Inventory Value: ${total_value:,.2f}")

    def on_row_select(self, event=None):
        if getattr(self, "suppress_row_select", False):
            return
        selected = self.tree.selection()
        if not selected:
            return
        selected_item_id = str(self.tree.item(selected[0], "values")[0])
        if selected_item_id == getattr(self, "refresh_selection_to_ignore", None):
            self.refresh_selection_to_ignore = None
            return
        values = self.tree.item(selected[0], "values")
        if values:
            self.entry_update_quantity.delete(0, tk.END)
            self.entry_update_quantity.insert(0, str(values[3]))
            self.entry_update_unit_price.delete(0, tk.END)
            self.entry_update_unit_price.insert(0, str(values[4]))

    def add_item(self):
        item_name = self.entry_name.get().strip()
        category = self.entry_category.get().strip()
        quantity = self.entry_quantity.get().strip()
        unit_price = self.entry_unit_price.get().strip()

        try:
            quantity_value = int(quantity)
        except ValueError:
            messagebox.showerror("Invalid quantity", "Quantity must be a whole number.")
            return

        try:
            unit_price_value = float(unit_price)
        except ValueError:
            messagebox.showerror("Invalid price", "Unit price must be numeric.")
            return

        success, msg = self.controller.add_item(item_name, category, quantity_value, unit_price_value)
        if success:
            self.entry_name.delete(0, tk.END)
            self.entry_category.delete(0, tk.END)
            self.entry_quantity.delete(0, tk.END)
            self.entry_unit_price.delete(0, tk.END)
            self.refresh_table()
            self.refresh_total_value()
            messagebox.showinfo("Item saved", msg)
        else:
            messagebox.showerror("Save failed", msg)

    def add_schedule(self):
        section = simpledialog.askstring("Add schedule", "Section:", parent=self.root)
        if section is None:
            return
        subject = simpledialog.askstring("Add schedule", "Subject or laboratory activity:", parent=self.root)
        if subject is None:
            return
        instructor = simpledialog.askstring("Add schedule", "Instructor:", parent=self.root)
        if instructor is None:
            return
        room = simpledialog.askstring("Add schedule", "Laboratory room:", parent=self.root)
        if room is None:
            return
        schedule_date = self.choose_schedule_day()
        if not schedule_date:
            return
        start_time = simpledialog.askstring("Add schedule", "From time (HH:MM):", parent=self.root)
        if start_time is None:
            return
        end_time = simpledialog.askstring("Add schedule", "To time (HH:MM):", parent=self.root)
        if end_time is None:
            return
        success, msg = self.controller.add_schedule(
            section, subject, instructor, room, schedule_date, start_time, end_time, self.current_user["username"]
        )
        (messagebox.showinfo if success else messagebox.showerror)("Schedule", msg)

    def choose_schedule_day(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add schedule")
        dialog.geometry("330x145")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Choose the schedule day:", fg=APP_NAVY, font=("Segoe UI", 11, "bold")).pack(pady=(15, 8))
        day_var = tk.StringVar(value="Monday")
        day_dropdown = ttk.Combobox(
            dialog,
            textvariable=day_var,
            values=("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"),
            state="readonly",
            width=25,
        )
        day_dropdown.pack(pady=2)

        selected_day = {"value": None}

        def confirm_day():
            selected_day["value"] = day_var.get()
            dialog.destroy()

        tk.Button(dialog, text="Continue", command=confirm_day, bg=APP_BLUE, fg="white", width=14).pack(pady=10)
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        self.root.wait_window(dialog)
        return selected_day["value"]

    def view_schedule(self):
        section = None
        if str(self.current_user.get("role", "USER")).upper() != "ADMIN":
            profile = self.auth_controller.get_user_profile(self.current_user.get("username"))
            section = profile.get("section") if profile else None
            if not section:
                messagebox.showwarning("Section unavailable", "Your account has no registered section.")
                return

        schedules = self.controller.get_schedules(section)
        dialog = tk.Toplevel(self.root)
        dialog.title("Laboratory Schedule" if not section else f"Schedule | {section}")
        dialog.geometry("850x300")
        dialog.transient(self.root)

        title = "All laboratory schedules" if not section else f"Schedules for section {section}"
        tk.Label(dialog, text=title, fg=APP_NAVY, font=("Segoe UI", 12, "bold")).pack(pady=(12, 8))
        schedule_tree = ttk.Treeview(
            dialog,
            columns=("section", "subject", "instructor", "room", "day", "time_range"),
            show="headings",
        )
        for column, heading in (("section", "Section"), ("subject", "Subject"), ("instructor", "Instructor"), ("room", "Room"), ("day", "Day"), ("time_range", "Time Range")):
            schedule_tree.heading(column, text=heading, anchor="center")
        schedule_tree.column("section", width=90, anchor="center", stretch=False)
        schedule_tree.column("subject", width=180, anchor="center", stretch=False)
        schedule_tree.column("instructor", width=180, anchor="center", stretch=False)
        schedule_tree.column("room", width=100, anchor="center", stretch=False)
        schedule_tree.column("day", width=100, anchor="center", stretch=False)
        schedule_tree.column("time_range", width=150, anchor="center", stretch=False)
        for schedule_id, section_name, subject, instructor, room, day, start_time, end_time in schedules:
            schedule_tree.insert(
                "",
                "end",
                iid=str(schedule_id),
                values=(section_name, subject, instructor, room, day, f"{start_time} - {end_time}"),
            )
        schedule_scrollbar = ttk.Scrollbar(dialog, orient=tk.HORIZONTAL, command=schedule_tree.xview)
        schedule_tree.configure(xscrollcommand=schedule_scrollbar.set)
        if not section:
            schedule_action_row = tk.Frame(dialog, bg=APP_BG)
            schedule_action_row.pack(side=tk.BOTTOM, fill="x", padx=12, pady=(8, 12))
            tk.Button(
                schedule_action_row,
                text="Delete Schedule",
                command=lambda: self.delete_selected_schedule(schedule_tree),
                bg=APP_RED,
                fg="white",
                width=18,
            ).pack()
        schedule_scrollbar.pack(side=tk.BOTTOM, fill="x", padx=12, pady=(0, 4))
        schedule_tree.pack(fill="both", expand=True, padx=12, pady=(0, 0))

    def delete_selected_schedule(self, schedule_tree):
        selected = schedule_tree.selection()
        if not selected:
            messagebox.showwarning("No schedule selected", "Choose a schedule to delete.", parent=schedule_tree.winfo_toplevel())
            return
        schedule_id = selected[0]
        success, msg = self.controller.delete_schedule(schedule_id)
        if success:
            schedule_tree.delete(selected[0])
            messagebox.showinfo("Schedule deleted", msg, parent=schedule_tree.winfo_toplevel())
        else:
            messagebox.showerror("Delete failed", msg, parent=schedule_tree.winfo_toplevel())

    def update_item(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No item selected", "Choose an item from the table to update.")
            return

        item_id = self.tree.item(selected[0], "values")[0]
        quantity = self.entry_update_quantity.get().strip()
        unit_price = self.entry_update_unit_price.get().strip()

        try:
            quantity_value = int(quantity)
        except ValueError:
            messagebox.showerror("Invalid quantity", "New quantity must be a whole number.")
            return

        try:
            unit_price_value = float(unit_price)
        except ValueError:
            messagebox.showerror("Invalid price", "New unit price must be numeric.")
            return

        success, msg = self.controller.update_item(item_id, quantity_value, unit_price_value)
        if success:
            current_values = self.tree.item(selected[0], "values")
            updated_status = self.controller.stock_status(quantity_value)
            self.tree.item(
                selected[0],
                values=(
                    item_id,
                    current_values[1],
                    current_values[2],
                    quantity_value,
                    unit_price_value,
                    updated_status,
                ),
                tags=(updated_status,),
            )
            self.refresh_total_value()
            messagebox.showinfo("Item updated", msg)
        else:
            messagebox.showerror("Update failed", msg)

    def delete_item(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No item selected", "Choose an item from the table to delete.")
            return

        item_id = self.tree.item(selected[0], "values")[0]
        success, msg = self.controller.delete_item(item_id)
        if success:
            self.refresh_table()
            self.refresh_total_value()
            messagebox.showinfo("Delete successful", msg)
        else:
            messagebox.showerror("Delete failed", msg)

    def export_report(self):
        export_path = os.path.join(os.getcwd(), "inventory_report.csv")
        success, msg = self.controller.export_inventory_csv(export_path)
        if success:
            messagebox.showinfo("Export complete", msg)
        else:
            messagebox.showerror("Export failed", msg)

    def logout(self):
        if self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)
            self.refresh_job = None
        if self.on_logout:
            self.on_logout()

    def schedule_auto_refresh(self):
        self.refresh_job = self.root.after(2000, self.auto_refresh)

    def auto_refresh(self):
        self.refresh_table(update_form=False)
        self.refresh_total_value()
        if hasattr(self, "admin_tree"):
            self.refresh_admin_requests()
            self.refresh_borrow_requests()
            self.refresh_reports()
        else:
            self.refresh_my_borrow_requests()
        self.schedule_auto_refresh()

    def format_price(self, amount):
        try:
            return f"{float(amount):,.2f}"
        except (TypeError, ValueError):
            return "0.00"


def launch_main_app(root, user=None):
    for widget in root.winfo_children():
        widget.destroy()
    TrackerWindow(root, on_logout=lambda: launch_login_screen(root), current_user=user or {"username": "user", "role": "USER"})


def launch_login_screen(root):
    for widget in root.winfo_children():
        widget.destroy()
    root.geometry("460x700")
    LoginWindow(root, on_login_success=lambda user: launch_main_app(root, user))


def main():
    init_db("hardware_inventory.db")
    root = tk.Tk()
    launch_login_screen(root)
    root.mainloop()


if __name__ == "__main__":
    main()
