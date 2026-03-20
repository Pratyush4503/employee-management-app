"""
Employee Management Application
================================
Features:
- Attendance tracking
- HR data management for 200+ employees
- Role-Based Access Control (RBAC)
- Data security protocols
- MySQL backend
- Tableau-ready CSV export

Tech Stack: Python, MySQL
"""

import mysql.connector
import hashlib
import csv
import os
import getpass
from datetime import date, datetime, timedelta
from functools import wraps

# ─────────────────────────────────────────────
# DATABASE CONFIGURATION
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",   # <-- update this
    "database": "employee_mgmt"
}

# ─────────────────────────────────────────────
# ROLE PERMISSIONS (RBAC)
# ─────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": [
        "view_employees", "add_employee", "edit_employee", "delete_employee",
        "view_attendance", "mark_attendance", "edit_attendance",
        "view_salary", "edit_salary",
        "view_reports", "export_reports",
        "manage_users"
    ],
    "hr": [
        "view_employees", "add_employee", "edit_employee",
        "view_attendance", "mark_attendance",
        "view_salary",
        "view_reports", "export_reports"
    ],
    "manager": [
        "view_employees",
        "view_attendance", "mark_attendance",
        "view_reports"
    ],
    "employee": [
        "view_own_profile",
        "view_own_attendance",
        "view_own_salary"
    ]
}

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def get_connection():
    """Create and return a MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


def initialize_database():
    """Create all required tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Users table (for login/auth)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(64) NOT NULL,
            role ENUM('admin', 'hr', 'manager', 'employee') DEFAULT 'employee',
            employee_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    """)

    # Departments
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            dept_id INT AUTO_INCREMENT PRIMARY KEY,
            dept_name VARCHAR(100) UNIQUE NOT NULL,
            manager_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Employees
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            emp_id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(50) NOT NULL,
            last_name VARCHAR(50) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            phone VARCHAR(15),
            dept_id INT,
            designation VARCHAR(100),
            date_of_joining DATE,
            employment_type ENUM('full_time', 'part_time', 'contract') DEFAULT 'full_time',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
        )
    """)

    # Attendance
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            attendance_id INT AUTO_INCREMENT PRIMARY KEY,
            emp_id INT NOT NULL,
            attendance_date DATE NOT NULL,
            check_in TIME,
            check_out TIME,
            status ENUM('present', 'absent', 'half_day', 'leave', 'holiday') DEFAULT 'absent',
            remarks VARCHAR(255),
            marked_by INT,
            UNIQUE KEY unique_emp_date (emp_id, attendance_date),
            FOREIGN KEY (emp_id) REFERENCES employees(emp_id),
            FOREIGN KEY (marked_by) REFERENCES users(user_id)
        )
    """)

    # Salary
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS salary (
            salary_id INT AUTO_INCREMENT PRIMARY KEY,
            emp_id INT NOT NULL,
            basic_salary DECIMAL(10,2) NOT NULL,
            hra DECIMAL(10,2) DEFAULT 0,
            allowances DECIMAL(10,2) DEFAULT 0,
            deductions DECIMAL(10,2) DEFAULT 0,
            effective_date DATE NOT NULL,
            FOREIGN KEY (emp_id) REFERENCES employees(emp_id)
        )
    """)

    # Access logs (security audit trail)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            log_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(200),
            table_affected VARCHAR(50),
            record_id INT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45),
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("[✓] Database initialized successfully.")


def seed_demo_data():
    """Insert demo admin user and sample data."""
    conn = get_connection()
    cursor = conn.cursor()

    # Admin user (password: admin123)
    admin_hash = hash_password("admin123")
    cursor.execute("""
        INSERT IGNORE INTO users (username, password_hash, role)
        VALUES ('admin', %s, 'admin')
    """, (admin_hash,))

    # HR user (password: hr123)
    hr_hash = hash_password("hr123")
    cursor.execute("""
        INSERT IGNORE INTO users (username, password_hash, role)
        VALUES ('hr_user', %s, 'hr')
    """, (hr_hash,))

    # Departments
    departments = [("Engineering", None), ("Human Resources", None),
                   ("Finance", None), ("Marketing", None), ("Operations", None)]
    cursor.executemany(
        "INSERT IGNORE INTO departments (dept_name) VALUES (%s)", 
        [(d[0],) for d in departments]
    )

    conn.commit()
    cursor.close()
    conn.close()
    print("[✓] Demo data seeded. Login: admin / admin123  OR  hr_user / hr123")


# ─────────────────────────────────────────────
# SECURITY UTILITIES
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def log_action(conn, user_id, action, table=None, record_id=None):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO access_logs (user_id, action, table_affected, record_id)
        VALUES (%s, %s, %s, %s)
    """, (user_id, action, table, record_id))
    conn.commit()
    cursor.close()


# ─────────────────────────────────────────────
# SESSION & AUTH
# ─────────────────────────────────────────────

class Session:
    def __init__(self):
        self.user_id = None
        self.username = None
        self.role = None
        self.employee_id = None

    def login(self, username, password):
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        pw_hash = hash_password(password)
        cursor.execute("""
            SELECT * FROM users
            WHERE username=%s AND password_hash=%s AND is_active=TRUE
        """, (username, pw_hash))
        user = cursor.fetchone()
        if user:
            self.user_id = user["user_id"]
            self.username = user["username"]
            self.role = user["role"]
            self.employee_id = user["employee_id"]
            # Update last login
            cursor.execute("UPDATE users SET last_login=NOW() WHERE user_id=%s", (self.user_id,))
            conn.commit()
            log_action(conn, self.user_id, f"LOGIN: {username}")
        cursor.close()
        conn.close()
        return user is not None

    def logout(self):
        conn = get_connection()
        log_action(conn, self.user_id, "LOGOUT")
        conn.close()
        self.user_id = None
        self.username = None
        self.role = None

    def has_permission(self, permission):
        if not self.role:
            return False
        return permission in ROLE_PERMISSIONS.get(self.role, [])


# Global session
session = Session()


def require_permission(permission):
    """Decorator to enforce RBAC on functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not session.has_permission(permission):
                print(f"\n[✗] Access Denied. Your role '{session.role}' cannot perform '{permission}'.")
                return
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────
# EMPLOYEE MANAGEMENT
# ─────────────────────────────────────────────

@require_permission("view_employees")
def list_employees():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.emp_id, e.first_name, e.last_name, e.email,
               e.designation, d.dept_name, e.date_of_joining,
               e.employment_type, e.is_active
        FROM employees e
        LEFT JOIN departments d ON e.dept_id = d.dept_id
        WHERE e.is_active = TRUE
        ORDER BY e.emp_id
    """)
    employees = cursor.fetchall()
    cursor.close()
    conn.close()

    if not employees:
        print("\n[!] No employees found.")
        return

    print("\n" + "="*90)
    print(f"{'ID':<6} {'Name':<25} {'Email':<30} {'Designation':<20} {'Dept':<15}")
    print("="*90)
    for emp in employees:
        name = f"{emp['first_name']} {emp['last_name']}"
        print(f"{emp['emp_id']:<6} {name:<25} {emp['email']:<30} "
              f"{emp['designation'] or 'N/A':<20} {emp['dept_name'] or 'N/A':<15}")
    print(f"\nTotal employees: {len(employees)}")


@require_permission("add_employee")
def add_employee():
    print("\n─── Add New Employee ───")
    first = input("First Name: ").strip()
    last = input("Last Name: ").strip()
    email = input("Email: ").strip()
    phone = input("Phone: ").strip()
    designation = input("Designation: ").strip()
    doj = input("Date of Joining (YYYY-MM-DD): ").strip()
    emp_type = input("Employment Type (full_time/part_time/contract): ").strip() or "full_time"

    # Show departments
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT dept_id, dept_name FROM departments")
    depts = cursor.fetchall()
    print("\nDepartments:")
    for d in depts:
        print(f"  [{d['dept_id']}] {d['dept_name']}")
    dept_id = input("Department ID: ").strip()

    try:
        cursor.execute("""
            INSERT INTO employees (first_name, last_name, email, phone,
                                   dept_id, designation, date_of_joining, employment_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (first, last, email, phone, dept_id, designation, doj, emp_type))
        conn.commit()
        emp_id = cursor.lastrowid
        log_action(conn, session.user_id, f"ADD_EMPLOYEE: {first} {last}", "employees", emp_id)
        print(f"\n[✓] Employee '{first} {last}' added with ID: {emp_id}")
    except mysql.connector.Error as e:
        print(f"\n[✗] Error: {e}")
    finally:
        cursor.close()
        conn.close()


@require_permission("edit_employee")
def edit_employee():
    emp_id = input("\nEnter Employee ID to edit: ").strip()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM employees WHERE emp_id=%s", (emp_id,))
    emp = cursor.fetchone()
    if not emp:
        print("[!] Employee not found.")
        cursor.close()
        conn.close()
        return

    print(f"\nEditing: {emp['first_name']} {emp['last_name']} (leave blank to keep current)")
    new_designation = input(f"Designation [{emp['designation']}]: ").strip() or emp['designation']
    new_phone = input(f"Phone [{emp['phone']}]: ").strip() or emp['phone']

    cursor.execute("""
        UPDATE employees SET designation=%s, phone=%s WHERE emp_id=%s
    """, (new_designation, new_phone, emp_id))
    conn.commit()
    log_action(conn, session.user_id, f"EDIT_EMPLOYEE", "employees", emp_id)
    print(f"[✓] Employee ID {emp_id} updated.")
    cursor.close()
    conn.close()


@require_permission("delete_employee")
def deactivate_employee():
    emp_id = input("\nEnter Employee ID to deactivate: ").strip()
    confirm = input(f"Are you sure you want to deactivate employee {emp_id}? (yes/no): ").strip()
    if confirm.lower() != "yes":
        print("[!] Operation cancelled.")
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE employees SET is_active=FALSE WHERE emp_id=%s", (emp_id,))
    conn.commit()
    log_action(conn, session.user_id, f"DEACTIVATE_EMPLOYEE", "employees", int(emp_id))
    print(f"[✓] Employee {emp_id} deactivated.")
    cursor.close()
    conn.close()


# ─────────────────────────────────────────────
# ATTENDANCE MANAGEMENT
# ─────────────────────────────────────────────

@require_permission("mark_attendance")
def mark_attendance():
    print("\n─── Mark Attendance ───")
    att_date = input(f"Date (YYYY-MM-DD) [today={date.today()}]: ").strip() or str(date.today())

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT emp_id, first_name, last_name FROM employees WHERE is_active=TRUE
    """)
    employees = cursor.fetchall()

    print(f"\nMarking attendance for {att_date}")
    print("Status options: P=present, A=absent, H=half_day, L=leave\n")

    records = []
    for emp in employees:
        name = f"{emp['first_name']} {emp['last_name']}"
        status_input = input(f"  {emp['emp_id']:>4}. {name:<30} Status [P/A/H/L]: ").strip().upper()
        status_map = {"P": "present", "A": "absent", "H": "half_day", "L": "leave"}
        status = status_map.get(status_input, "absent")

        check_in = None
        check_out = None
        if status in ("present", "half_day"):
            check_in = input(f"         Check-in time (HH:MM) [09:00]: ").strip() or "09:00"
            check_out = input(f"         Check-out time (HH:MM) [18:00]: ").strip() or "18:00"

        records.append((emp["emp_id"], att_date, check_in, check_out, status, session.user_id))

    try:
        cursor.executemany("""
            INSERT INTO attendance (emp_id, attendance_date, check_in, check_out, status, marked_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                check_in=VALUES(check_in), check_out=VALUES(check_out),
                status=VALUES(status), marked_by=VALUES(marked_by)
        """, records)
        conn.commit()
        log_action(conn, session.user_id, f"MARK_ATTENDANCE for {att_date}", "attendance")
        print(f"\n[✓] Attendance marked for {len(records)} employees on {att_date}.")
    except mysql.connector.Error as e:
        print(f"[✗] Error: {e}")
    finally:
        cursor.close()
        conn.close()


@require_permission("view_attendance")
def view_attendance_report():
    print("\n─── Attendance Report ───")
    emp_id = input("Employee ID (leave blank for all): ").strip()
    month = input("Month (YYYY-MM) [current]: ").strip() or datetime.now().strftime("%Y-%m")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT e.emp_id, e.first_name, e.last_name,
               a.attendance_date, a.check_in, a.check_out, a.status
        FROM attendance a
        JOIN employees e ON a.emp_id = e.emp_id
        WHERE DATE_FORMAT(a.attendance_date, '%%Y-%%m') = %s
    """
    params = [month]
    if emp_id:
        query += " AND a.emp_id = %s"
        params.append(emp_id)
    query += " ORDER BY a.attendance_date, e.emp_id"

    cursor.execute(query, params)
    records = cursor.fetchall()
    cursor.close()
    conn.close()

    if not records:
        print("[!] No records found.")
        return

    print(f"\n{'EmpID':<8} {'Name':<25} {'Date':<14} {'Check-in':<12} {'Check-out':<12} {'Status'}")
    print("-"*85)
    for r in records:
        name = f"{r['first_name']} {r['last_name']}"
        print(f"{r['emp_id']:<8} {name:<25} {str(r['attendance_date']):<14} "
              f"{str(r['check_in'] or 'N/A'):<12} {str(r['check_out'] or 'N/A'):<12} {r['status']}")

    # Summary
    from collections import Counter
    status_count = Counter(r["status"] for r in records)
    print(f"\n── Summary for {month} ──")
    for status, count in status_count.items():
        print(f"  {status.capitalize():<15}: {count}")


# ─────────────────────────────────────────────
# SALARY MANAGEMENT
# ─────────────────────────────────────────────

@require_permission("edit_salary")
def set_salary():
    emp_id = input("\nEmployee ID: ").strip()
    basic = float(input("Basic Salary (₹): ").strip())
    hra = float(input("HRA (₹): ").strip() or 0)
    allowances = float(input("Allowances (₹): ").strip() or 0)
    deductions = float(input("Deductions (₹): ").strip() or 0)
    effective = input("Effective Date (YYYY-MM-DD): ").strip() or str(date.today())

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO salary (emp_id, basic_salary, hra, allowances, deductions, effective_date)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (emp_id, basic, hra, allowances, deductions, effective))
    conn.commit()
    log_action(conn, session.user_id, "SET_SALARY", "salary", int(emp_id))
    net = basic + hra + allowances - deductions
    print(f"\n[✓] Salary set. Net Pay: ₹{net:,.2f}")
    cursor.close()
    conn.close()


@require_permission("view_salary")
def view_salary():
    emp_id = input("\nEmployee ID: ").strip()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.first_name, e.last_name, s.*
        FROM salary s JOIN employees e ON s.emp_id = e.emp_id
        WHERE s.emp_id = %s ORDER BY s.effective_date DESC LIMIT 1
    """, (emp_id,))
    rec = cursor.fetchone()
    cursor.close()
    conn.close()

    if not rec:
        print("[!] No salary record found.")
        return

    net = rec["basic_salary"] + rec["hra"] + rec["allowances"] - rec["deductions"]
    print(f"\n─── Salary Details: {rec['first_name']} {rec['last_name']} ───")
    print(f"  Basic Salary  : ₹{rec['basic_salary']:>12,.2f}")
    print(f"  HRA           : ₹{rec['hra']:>12,.2f}")
    print(f"  Allowances    : ₹{rec['allowances']:>12,.2f}")
    print(f"  Deductions    : ₹{rec['deductions']:>12,.2f}")
    print(f"  {'─'*30}")
    print(f"  Net Pay       : ₹{net:>12,.2f}")
    print(f"  Effective Date: {rec['effective_date']}")


# ─────────────────────────────────────────────
# REPORTS & EXPORT (Tableau-ready CSV)
# ─────────────────────────────────────────────

@require_permission("export_reports")
def export_attendance_csv():
    month = input("Export Month (YYYY-MM) [current]: ").strip() or datetime.now().strftime("%Y-%m")
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.emp_id, e.first_name, e.last_name, d.dept_name,
               e.designation, a.attendance_date, a.check_in,
               a.check_out, a.status
        FROM attendance a
        JOIN employees e ON a.emp_id = e.emp_id
        LEFT JOIN departments d ON e.dept_id = d.dept_id
        WHERE DATE_FORMAT(a.attendance_date, '%%Y-%%m') = %s
        ORDER BY a.attendance_date, e.emp_id
    """, (month,))
    records = cursor.fetchall()
    cursor.close()
    conn.close()

    filename = f"attendance_report_{month}.csv"
    os.makedirs("exports", exist_ok=True)
    filepath = os.path.join("exports", filename)

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "emp_id", "first_name", "last_name", "dept_name",
            "designation", "attendance_date", "check_in", "check_out", "status"
        ])
        writer.writeheader()
        writer.writerows(records)

    print(f"\n[✓] Exported {len(records)} records to '{filepath}' (Tableau-ready)")


@require_permission("export_reports")
def export_salary_csv():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.emp_id, e.first_name, e.last_name, d.dept_name,
               e.designation, s.basic_salary, s.hra, s.allowances,
               s.deductions,
               (s.basic_salary + s.hra + s.allowances - s.deductions) AS net_pay,
               s.effective_date
        FROM salary s
        JOIN employees e ON s.emp_id = e.emp_id
        LEFT JOIN departments d ON e.dept_id = d.dept_id
        ORDER BY s.effective_date DESC
    """)
    records = cursor.fetchall()
    cursor.close()
    conn.close()

    os.makedirs("exports", exist_ok=True)
    filepath = "exports/salary_report.csv"
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys() if records else [])
        writer.writeheader()
        writer.writerows(records)

    print(f"[✓] Salary report exported to '{filepath}'")


# ─────────────────────────────────────────────
# USER MANAGEMENT (Admin only)
# ─────────────────────────────────────────────

@require_permission("manage_users")
def add_user():
    print("\n─── Add System User ───")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    role = input("Role (admin/hr/manager/employee): ").strip()
    emp_id = input("Link to Employee ID (optional): ").strip() or None

    conn = get_connection()
    cursor = conn.cursor()
    pw_hash = hash_password(password)
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, employee_id)
            VALUES (%s, %s, %s, %s)
        """, (username, pw_hash, role, emp_id))
        conn.commit()
        log_action(conn, session.user_id, f"ADD_USER: {username}", "users")
        print(f"[✓] User '{username}' created with role '{role}'.")
    except mysql.connector.Error as e:
        print(f"[✗] Error: {e}")
    finally:
        cursor.close()
        conn.close()


@require_permission("manage_users")
def view_access_logs():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT al.log_id, u.username, al.action, al.table_affected,
               al.record_id, al.timestamp
        FROM access_logs al
        LEFT JOIN users u ON al.user_id = u.user_id
        ORDER BY al.timestamp DESC
        LIMIT 50
    """)
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    print(f"\n{'ID':<6} {'User':<15} {'Action':<40} {'Table':<15} {'Timestamp'}")
    print("-"*100)
    for log in logs:
        print(f"{log['log_id']:<6} {log['username'] or 'N/A':<15} "
              f"{log['action']:<40} {log['table_affected'] or 'N/A':<15} "
              f"{log['timestamp']}")


# ─────────────────────────────────────────────
# MENUS
# ─────────────────────────────────────────────

def employee_menu():
    while True:
        print("\n══ Employee Management ══")
        print("  1. List All Employees")
        print("  2. Add New Employee")
        print("  3. Edit Employee")
        print("  4. Deactivate Employee")
        print("  0. Back")
        choice = input("Choice: ").strip()
        if choice == "1": list_employees()
        elif choice == "2": add_employee()
        elif choice == "3": edit_employee()
        elif choice == "4": deactivate_employee()
        elif choice == "0": break


def attendance_menu():
    while True:
        print("\n══ Attendance Management ══")
        print("  1. Mark Attendance")
        print("  2. View Attendance Report")
        print("  3. Export Attendance to CSV")
        print("  0. Back")
        choice = input("Choice: ").strip()
        if choice == "1": mark_attendance()
        elif choice == "2": view_attendance_report()
        elif choice == "3": export_attendance_csv()
        elif choice == "0": break


def salary_menu():
    while True:
        print("\n══ Salary Management ══")
        print("  1. Set/Update Salary")
        print("  2. View Salary")
        print("  3. Export Salary Report")
        print("  0. Back")
        choice = input("Choice: ").strip()
        if choice == "1": set_salary()
        elif choice == "2": view_salary()
        elif choice == "3": export_salary_csv()
        elif choice == "0": break


def admin_menu():
    while True:
        print("\n══ Admin Panel ══")
        print("  1. Add System User")
        print("  2. View Access Logs")
        print("  0. Back")
        choice = input("Choice: ").strip()
        if choice == "1": add_user()
        elif choice == "2": view_access_logs()
        elif choice == "0": break


def main_menu():
    while True:
        print(f"\n╔══════════════════════════════════════╗")
        print(f"║   Employee Management System          ║")
        print(f"║   Logged in: {session.username:<10} Role: {session.role:<8}║")
        print(f"╚══════════════════════════════════════╝")
        print("  1. Employee Management")
        print("  2. Attendance Management")
        print("  3. Salary Management")
        if session.role == "admin":
            print("  4. Admin Panel")
        print("  0. Logout")
        choice = input("\nChoice: ").strip()
        if choice == "1": employee_menu()
        elif choice == "2": attendance_menu()
        elif choice == "3": salary_menu()
        elif choice == "4" and session.role == "admin": admin_menu()
        elif choice == "0":
            session.logout()
            print("[✓] Logged out.")
            break


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print("╔══════════════════════════════════════════╗")
    print("║  Employee Management Application v1.0    ║")
    print("╚══════════════════════════════════════════╝")

    # First-time setup
    initialize_database()
    seed_demo_data()

    # Login loop
    while True:
        print("\n─── Login ───")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        if session.login(username, password):
            print(f"\n[✓] Welcome, {session.username}! (Role: {session.role})")
            main_menu()
            break
        else:
            print("[✗] Invalid credentials. Try again.")
            retry = input("Retry? (yes/no): ").strip().lower()
            if retry != "yes":
                print("Goodbye.")
                break


if __name__ == "__main__":
    main()
