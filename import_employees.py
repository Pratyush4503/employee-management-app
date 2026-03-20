"""
Import 1000 Employees from CSV into MySQL
==========================================
Run: python import_employees.py
"""

import mysql.connector
import csv
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "employee_mgmt"
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


def get_or_create_department(cursor, dept_name):
    """Get department ID or create it if it doesn't exist."""
    cursor.execute(
        "SELECT dept_id FROM departments WHERE dept_name=%s", (dept_name,)
    )
    result = cursor.fetchone()
    if result:
        return result[0]
    cursor.execute(
        "INSERT INTO departments (dept_name) VALUES (%s)", (dept_name,)
    )
    return cursor.lastrowid


def import_employees(csv_file="employees_1000.csv"):
    print(f"\n{'='*50}")
    print(f"  Importing employees from {csv_file}")
    print(f"{'='*50}")

    conn = get_connection()
    cursor = conn.cursor()

    success = 0
    skipped = 0
    errors  = 0

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)

        for row in reader:
            try:
                # Get or create department
                dept_id = get_or_create_department(cursor, row["department"])

                # Insert employee
                cursor.execute("""
                    INSERT IGNORE INTO employees
                    (first_name, last_name, email, phone, dept_id,
                     designation, date_of_joining, employment_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    row["first_name"],
                    row["last_name"],
                    row["email"],
                    row["phone"],
                    dept_id,
                    row["designation"],
                    row["date_of_joining"],
                    row["employment_type"]
                ))

                emp_id = cursor.lastrowid

                # Insert salary if employee was inserted
                if emp_id:
                    cursor.execute("""
                        INSERT INTO salary
                        (emp_id, basic_salary, hra, allowances,
                         deductions, effective_date)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        emp_id,
                        float(row["basic_salary"]),
                        float(row["hra"]),
                        float(row["allowances"]),
                        float(row["deductions"]),
                        row["date_of_joining"]
                    ))
                    success += 1
                else:
                    skipped += 1

            except Exception as e:
                errors += 1
                print(f"  [!] Error on row {row['emp_id']}: {e}")

        conn.commit()

    cursor.close()
    conn.close()

    print(f"\n  ✓ Successfully imported : {success}")
    print(f"  ⚠ Skipped (duplicates)  : {skipped}")
    print(f"  ✗ Errors                : {errors}")
    print(f"\n  Total processed: {success + skipped + errors}")
    print(f"\n[✓] Import complete! You can now access all employees")
    print(f"    through the Employee Management App.")
    print(f"{'='*50}\n")


def verify_import():
    """Show a quick summary after import."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM employees")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT d.dept_name, COUNT(e.emp_id) as count
        FROM employees e
        JOIN departments d ON e.dept_id = d.dept_id
        GROUP BY d.dept_name
        ORDER BY count DESC
    """)
    dept_counts = cursor.fetchall()

    cursor.execute("""
        SELECT AVG(basic_salary), MAX(basic_salary), MIN(basic_salary)
        FROM salary
    """)
    sal = cursor.fetchone()

    cursor.close()
    conn.close()

    print(f"\n{'='*50}")
    print(f"  DATABASE SUMMARY AFTER IMPORT")
    print(f"{'='*50}")
    print(f"  Total Employees : {total}")
    print(f"\n  Employees by Department:")
    for dept, count in dept_counts:
        bar = "█" * (count // 10)
        print(f"    {dept:<20} {count:>4}  {bar}")
    print(f"\n  Salary Summary:")
    print(f"    Average : ₹{sal[0]:>10,.0f}")
    print(f"    Highest : ₹{sal[1]:>10,.0f}")
    print(f"    Lowest  : ₹{sal[2]:>10,.0f}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    import_employees()
    verify_import()

