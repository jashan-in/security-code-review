import os
import pymysql
from urllib.request import urlopen
import pymysql
from pymysql.cursors import DictCursor

db_config = {
    'host': 'mydatabase.com',
    'user': 'admin',
    'password': 'secret123'
    # Vulnerability: Hardcoded credentials (OWASP A02:2021 – Cryptographic Failures)
    # Fix: Store credentials securely using environment variables or a secrets manager.
} 

def get_user_input():
    user_input = input('Enter your name: ')
    return user_input
    # Vulnerability: Improper Input Validation (OWASP A04:2021 – Insecure Design)
    # Fix: Validate and sanitize user input before using or storing it.

def send_email(to, subject, body):
    os.system(f'echo {body} | mail -s "{subject}" {to}')
    # Vulnerability: Command Injection (OWASP A03:2021 – Injection)
    # Attackers could inject malicious shell commands via 'body' or 'subject'.
    # Fix: Use Python's 'subprocess' module with argument lists or a secure email library.

def get_data():
    url = 'http://insecure-api.com/get-data'
    data = urlopen(url).read().decode()
    return data
    # Vulnerability: Insecure Data Transport (OWASP A02:2021 – Cryptographic Failures)
    # The HTTP connection is unencrypted; data can be intercepted.
    # Fix: Always use HTTPS.

def save_to_db(data):
    """
    Mitigation: Use parameterized queries to prevent SQL Injection (OWASP A03:2021 – Injection)
    """
    connection = pymysql.connect(
        host=os.environ.get("DB_HOST"),               # moved from hardcoded config
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME", "appdb"),
        cursorclass=DictCursor,
        ssl={"ssl": {}} if os.environ.get("DB_SSL", "true") == "true" else None
    )
    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"
            cursor.execute(sql, (data, "Another Value"))
        connection.commit()
    finally:
        connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)

# Overall: No authentication or access control is implemented (OWASP A01:2021 – Broken Access Control)