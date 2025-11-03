import os
import pymysql
from urllib.request import urlopen
import smtplib
from email.message import EmailMessage
import ssl
from urllib.request import urlopen, Request
from urllib.parse import urlparse

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD')
}

if not all(db_config.values()):
    raise EnvironmentError(
        "Missing database credentials. Please set DB_HOST, DB_USER, "
        "and DB_PASSWORD as environment variables."
    )

def get_user_input():
    user_input = input('Enter your name: ')
    return user_input

def send_email(to: str, subject: str, body: str) -> None:
    """
    Mitigation: Eliminate shell calls; use Python's email + smtplib (OWASP A03:2021 – Injection).
    - No shell, no piping, no command strings.
    - Basic header sanitization to prevent newline/header injection.
    - SMTP settings pulled from environment variables (no hardcoding).
    """

    # Basic header safety: prevent newline/header injection
    for header_val in (to, subject):
        if "\r" in header_val or "\n" in header_val:
            raise ValueError("Invalid characters in email headers")

    smtp_host = os.getenv("SMTP_HOST", "smtp.example.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")         # optional if unauthenticated SMTP
    smtp_pass = os.getenv("SMTP_PASSWORD")     # optional
    use_starttls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    from_addr = os.getenv("SMTP_FROM", "no-reply@example.com")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    # Connect securely (STARTTLS on 587 by default)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        if use_starttls:
            smtp.starttls()
        if smtp_user and smtp_pass:
            smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)

# Allowlist to avoid accidental SSRF (bonus hardening)
ALLOWED_HOSTS = {"secure-api.com"}

def get_data():
    """
    Mitigation: Use HTTPS with certificate/hostname verification (OWASP A02:2021 – Cryptographic Failures)
    Bonus: Simple allowlist to reduce SSRF risk (OWASP A10:2021 – SSRF)
    """
    url = os.getenv("DATA_API_URL", "https://secure-api.com/get-data")

    # Block unapproved outbound destinations
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Blocked outbound request to unapproved host: {host}")

    # Enforce modern TLS
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # require TLS 1.2+

    req = Request(url, headers={"User-Agent": "security-review-assignment/1.0"})
    with urlopen(req, context=ctx, timeout=5) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Upstream returned HTTP {resp.status}")
        return resp.read().decode("utf-8")

def save_to_db(data):
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
