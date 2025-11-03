import os
import pymysql
from urllib.request import urlopen
import smtplib
from email.message import EmailMessage
import ssl
from urllib.request import urlopen, Request
from urllib.parse import urlparse
from pymysql.cursors import DictCursor

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
    """
    Mitigation: Use parameterized queries to prevent SQL Injection (OWASP A03:2021 – Injection).
    - Uses load_db_config() / env vars for credentials (no hardcoded secrets).
    - Uses parameter substitution instead of string formatting.
    - Basic validation: ensure 'data' is a reasonable string.
    """
    # Basic input sanity check (prevent absurdly large payloads)
    if not isinstance(data, str):
        raise TypeError("data must be a string")
    if len(data) > 10_000:  # tune limit for your app
        raise ValueError("data is too long")

    # Load DB config from environment (expects load_db_config() or similar)
    # If you used the earlier snippet: connection = pymysql.connect(**load_db_config())
    conn_kwargs = {
        "host": os.getenv("DB_HOST"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "database": os.getenv("DB_NAME", "appdb"),
        "cursorclass": DictCursor,
    }
    # Optional: add SSL if configured
    if os.getenv("DB_SSL", "true").lower() == "true":
        conn_kwargs["ssl"] = {"ssl": {}}

    # Fail fast if required env vars are missing
    missing = [k for k in ("host", "user", "password") if not conn_kwargs.get(k)]
    if missing:
        raise EnvironmentError("Missing DB credentials; set DB_HOST, DB_USER, DB_PASSWORD")

    connection = pymysql.connect(**conn_kwargs)
    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"
            # Parameterized execution prevents SQL injection
            cursor.execute(sql, (data, "Another Value"))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    

