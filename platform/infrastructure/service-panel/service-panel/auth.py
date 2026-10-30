"""Temporary local mock login matching the supplied website demo account.

This is a UI gate, not production authentication or website single sign-on.
"""
from secrets import compare_digest

ADMIN_EMAIL = "admin@athenasec.com"
ADMIN_PASSWORD = "admin123"


def authenticate(email, password):
    """Normalize email only; passwords remain case- and whitespace-sensitive."""
    if not isinstance(email, str) or not isinstance(password, str):
        return False
    email_ok = compare_digest(email.strip().casefold().encode("utf-8"), ADMIN_EMAIL.encode("utf-8"))
    password_ok = compare_digest(password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8"))
    return email_ok and password_ok
