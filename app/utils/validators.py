import re
import socket


def validate_email(email):
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def validate_password(password):
    """
    Validate password strength
    - At least 8 characters
    - Contains a mix of uppercase and lowercase letters
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False

    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    return has_lowercase and has_uppercase and has_digit and has_special


def validate_domain(domain):
    """Validate domain name"""
    try:
        # Try to resolve the domain
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False