import re
from typing import Tuple

def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password complexity requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character (@$!%*?&)"
    
    # Check for common patterns
    common_patterns = [
        r'12345',
        r'qwerty',
        r'password',
        r'admin',
        r'letmein',
        r'welcome'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            return False, "Password contains common patterns that are easily guessable"
    
    return True, ""

def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format.
    Returns (is_valid, error_message).
    """
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 64:
        return False, "Username must be less than 64 characters"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    return True, ""

def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email format.
    Returns (is_valid, error_message).
    """
    if len(email) > 120:
        return False, "Email must be less than 120 characters"
    
    # RFC 5322 compliant email regex
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format"
    
    # Check for common disposable email domains
    disposable_domains = [
        'tempmail.com',
        'throwawaymail.com',
        'mailinator.com',
        'guerrillamail.com',
        'sharklasers.com'
    ]
    
    domain = email.split('@')[1].lower()
    if domain in disposable_domains:
        return False, "Disposable email addresses are not allowed"
    
    return True, ""
