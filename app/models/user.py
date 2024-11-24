from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils.crypto import PasswordEncryption
import pyotp
from datetime import datetime
import base64
import os

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    master_key = db.Column(db.String(128))  # Encrypted master key
    master_key_salt = db.Column(db.String(64))  # Salt for master key derivation
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    passwords = db.relationship('Password', backref='owner', lazy='dynamic')
    
    def __init__(self, username, email):
        """Initialize a new user with a username and email."""
        super().__init__()
        self.username = username
        self.email = email
        self._generate_master_key()
    
    def _generate_master_key(self):
        """Generate a new master key and salt."""
        # Generate a random master key (32 bytes for AES-256)
        raw_key = os.urandom(32)
        self.master_key = base64.b64encode(raw_key).decode('utf-8')
        # Generate a random salt for future use
        self.master_key_salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    
    def set_password(self, password):
        """Set the user's password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)
    
    def encrypt_password(self, password):
        """Encrypt a password using the user's master key."""
        if not self.master_key:
            self._generate_master_key()
        encryptor = PasswordEncryption(self.master_key)
        return encryptor.encrypt_password(password)
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password using the user's master key."""
        if not self.master_key:
            raise ValueError("Master key not initialized")
        encryptor = PasswordEncryption(self.master_key)
        return encryptor.decrypt_password(encrypted_password)
    
    def enable_mfa(self):
        """Enable MFA for the user."""
        if not self.mfa_secret:
            self.mfa_secret = pyotp.random_base32()
        self.mfa_enabled = True
        db.session.commit()
    
    def disable_mfa(self):
        """Disable MFA for the user."""
        self.mfa_enabled = False
        db.session.commit()
    
    def verify_mfa_code(self, code):
        """Verify an MFA code."""
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(code)
    
    def get_mfa_uri(self):
        """Get the MFA provisioning URI."""
        if not self.mfa_secret:
            return None
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.provisioning_uri(self.email, issuer_name="Secure Password Manager")
    
    def update_last_login(self):
        """Update the user's last login timestamp."""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<User {self.username}>'
