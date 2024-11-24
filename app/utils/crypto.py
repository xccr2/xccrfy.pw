from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

class PasswordEncryption:
    def __init__(self, master_key):
        """Initialize encryption with a master key."""
        if not master_key:
            raise ValueError("Master key cannot be None")
        
        self.backend = default_backend()
        # Use the master key directly as it's already a secure random key
        try:
            key = base64.urlsafe_b64encode(base64.b64decode(master_key.encode()))
            self.fernet = Fernet(key)
        except Exception as e:
            raise ValueError(f"Invalid master key format: {str(e)}")

    def encrypt_password(self, password):
        """Encrypt a password using Fernet (AES)."""
        if not password:
            raise ValueError("Password cannot be None")
        return self.fernet.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt a password using Fernet (AES)."""
        if not encrypted_password:
            raise ValueError("Encrypted password cannot be None")
        try:
            return self.fernet.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

class SecureHash:
    @staticmethod
    def hash_master_password(password):
        """Hash the master password using PBKDF2."""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        return f"{base64.b64encode(salt).decode()}:{key.decode()}"
    
    @staticmethod
    def verify_master_password(password, hash_str):
        """Verify a password against its hash."""
        try:
            salt_str, key_str = hash_str.split(':')
            salt = base64.b64decode(salt_str)
            stored_key = base64.b64decode(key_str)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key == stored_key
        except Exception:
            return False
