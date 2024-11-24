import unittest
from app import create_app, db
from app.models.user import User
from app.models.password import Password
from app.utils.crypto import PasswordEncryption, SecureHash

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()
        
        # Create test user
        self.test_user = User(
            username='testuser',
            email='test@example.com'
        )
        self.test_user.set_password('TestPassword123!')
        db.session.add(self.test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_user_creation(self):
        """Test user creation and password hashing"""
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password('TestPassword123!'))
        self.assertFalse(user.check_password('WrongPassword'))

    def test_password_encryption(self):
        """Test password encryption and decryption"""
        master_key = "MasterPassword123!"
        crypto = PasswordEncryption(master_key)
        
        # Test encryption
        test_password = "MySecurePassword123!"
        encrypted = crypto.encrypt_password(test_password)
        self.assertNotEqual(encrypted, test_password)
        
        # Test decryption
        decrypted = crypto.decrypt_password(encrypted)
        self.assertEqual(decrypted, test_password)

    def test_password_storage(self):
        """Test password storage in database"""
        # Create a new password entry
        master_key = "MasterPassword123!"
        crypto = PasswordEncryption(master_key)
        
        password = Password(
            user_id=self.test_user.id,
            website='example.com',
            username='user@example.com',
            encrypted_password=crypto.encrypt_password('SecurePass123!')
        )
        
        db.session.add(password)
        db.session.commit()
        
        # Retrieve and verify
        stored_pass = Password.query.filter_by(website='example.com').first()
        self.assertIsNotNone(stored_pass)
        decrypted = crypto.decrypt_password(stored_pass.encrypted_password)
        self.assertEqual(decrypted, 'SecurePass123!')

    def test_password_rotation(self):
        """Test password rotation functionality"""
        password = Password(
            user_id=self.test_user.id,
            website='rotation-test.com',
            username='user@example.com',
            encrypted_password='encrypted_data'
        )
        
        db.session.add(password)
        db.session.commit()
        
        # Mark for rotation
        password.mark_for_rotation(reminder_days=90)
        self.assertTrue(password.requires_rotation)
        self.assertIsNotNone(password.rotation_reminder_date)

if __name__ == '__main__':
    unittest.main()
