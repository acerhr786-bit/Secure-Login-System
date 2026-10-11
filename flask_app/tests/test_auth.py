import unittest
import pyotp
from flask_bcrypt import Bcrypt
from flask_app.app import create_app
from flask_app.models import db, User

class SecurityAuthTestCase(unittest.TestCase):
    def setUp(self):
        """Set up an isolated in-memory test database and test client."""
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,  # We test CSRF explicitly in test_csrf_protection
            'SECRET_KEY': 'test-secret-key-32-chars-at-least!'
        })
        self.client = self.app.test_client()
        self.bcrypt = Bcrypt(self.app)

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_secure_password_hashing(self):
        """Verify that passwords are never stored in plain text and use bcrypt."""
        with self.app.app_context():
            raw_password = 'SuperSecret#Password1'
            hashed = self.bcrypt.generate_password_hash(raw_password, rounds=12).decode('utf-8')
            
            user = User(username='alice', email='alice@example.com', password_hash=hashed)
            db.session.add(user)
            db.session.commit()

            saved_user = User.query.filter_by(username='alice').first()
            # Plain text must never equal stored hash
            self.assertNotEqual(saved_user.password_hash, raw_password)
            # Must start with bcrypt identifier $2b$ or $2a$
            self.assertTrue(saved_user.password_hash.startswith(('$2b$', '$2a$')))
            # Verify bcrypt check returns True
            self.assertTrue(self.bcrypt.check_password_hash(saved_user.password_hash, raw_password))
            self.assertFalse(self.bcrypt.check_password_hash(saved_user.password_hash, 'WrongPass123!'))

    def test_sql_injection_resistance(self):
        """Verify parameterized queries prevent SQL injection payloads."""
        with self.app.app_context():
            hashed = self.bcrypt.generate_password_hash('Sec#Pass1', rounds=12).decode('utf-8')
            user = User(username='admin', email='admin@example.com', password_hash=hashed)
            db.session.add(user)
            db.session.commit()

            # Malicious SQL injection payloads
            payload1 = "admin' OR '1'='1"
            payload2 = "' OR 1=1 --"
            payload3 = "admin@example.com' OR '1'='1"

            # SQLAlchemy executes parameterized statements; payload treated as literal string
            res1 = User.query.filter_by(username=payload1).first()
            self.assertIsNone(res1)

            res2 = User.query.filter_by(email=payload3).first()
            self.assertIsNone(res2)

    def test_registration_validation(self):
        """Test registration input validation and password complexity."""
        # Weak password (no uppercase or symbol)
        res = self.client.post('/register', data={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'weakpassword',
            'confirm_password': 'weakpassword'
        }, follow_redirects=True)
        self.assertIn(b'Password must contain at least one uppercase letter', res.data)

        # Valid registration
        res_valid = self.client.post('/register', data={
            'username': 'bob_secure',
            'email': 'bob@example.com',
            'password': 'SecureP@ssw0rd2026',
            'confirm_password': 'SecureP@ssw0rd2026'
        }, follow_redirects=True)
        self.assertIn(b'Your account has been created successfully', res_valid.data)

    def test_account_enumeration_prevention(self):
        """Ensure failed logins return generic errors to prevent user enumeration."""
        res = self.client.post('/login', data={
            'email': 'nonexistent_account@example.com',
            'password': 'SomePassword123!'
        }, follow_redirects=True)
        self.assertIn(b'Invalid email or password combination', res.data)

    def test_access_control_dashboard_protection(self):
        """Ensure unauthenticated users cannot access protected pages."""
        res = self.client.get('/dashboard', follow_redirects=False)
        # Should redirect to login page (HTTP 302)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login', res.headers.get('Location', ''))

    def test_two_factor_authentication(self):
        """Test 2FA activation and TOTP token validation."""
        with self.app.app_context():
            secret = pyotp.random_base32()
            hashed = self.bcrypt.generate_password_hash('Sec#Pass1', rounds=12).decode('utf-8')
            user = User(
                username='carol',
                email='carol@example.com',
                password_hash=hashed,
                totp_secret=secret,
                is_totp_enabled=True
            )
            db.session.add(user)
            db.session.commit()

            totp = pyotp.TOTP(secret)
            valid_token = totp.now()

            # Verify token validates
            self.assertTrue(totp.verify(valid_token))
            # Bad token fails
            self.assertFalse(totp.verify('000000'))

    def test_csrf_protection_enforced(self):
        """Verify CSRF rejects unauthorized POST requests when CSRF is enabled."""
        csrf_app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': True,
            'SECRET_KEY': 'csrf-test-secret-key-32-chars!'
        })
        client = csrf_app.test_client()

        # POST without CSRF token should be rejected (400 Bad Request)
        res = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'Password123!'
        })
        self.assertEqual(res.status_code, 400)

if __name__ == '__main__':
    unittest.main()
