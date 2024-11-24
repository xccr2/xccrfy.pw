# xccrfy.pw - Secure Password Manager

A modern, secure web-based password manager with strong security features including AES encryption, MFA support, and protection against common web vulnerabilities. Features a sleek dark theme UI with dynamic 3D effects.

## Features

- Secure credential storage using AES-256 encryption
- Two-factor authentication (2FA) support
- Protection against SQL injection and XSS attacks
- CSRF protection
- Secure session management
- Modern, responsive UI with dark/light theme
- Dynamic 3D card effects and animations
- Secure password generation
- Copy-to-clipboard functionality
- Password strength indicators

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- virtualenv or venv

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/xccrfy.pw.git
cd xccrfy.pw
```

2. Create and activate a virtual environment:
```bash
# On Linux/Mac
python3 -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a .env file in the root directory:
```env
SECRET_KEY=your-secure-secret-key-here
DATABASE_URL=sqlite:///passwords.db
FLASK_ENV=development
FLASK_APP=run_dev.py
```

5. Initialize the database:
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

6. Run the development server:
```bash
python run_dev.py
# or
flask run
```

7. Access the application at `http://127.0.0.1:5000`

## Development Setup

### Dependencies

Key dependencies include:
- Flask 2.0.1
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- cryptography
- python-dotenv
- Flask-Migrate

For a complete list, see `requirements.txt`.

### Project Structure

```
secure_password_manager/
├── app/
│   ├── __init__.py          # App initialization and configuration
│   ├── auth/                # Authentication routes and forms
│   ├── main/                # Main application routes
│   ├── models/              # Database models
│   ├── static/              # Static files (CSS, JS)
│   └── templates/           # HTML templates
├── migrations/              # Database migrations
├── tests/                   # Test suite
├── .env                     # Environment variables
├── requirements.txt         # Project dependencies
└── run_dev.py              # Development server script
```

## Security Features

### Encryption
- AES-256 encryption for stored credentials
- Server-side encryption with secure key derivation (PBKDF2)
- Encrypted fields: passwords, security questions, notes

### Authentication
- Secure password hashing using bcrypt
- Optional 2FA using TOTP
- Session management with secure cookies
- CSRF token protection on all forms

### Web Security
- Content Security Policy (CSP) headers
- XSS protection through input sanitization
- SQL injection prevention using SQLAlchemy ORM
- Secure headers configuration
- HTTPS enforcement in production

## Testing

Run the test suite:
```bash
# Run all tests
python -m pytest tests/

# Run with coverage report
python -m pytest --cov=app tests/
```

## Production Deployment

Additional steps for production deployment:

1. Update .env file:
```env
FLASK_ENV=production
SECRET_KEY=<strong-random-key>
DATABASE_URL=<your-production-db-url>
```

2. Configure your web server (e.g., Nginx) with SSL/TLS

3. Set up proper logging and monitoring

4. Enable production security features:
```python
# In app/__init__.py
app.config['SECURE_SSL_REDIRECT'] = True
app.config['SESSION_COOKIE_SECURE'] = True
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask and its extensions maintainers
- The Python cryptography team
- Font Awesome for icons
