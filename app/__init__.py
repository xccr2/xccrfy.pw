from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
from config import config

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
talisman = Talisman()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))

def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load the configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)

    # Enable HTTPS-only cookies in production
    if not app.config['TESTING']:
        talisman.init_app(app,
                force_https=True,
                session_cookie_secure=True,
                frame_options='DENY',
                content_security_policy={
                    'default-src': "'self'",
                    'script-src': "'self' 'unsafe-inline'",
                    'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
                    'img-src': "'self' data:",
                    'font-src': "'self' https://cdnjs.cloudflare.com"
                })
    
    # Register blueprints
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    # Create database tables
    with app.app_context():
        db.create_all()

    return app

from app.models import user, password
