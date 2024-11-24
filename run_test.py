from app import create_app, db
from app.models.user import User
from app.models.password import Password

app = create_app('testing')

@app.cli.command('test')
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create test database tables
    app.run(debug=True, ssl_context='adhoc')
