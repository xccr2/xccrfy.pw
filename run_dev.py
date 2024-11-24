from app import create_app, db
from app.models.user import User
from app.models.password import Password

app = create_app('development')

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Password': Password
    }

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
        
        # Create a default admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com'
            )
            admin.set_password('admin123')  # Set a default password
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user (username: admin, password: admin123)")
    
    # Run the application
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )
