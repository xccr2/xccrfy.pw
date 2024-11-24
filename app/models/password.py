from app import db
from datetime import datetime

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(256), nullable=False)
    username = db.Column(db.String(256), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # Additional security metadata
    password_strength = db.Column(db.Integer)  # Score from 0-100
    requires_rotation = db.Column(db.Boolean, default=False)
    rotation_reminder_date = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Password {self.website}>'
    
    def update_last_accessed(self):
        """Update the last accessed timestamp."""
        self.last_accessed = datetime.utcnow()
        db.session.commit()
    
    def mark_for_rotation(self, reminder_days=90):
        """Mark password for rotation with a reminder date."""
        self.requires_rotation = True
        self.rotation_reminder_date = datetime.utcnow() + timedelta(days=reminder_days)
        db.session.commit()
