from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.main import main
from app.models.password import Password
from app.utils.crypto import PasswordEncryption
from datetime import datetime, timedelta

@main.route('/')
@main.route('/index')
@login_required
def index():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    return render_template('main/index.html', passwords=passwords)

@main.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        notes = request.form.get('notes')
        
        if not all([website, username, password]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('main.add_password'))
        
        # Encrypt the password using the user's master key
        encrypted_password = current_user.encrypt_password(password)
        
        # Calculate password strength
        password_strength = calculate_password_strength(password)
        
        password_entry = Password(
            user_id=current_user.id,
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            notes=notes,
            password_strength=password_strength,
            created_at=datetime.utcnow()
        )
        
        db.session.add(password_entry)
        db.session.commit()
        
        flash('Password added successfully', 'success')
        return redirect(url_for('main.index'))
        
    return render_template('main/add_password.html')

@main.route('/view_password/<int:id>', methods=['POST'])
@login_required
def view_password(id):
    password_entry = Password.query.get_or_404(id)
    
    if password_entry.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized access'}), 403
        
    try:
        decrypted_password = current_user.decrypt_password(password_entry.encrypted_password)
        return jsonify({
            'password': decrypted_password,
            'last_viewed': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/edit_password/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_password(id):
    password_entry = Password.query.get_or_404(id)
    
    if password_entry.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        notes = request.form.get('notes')
        
        if not all([website, username]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('main.edit_password', id=id))
        
        password_entry.website = website
        password_entry.username = username
        password_entry.notes = notes
        password_entry.last_modified = datetime.utcnow()
        
        if password:  # Only update password if a new one is provided
            password_entry.encrypted_password = current_user.encrypt_password(password)
            password_entry.password_strength = calculate_password_strength(password)
        
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('main.index'))
        
    return render_template('main/edit_password.html', password=password_entry)

@main.route('/delete_password/<int:id>', methods=['POST'])
@login_required
def delete_password(id):
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.index'))
    
    db.session.delete(password)
    db.session.commit()
    flash('Password deleted successfully', 'success')
    return redirect(url_for('main.index'))

def calculate_password_strength(password):
    """Calculate password strength score (0-100)."""
    score = 0
    
    # Length check (up to 40 points)
    length = len(password)
    score += min(length * 4, 40)
    
    # Character variety checks (up to 60 points)
    if any(c.islower() for c in password):
        score += 10
    if any(c.isupper() for c in password):
        score += 10
    if any(c.isdigit() for c in password):
        score += 20
    if any(not c.isalnum() for c in password):
        score += 20
        
    return min(score, 100)  # Cap at 100
