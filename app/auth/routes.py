from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.auth import auth
from app.models.user import User
from app.utils.crypto import SecureHash
from datetime import datetime
import pyotp

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('auth.register'))
            
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                return redirect(url_for('auth.mfa_verify'))
            
            login_user(user, remember=remember)
            user.update_last_login()
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
            
        flash('Invalid username or password')
    return render_template('auth/login.html')

@auth.route('/mfa/verify', methods=['GET', 'POST'])
@login_required
def mfa_verify():
    if 'mfa_user_id' not in session:
        return redirect(url_for('auth.login'))
        
    user = User.query.get(session['mfa_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        if user.verify_mfa_code(code):
            login_user(user)
            session.pop('mfa_user_id')
            return redirect(url_for('main.index'))
        flash('Invalid MFA code')
        
    return render_template('auth/mfa_verify.html')

@auth.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if request.method == 'POST':
        code = request.form.get('code')
        if current_user.verify_mfa_code(code):
            current_user.enable_mfa()
            flash('MFA enabled successfully')
            return redirect(url_for('main.index'))
        flash('Invalid MFA code')
        
    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()
        
    qr_uri = current_user.get_mfa_uri()
    return render_template('auth/mfa_setup.html', qr_uri=qr_uri)

@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))