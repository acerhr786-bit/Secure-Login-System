import os
import io
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, url_for, flash, redirect, request, session, abort
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode

from .models import db, User, SecurityLog
from .forms import (
    RegistrationForm,
    LoginForm,
    RequestResetForm,
    ResetPasswordForm,
    TwoFactorVerifyForm,
    ChangePasswordForm
)

def create_app(test_config=None):
    app = Flask(__name__)

    # Security configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secure-cybersec-lab-key-32-chars-min!')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///auth.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Cookie Security Settings
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

    if test_config:
        app.config.update(test_config)

    # Initialize extensions
    db.init_app(app)
    bcrypt = Bcrypt(app)
    csrf = CSRFProtect(app)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this secured page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def log_event(event_type, details, user_id=None):
        try:
            client_ip = request.remote_addr or '127.0.0.1'
            log = SecurityLog(
                user_id=user_id,
                event_type=event_type,
                ip_address=client_ip,
                details=details
            )
            db.session.add(log)
            db.session.commit()
        except Exception:
            db.session.rollback()

    @app.after_request
    def set_security_headers(response):
        """OWASP recommended security headers."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    # ----------------- ROUTES -----------------

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = RegistrationForm()
        if form.validate_on_submit():
            # Secure Bcrypt hashing with cost factor 12
            hashed_password = bcrypt.generate_password_hash(form.password.data, rounds=12).decode('utf-8')
            
            user = User(
                username=form.username.data.strip(),
                email=form.email.data.strip().lower(),
                password_hash=hashed_password
            )
            db.session.add(user)
            db.session.commit()

            log_event('USER_REGISTERED', f"New account registered: @{user.username}", user.id)
            flash('Your account has been created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', title='Register', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")  # Protect against brute-force attacks
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = LoginForm()
        if form.validate_on_submit():
            clean_email = form.email.data.strip().lower()
            user = User.query.filter_by(email=clean_email).first()

            # Constant-time comparison & generic error message (prevents account enumeration)
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Check if Two-Factor Authentication is enabled
                if user.is_totp_enabled:
                    session['pending_2fa_user_id'] = user.id
                    log_event('2FA_PROMPTED', f"2FA code requested for {clean_email}", user.id)
                    return redirect(url_for('two_factor_verify'))

                login_user(user, remember=form.remember.data)
                user.last_login_at = datetime.utcnow()
                db.session.commit()

                log_event('LOGIN_SUCCESS', f"User {user.username} logged in successfully", user.id)
                flash('Welcome back! You have securely authenticated.', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                log_event('LOGIN_FAILED', f"Failed login attempt for {clean_email}")
                flash('Invalid email or password combination. Please check your credentials.', 'danger')

        return render_template('login.html', title='Sign In', form=form)

    @app.route('/two-factor-verify', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def two_factor_verify():
        user_id = session.get('pending_2fa_user_id')
        if not user_id:
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user:
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('login'))

        form = TwoFactorVerifyForm()
        if form.validate_on_submit():
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(form.code.data.strip()):
                session.pop('pending_2fa_user_id', None)
                login_user(user)
                user.last_login_at = datetime.utcnow()
                db.session.commit()

                log_event('2FA_VERIFIED', f"2FA verified successfully for {user.username}", user.id)
                flash('Two-factor authentication verified successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                log_event('2FA_FAILED', f"Invalid 2FA code supplied for {user.username}", user.id)
                flash('Invalid 6-digit authentication code.', 'danger')

        return render_template('two_factor.html', title='Two-Factor Authentication', form=form, user=user)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        logs = SecurityLog.query.filter_by(user_id=current_user.id).order_by(SecurityLog.created_at.desc()).limit(10).all()
        return render_template('dashboard.html', title='Security Dashboard', user=current_user, logs=logs)

    @app.route('/two-factor-setup', methods=['GET', 'POST'])
    @login_required
    def two_factor_setup():
        form = TwoFactorVerifyForm()

        if request.method == 'GET':
            secret = pyotp.random_base32()
            session['temp_totp_secret'] = secret
            
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(current_user.email, issuer_name='SecureAuth')
            
            # Generate QR code as base64 string
            img = qrcode.make(provisioning_uri)
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            return render_template('two_factor_setup.html', title='Enable 2FA', form=form, secret=secret, qr_base64=qr_base64)

        if form.validate_on_submit():
            secret = session.get('temp_totp_secret')
            if not secret:
                flash('Session expired. Please restart 2FA setup.', 'danger')
                return redirect(url_for('two_factor_setup'))

            totp = pyotp.TOTP(secret)
            if totp.verify(form.code.data.strip()):
                current_user.totp_secret = secret
                current_user.is_totp_enabled = True
                db.session.commit()
                session.pop('temp_totp_secret', None)

                log_event('2FA_ENABLED', 'Two-Factor Authentication successfully activated', current_user.id)
                flash('Two-Factor Authentication has been successfully enabled!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid verification code. Please check your authenticator app and try again.', 'danger')

        return redirect(url_for('two_factor_setup'))

    @app.route('/two-factor-disable', methods=['POST'])
    @login_required
    def two_factor_disable():
        current_user.is_totp_enabled = False
        current_user.totp_secret = None
        db.session.commit()

        log_event('2FA_DISABLED', 'Two-Factor Authentication disabled', current_user.id)
        flash('Two-Factor Authentication has been disabled.', 'info')
        return redirect(url_for('dashboard'))

    @app.route('/reset-password', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def reset_request():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = RequestResetForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.strip().lower()).first()
            if user:
                token = user.get_reset_token()
                log_event('PASSWORD_RESET_REQUESTED', f"Password reset requested for {user.email}", user.id)
                # In production, send via email. For local lab, log and provide link
                reset_url = url_for('reset_token', token=token, _external=True)
                session['last_reset_url'] = reset_url

            # Generic notice prevents user enumeration
            flash('If an account with that email exists, password reset instructions have been dispatched.', 'info')
            return redirect(url_for('login'))

        return render_template('reset_request.html', title='Forgot Password', form=form)

    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_token(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        user = User.verify_reset_token(token)
        if not user:
            flash('The reset token is invalid or has expired. Please request a new one.', 'warning')
            return redirect(url_for('reset_request'))

        form = ResetPasswordForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data, rounds=12).decode('utf-8')
            user.password_hash = hashed_password
            db.session.commit()

            log_event('PASSWORD_RESET_COMPLETED', f"Password reset completed for {user.email}", user.id)
            flash('Your password has been successfully updated! You can now log in.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_token.html', title='Reset Password', form=form)

    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        form = ChangePasswordForm()
        if form.validate_on_submit():
            if bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
                new_hash = bcrypt.generate_password_hash(form.new_password.data, rounds=12).decode('utf-8')
                current_user.password_hash = new_hash
                db.session.commit()

                log_event('PASSWORD_CHANGED', 'User changed account password', current_user.id)
                flash('Your password has been updated successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Current password is incorrect.', 'danger')

        return render_template('change_password.html', title='Change Password', form=form)

    @app.route('/logout', methods=['POST'])
    @login_required
    def logout():
        uid = current_user.id
        logout_user()
        log_event('LOGOUT', 'User logged out and session terminated', uid)
        flash('You have been securely logged out.', 'info')
        return redirect(url_for('login'))

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
