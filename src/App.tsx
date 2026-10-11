/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useId } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  Eye,
  EyeOff,
  User,
  Mail,
  QrCode,
  RefreshCw,
  LogOut,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  Check,
  Smartphone,
  Laptop,
  Code,
  FileText,
  Clock,
  ArrowRight,
} from 'lucide-react';

interface AuthUserData {
  id: number;
  username: string;
  email: string;
  is_totp_enabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

interface SessionItem {
  id: number;
  ip_address: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  is_current: boolean;
}

interface SecurityLogItem {
  id: number;
  event_type: string;
  details: string;
  ip_address: string;
  created_at: string;
  username?: string;
}

interface ResetInboxItem {
  email: string;
  token: string;
  expiresAt: string;
  sentAt: string;
}

export default function App() {
  // Navigation & View state
  const [activeTab, setActiveTab] = useState<'auth' | 'dashboard' | 'lab' | 'flask_code'>('auth');
  const [authMode, setAuthMode] = useState<'login' | 'register' | 'forgot' | 'reset'>('login');

  // Authenticated state
  const [user, setUser] = useState<AuthUserData | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);

  // CSRF Token
  const [csrfToken, setCsrfToken] = useState<string>('');

  // Form states
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  // 2FA Challenge during login
  const [tempToken2FA, setTempToken2FA] = useState<string | null>(null);
  const [totpInputCode, setTotpInputCode] = useState('');
  const [totp2FALoading, setTotp2FALoading] = useState(false);
  const [totp2FAError, setTotp2FAError] = useState<string | null>(null);

  // Register Form states
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');
  const [showRegPassword, setShowRegPassword] = useState(false);
  const [regLoading, setRegLoading] = useState(false);
  const [regError, setRegError] = useState<string | null>(null);

  // Password Reset states
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotLoading, setForgotLoading] = useState(false);
  const [forgotSuccess, setForgotSuccess] = useState<string | null>(null);
  const [forgotError, setForgotError] = useState<string | null>(null);

  const [resetTokenParam, setResetTokenParam] = useState('');
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [resetConfirmPassword, setResetConfirmPassword] = useState('');
  const [showResetPassword, setShowResetPassword] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);
  const [resetSuccess, setResetSuccess] = useState<string | null>(null);
  const [resetError, setResetError] = useState<string | null>(null);

  // Dashboard states
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);

  // 2FA Setup in Dashboard
  const [setup2FAOpen, setSetup2FAOpen] = useState(false);
  const [setup2FASecret, setSetup2FASecret] = useState('');
  const [setup2FAQrUrl, setSetup2FAQrUrl] = useState('');
  const [setup2FACode, setSetup2FACode] = useState('');
  const [setup2FALoading, setSetup2FALoading] = useState(false);
  const [setup2FAError, setSetup2FAError] = useState<string | null>(null);
  const [setup2FASuccess, setSetup2FASuccess] = useState(false);

  // Change Password in Dashboard
  const [currentPass, setCurrentPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmNewPass, setConfirmNewPass] = useState('');
  const [changePassLoading, setChangePassLoading] = useState(false);
  const [changePassError, setChangePassError] = useState<string | null>(null);
  const [changePassSuccess, setChangePassSuccess] = useState<string | null>(null);

  // Security Lab states
  const [securityLogs, setSecurityLogs] = useState<SecurityLogItem[]>([]);
  const [resetInbox, setResetInbox] = useState<ResetInboxItem[]>([]);
  const [labSection, setLabSection] = useState<'sqli' | 'bcrypt' | 'csrf' | 'audit'>('sqli');

  // SQLi Probe states
  const [sqliInput, setSqliInput] = useState("admin@example.com' OR '1'='1");
  const [sqliResponse, setSqliResponse] = useState<any>(null);
  const [sqliLoading, setSqliLoading] = useState(false);

  // Bcrypt Analyzer states
  const [bcryptPassInput, setBcryptPassInput] = useState('CyberSec#2026!');
  const [bcryptRounds, setBcryptRounds] = useState(12);
  const [bcryptResponse, setBcryptResponse] = useState<any>(null);
  const [bcryptLoading, setBcryptLoading] = useState(false);

  // CSRF Test states
  const [csrfTestResult, setCsrfTestResult] = useState<any>(null);
  const [csrfTesting, setCsrfTesting] = useState(false);

  // Python Code Viewer file selector
  const [selectedFlaskFile, setSelectedFlaskFile] = useState<string>('app.py');
  const [copiedCode, setCopiedCode] = useState(false);

  // Fetch initial CSRF token and check session
  useEffect(() => {
    fetchCsrfToken();
    checkCurrentUser();
  }, []);

  // Sync tab with auth status
  useEffect(() => {
    if (user && activeTab === 'auth') {
      setActiveTab('dashboard');
    }
  }, [user]);

  // Load dashboard or lab data when switching
  useEffect(() => {
    if (activeTab === 'dashboard' && user) {
      loadSessions();
    }
    if (activeTab === 'lab') {
      loadSecurityLogs();
      loadResetInbox();
    }
  }, [activeTab, user]);

  const fetchCsrfToken = async () => {
    try {
      const res = await fetch('/api/csrf-token');
      const data = await res.json();
      if (data.csrfToken) {
        setCsrfToken(data.csrfToken);
      }
    } catch (err) {
      console.error('Failed to get CSRF token', err);
    }
  };

  const checkCurrentUser = async () => {
    try {
      setIsInitializing(true);
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      if (data.authenticated && data.user) {
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setIsInitializing(false);
    }
  };

  const loadSessions = async () => {
    try {
      setSessionsLoading(true);
      const res = await fetch('/api/auth/sessions');
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions || []);
      }
    } finally {
      setSessionsLoading(false);
    }
  };

  const loadSecurityLogs = async () => {
    try {
      const res = await fetch('/api/security-lab/logs');
      if (res.ok) {
        const data = await res.json();
        setSecurityLogs(data.logs || []);
      }
    } catch (err) {
      console.error('Failed to load security logs', err);
    }
  };

  const loadResetInbox = async () => {
    try {
      const res = await fetch('/api/security-lab/reset-inbox');
      if (res.ok) {
        const data = await res.json();
        setResetInbox(data.inbox || []);
      }
    } catch (err) {
      console.error('Failed to load reset inbox', err);
    }
  };

  // ----------------- AUTH ACTIONS -----------------

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setRemainingAttempts(null);
    setLoginLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          email: loginEmail,
          password: loginPassword,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setLoginError(data.error || 'Authentication failed.');
        if (data.remainingAttempts !== undefined) {
          setRemainingAttempts(data.remainingAttempts);
        }
        return;
      }

      // Check if 2FA is required
      if (data.require2FA) {
        setTempToken2FA(data.tempToken);
        setTotpInputCode('');
        return;
      }

      // Login success
      setUser(data.user);
      setLoginPassword('');
      setActiveTab('dashboard');
    } catch {
      setLoginError('Unable to connect to authentication server.');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleVerify2FALogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tempToken2FA) return;
    setTotp2FAError(null);
    setTotp2FALoading(true);

    try {
      const res = await fetch('/api/auth/verify-2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          tempToken: tempToken2FA,
          code: totpInputCode,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setTotp2FAError(data.error || 'Invalid 2FA code.');
        return;
      }

      setUser(data.user);
      setTempToken2FA(null);
      setTotpInputCode('');
      setActiveTab('dashboard');
    } catch {
      setTotp2FAError('Connection error during 2FA verification.');
    } finally {
      setTotp2FALoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError(null);

    if (regPassword !== regConfirmPassword) {
      setRegError('Passwords do not match.');
      return;
    }

    setRegLoading(true);

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          username: regUsername,
          email: regEmail,
          password: regPassword,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setRegError(data.error || 'Registration failed.');
        return;
      }

      setUser(data.user);
      setRegPassword('');
      setRegConfirmPassword('');
      setActiveTab('dashboard');
    } catch {
      setRegError('Connection error during registration.');
    } finally {
      setRegLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'x-csrf-token': csrfToken,
        },
      });
      setUser(null);
      setLoginEmail('');
      setLoginPassword('');
      setActiveTab('auth');
      setAuthMode('login');
      // Refresh CSRF token
      fetchCsrfToken();
    } catch (err) {
      console.error('Logout error', err);
    }
  };

  const handleRevokeSession = async (sessionId?: number, revokeOthers?: boolean) => {
    try {
      const res = await fetch('/api/auth/sessions/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          sessionId,
          revokeOthers,
        }),
      });

      if (res.ok) {
        loadSessions();
      }
    } catch (err) {
      console.error('Failed to revoke session', err);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError(null);
    setForgotSuccess(null);
    setForgotLoading(true);

    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({ email: forgotEmail }),
      });

      const data = await res.json();
      setForgotSuccess(data.message);
      loadResetInbox();
    } catch {
      setForgotError('Failed to dispatch password reset request.');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetError(null);
    setResetSuccess(null);

    if (resetNewPassword !== resetConfirmPassword) {
      setResetError('New passwords do not match.');
      return;
    }

    setResetLoading(true);

    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          token: resetTokenParam,
          newPassword: resetNewPassword,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setResetError(data.error || 'Failed to reset password.');
        return;
      }

      setResetSuccess(data.message);
      setResetNewPassword('');
      setResetConfirmPassword('');
      loadResetInbox();
    } catch {
      setResetError('Error connecting to password reset service.');
    } finally {
      setResetLoading(false);
    }
  };

  // 2FA Setup
  const handleStart2FASetup = async () => {
    setSetup2FAError(null);
    setSetup2FASuccess(false);
    setSetup2FACode('');
    try {
      const res = await fetch('/api/auth/2fa/setup', {
        method: 'POST',
        headers: { 'x-csrf-token': csrfToken },
      });
      const data = await res.json();
      if (res.ok) {
        setSetup2FASecret(data.secret);
        setSetup2FAQrUrl(data.qrCodeUrl);
        setSetup2FAOpen(true);
      }
    } catch (err) {
      console.error('Failed to start 2FA setup', err);
    }
  };

  const handleConfirm2FASetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setSetup2FAError(null);
    setSetup2FALoading(true);

    try {
      const res = await fetch('/api/auth/2fa/confirm', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({ code: setup2FACode }),
      });

      const data = await res.json();
      if (!res.ok) {
        setSetup2FAError(data.error || 'Failed to verify code.');
        return;
      }

      setSetup2FASuccess(true);
      if (user) {
        setUser({ ...user, is_totp_enabled: true });
      }
      setTimeout(() => {
        setSetup2FAOpen(false);
      }, 1500);
    } catch {
      setSetup2FAError('Connection error confirming 2FA.');
    } finally {
      setSetup2FALoading(false);
    }
  };

  const handleDisable2FA = async () => {
    const password = prompt('Enter your account password to disable Two-Factor Authentication:');
    if (!password) return;

    try {
      const res = await fetch('/api/auth/2fa/disable', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({ currentPassword: password }),
      });

      const data = await res.json();
      if (!res.ok) {
        alert(data.error || 'Failed to disable 2FA');
        return;
      }

      if (user) {
        setUser({ ...user, is_totp_enabled: false });
      }
      alert('Two-factor authentication disabled.');
    } catch (err) {
      console.error(err);
    }
  };

  // Change Password
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangePassError(null);
    setChangePassSuccess(null);

    if (newPass !== confirmNewPass) {
      setChangePassError('New passwords do not match.');
      return;
    }

    setChangePassLoading(true);

    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken,
        },
        body: JSON.stringify({
          currentPassword: currentPass,
          newPassword: newPass,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setChangePassError(data.error || 'Failed to change password.');
        return;
      }

      setChangePassSuccess('Password successfully updated.');
      setCurrentPass('');
      setNewPass('');
      setConfirmNewPass('');
    } catch {
      setChangePassError('Connection error updating password.');
    } finally {
      setChangePassLoading(false);
    }
  };

  // ----------------- SECURITY LAB PROBES -----------------

  const runSqliProbe = async () => {
    setSqliLoading(true);
    try {
      const res = await fetch('/api/security-lab/test-sqli', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inputEmail: sqliInput }),
      });
      const data = await res.json();
      setSqliResponse(data);
    } catch (err) {
      console.error(err);
    } finally {
      setSqliLoading(false);
    }
  };

  const runBcryptProbe = async () => {
    setBcryptLoading(true);
    try {
      const res = await fetch('/api/security-lab/test-bcrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: bcryptPassInput, rounds: bcryptRounds }),
      });
      const data = await res.json();
      setBcryptResponse(data);
    } catch (err) {
      console.error(err);
    } finally {
      setBcryptLoading(false);
    }
  };

  const runCsrfTest = async (sendWithValidToken: boolean) => {
    setCsrfTesting(true);
    setCsrfTestResult(null);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (sendWithValidToken) {
        headers['x-csrf-token'] = csrfToken;
      } else {
        headers['x-csrf-token'] = 'malicious-forged-token-or-empty';
      }

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'TestPassword123!',
        }),
      });

      const data = await res.json();
      setCsrfTestResult({
        sentWithValidToken: sendWithValidToken,
        statusCode: res.status,
        statusText: res.statusText,
        response: data,
        blocked: res.status === 403,
      });
    } catch (err) {
      console.error(err);
    } finally {
      setCsrfTesting(false);
    }
  };

  // Password Strength Calculator
  const getPasswordStrength = (pass: string) => {
    let score = 0;
    if (pass.length >= 8) score++;
    if (/[a-z]/.test(pass)) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^a-zA-Z0-9]/.test(pass)) score++;
    return score; // 0 to 5
  };

  const regStrength = getPasswordStrength(regPassword);

  // Flask Code Files Dictionary for Explorer
  const flaskFiles: Record<string, string> = {
    'app.py': `# flask_app/app.py
import os, io, base64
from datetime import datetime, timedelta
from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp, qrcode
from .models import db, User, SecurityLog
from .forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, TwoFactorVerifyForm

def create_app(test_config=None):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secure-key-32-chars-min!')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    db.init_app(app)
    bcrypt = Bcrypt(app)
    csrf = CSRFProtect(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])
    login_manager = LoginManager(app)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                if user.is_totp_enabled:
                    session['pending_2fa_user_id'] = user.id
                    return redirect(url_for('two_factor_verify'))
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
            flash('Invalid email or password combination.', 'danger')
        return render_template('login.html', form=form)

    return app`,
    'models.py': `# flask_app/models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def get_reset_token(self, expires_sec=900):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age_sec=900):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=max_age_sec)
        except Exception:
            return None
        return User.query.get(data.get('user_id'))`,
    'forms.py': `# flask_app/forms.py
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

def validate_password_complexity(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Must contain an uppercase letter (A-Z).')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Must contain a number (0-9).')
    if not re.search(r'[^a-zA-Z0-9]', password):
        raise ValidationError('Must contain a special symbol (!@#$...).')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_complexity])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')`,
    'test_auth.py': `# flask_app/tests/test_auth.py
import unittest
from flask_bcrypt import Bcrypt
from flask_app.app import create_app
from flask_app.models import db, User

class SecurityAuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,
            'SECRET_KEY': 'test-secret-key-32-chars!'
        })
        self.client = self.app.test_client()
        self.bcrypt = Bcrypt(self.app)
        with self.app.app_context():
            db.create_all()

    def test_sql_injection_resistance(self):
        """Verify parameterized queries block injection payloads."""
        payload = "admin' OR '1'='1"
        with self.app.app_context():
            # SQLAlchemy parameterized lookup treats payload as pure string
            user = User.query.filter_by(username=payload).first()
            self.assertIsNone(user)

    def test_password_hashing(self):
        raw = "Secret#Pass1"
        hashed = self.bcrypt.generate_password_hash(raw, rounds=12).decode('utf-8')
        self.assertTrue(hashed.startswith(('$2b$', '$2a$')))
        self.assertTrue(self.bcrypt.check_password_hash(hashed, raw))`,
    'requirements.txt': `Flask==3.0.3
Flask-SQLAlchemy==3.1.1
Flask-Bcrypt==1.0.1
Flask-WTF==1.2.1
Flask-Login==0.6.3
Flask-Limiter==3.8.0
email-validator==2.2.0
pyotp==2.9.0
qrcode==8.0
pytest==8.3.3
python-dotenv==1.0.1`,
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* ================= TOP BAR CONTRACT (Zone 1: Wordmark | Zone 2: Nav Links | Zone 3: CTA) ================= */}
      <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-8">
          {/* Zone 1: Brand Wordmark */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="text-lg font-bold tracking-tight text-white whitespace-nowrap">
              SecureAuth
            </span>
          </div>

          {/* Zone 2: Navigation Links (Clean unboxed text links) */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
            <button
              onClick={() => setActiveTab('auth')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 text-left cursor-pointer ${
                activeTab === 'auth' ? 'text-blue-400 font-semibold' : ''
              }`}
            >
              Auth Portal
            </button>
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 text-left cursor-pointer ${
                activeTab === 'dashboard' ? 'text-blue-400 font-semibold' : ''
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('lab')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 text-left cursor-pointer ${
                activeTab === 'lab' ? 'text-blue-400 font-semibold' : ''
              }`}
            >
              Security Lab
            </button>
            <button
              onClick={() => setActiveTab('flask_code')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 text-left cursor-pointer ${
                activeTab === 'flask_code' ? 'text-blue-400 font-semibold' : ''
              }`}
            >
              Flask Architecture
            </button>
          </nav>

          {/* Zone 3: Single Primary Action */}
          <div className="flex items-center gap-3 shrink-0">
            {user ? (
              <button
                onClick={handleLogout}
                className="px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out ({user.username})
              </button>
            ) : (
              <button
                onClick={() => {
                  setActiveTab('auth');
                  setAuthMode('register');
                }}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-sm"
              >
                Create Account
              </button>
            )}
          </div>
        </div>
      </header>

      {/* ================= MAIN CONTENT VIEWPORT ================= */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-8">
        {/* TAB 1: AUTHENTICATION PORTAL (Login, Register, Forgot Password, Reset Password) */}
        {activeTab === 'auth' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Left Column: Visual Security Banner & Core Defenses */}
            <div className="lg:col-span-5 flex flex-col gap-6">
              <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-900 shadow-sm aspect-video">
                <img
                  src="/src/assets/images/security_vault_banner_1791701264588.jpg"
                  alt="High tech security vault representing multi-layer defensive authentication"
                  referrerPolicy="no-referrer"
                  className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-950/50 to-transparent flex flex-col justify-end p-6">
                  <h2 className="text-xl font-bold text-white tracking-tight">
                    Defense-in-Depth Authentication
                  </h2>
                  <p className="text-xs text-slate-300 mt-1">
                    Bcrypt (cost 12), parameterized SQLite queries, CSRF Double-Submit tokens, and RFC 6238 TOTP.
                  </p>
                </div>
              </div>

              {/* Defense Overview Cards */}
              <div className="border border-slate-800 rounded-xl p-5 bg-slate-900/60">
                <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Active Security Policies
                </h3>
                <div className="space-y-2.5 text-xs text-slate-400">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <span>Password Hash Algorithm</span>
                    <span className="font-mono text-emerald-400 font-medium">Bcrypt ($2a$12)</span>
                  </div>
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <span>Database Protection</span>
                    <span className="font-mono text-emerald-400 font-medium">100% Prepared Statements</span>
                  </div>
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <span>Brute Force Mitigation</span>
                    <span className="font-mono text-amber-400 font-medium">5 Attempts / 15m Window</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Cookie Security</span>
                    <span className="font-mono text-emerald-400 font-medium">HttpOnly, SameSite=Strict</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: Interactive Auth Form */}
            <div className="lg:col-span-7">
              <div className="border border-slate-800 bg-slate-900/90 rounded-xl p-6 md:p-8 shadow-sm">
                {/* Mode Selector Tabs */}
                {!tempToken2FA && (
                  <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg mb-6 max-w-sm">
                    <button
                      onClick={() => {
                        setAuthMode('login');
                        setLoginError(null);
                      }}
                      className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                        authMode === 'login' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Sign In
                    </button>
                    <button
                      onClick={() => {
                        setAuthMode('register');
                        setRegError(null);
                      }}
                      className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                        authMode === 'register' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Register
                    </button>
                    <button
                      onClick={() => {
                        setAuthMode('forgot');
                        setForgotError(null);
                      }}
                      className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                        authMode === 'forgot' || authMode === 'reset' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Reset Password
                    </button>
                  </div>
                )}

                {/* 2FA Challenge during login */}
                {tempToken2FA ? (
                  <div>
                    <div className="mb-6">
                      <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-3">
                        <Smartphone className="w-5 h-5" />
                      </div>
                      <h2 className="text-xl font-bold text-white tracking-tight">Two-Factor Authentication</h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Primary password accepted. Enter the 6-digit TOTP code generated by your authenticator app.
                      </p>
                    </div>

                    {totp2FAError && (
                      <div className="p-3 mb-4 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-200 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                        <span>{totp2FAError}</span>
                      </div>
                    )}

                    <form onSubmit={handleVerify2FALogin} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          6-Digit Authenticator Code
                        </label>
                        <input
                          type="text"
                          inputMode="numeric"
                          maxLength={6}
                          value={totpInputCode}
                          onChange={(e) => setTotpInputCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                          className="w-full text-center tracking-[0.5em] font-mono text-2xl py-3 px-4 bg-slate-950 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500 transition-colors"
                          required
                          autoFocus
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={totp2FALoading || totpInputCode.length !== 6}
                        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm"
                      >
                        {totp2FALoading ? 'Verifying...' : 'Verify and Authenticate'}
                      </button>

                      <div className="text-center pt-2">
                        <button
                          type="button"
                          onClick={() => setTempToken2FA(null)}
                          className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
                        >
                          Cancel and return to login
                        </button>
                      </div>
                    </form>
                  </div>
                ) : authMode === 'login' ? (
                  /* ================= LOGIN FORM ================= */
                  <div>
                    <div className="mb-6">
                      <h2 className="text-xl font-bold text-white tracking-tight">Sign In to Account</h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Enter your registered email and password to start a secure session.
                      </p>
                    </div>

                    {loginError && (
                      <div className="p-3 mb-4 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-200 flex items-start gap-2">
                        <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                        <div>
                          <div>{loginError}</div>
                          {remainingAttempts !== null && remainingAttempts > 0 && (
                            <div className="mt-1 font-mono text-[11px] text-amber-300">
                              {remainingAttempts} attempt{remainingAttempts === 1 ? '' : 's'} remaining before security lockout.
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <form onSubmit={handleLogin} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Email Address
                        </label>
                        <div className="relative">
                          <input
                            type="email"
                            value={loginEmail}
                            onChange={(e) => setLoginEmail(e.target.value)}
                            placeholder="admin@example.com"
                            className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                            required
                          />
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <label className="text-xs font-semibold text-slate-300">Password</label>
                          <button
                            type="button"
                            onClick={() => setAuthMode('forgot')}
                            className="text-[11px] text-blue-400 hover:underline cursor-pointer"
                          >
                            Forgot password?
                          </button>
                        </div>
                        <div className="relative">
                          <input
                            type={showLoginPassword ? 'text' : 'password'}
                            value={loginPassword}
                            onChange={(e) => setLoginPassword(e.target.value)}
                            placeholder="••••••••••••"
                            className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors pr-10"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowLoginPassword(!showLoginPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                            aria-label="Toggle password visibility"
                          >
                            {showLoginPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-1">
                        <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-400">
                          <input type="checkbox" className="rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-0" />
                          <span>Remember this device</span>
                        </label>
                        <div className="text-[11px] text-slate-500">
                          CSRF Protection active
                        </div>
                      </div>

                      <button
                        type="submit"
                        disabled={loginLoading}
                        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm mt-2"
                      >
                        {loginLoading ? 'Authenticating...' : 'Sign In'}
                      </button>
                    </form>
                  </div>
                ) : authMode === 'register' ? (
                  /* ================= REGISTER FORM ================= */
                  <div>
                    <div className="mb-6">
                      <h2 className="text-xl font-bold text-white tracking-tight">Create Secure Account</h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Passwords are hashed with Bcrypt (cost factor 12) before storage.
                      </p>
                    </div>

                    {regError && (
                      <div className="p-3 mb-4 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-200 flex items-center gap-2">
                        <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                        <span>{regError}</span>
                      </div>
                    )}

                    <form onSubmit={handleRegister} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Username
                        </label>
                        <input
                          type="text"
                          value={regUsername}
                          onChange={(e) => setRegUsername(e.target.value)}
                          placeholder="johndoe_sec"
                          className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                        <span className="text-[11px] text-slate-500 mt-1 block">
                          3–20 alphanumeric characters or underscores
                        </span>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Email Address
                        </label>
                        <input
                          type="email"
                          value={regEmail}
                          onChange={(e) => setRegEmail(e.target.value)}
                          placeholder="john@example.com"
                          className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Password
                        </label>
                        <div className="relative">
                          <input
                            type={showRegPassword ? 'text' : 'password'}
                            value={regPassword}
                            onChange={(e) => setRegPassword(e.target.value)}
                            placeholder="Create strong password"
                            className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors pr-10"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowRegPassword(!showRegPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                          >
                            {showRegPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>

                        {/* Password Strength Meter */}
                        {regPassword && (
                          <div className="mt-2.5 space-y-1.5">
                            <div className="flex gap-1">
                              {[1, 2, 3, 4, 5].map((level) => (
                                <div
                                  key={level}
                                  className={`h-1 flex-1 rounded-full transition-colors ${
                                    regStrength >= level
                                      ? regStrength >= 4
                                        ? 'bg-emerald-500'
                                        : regStrength >= 3
                                        ? 'bg-amber-500'
                                        : 'bg-red-500'
                                      : 'bg-slate-800'
                                  }`}
                                />
                              ))}
                            </div>
                            <div className="grid grid-cols-2 gap-1 text-[11px] text-slate-400 pt-1">
                              <span className={regPassword.length >= 8 ? 'text-emerald-400' : ''}>
                                {regPassword.length >= 8 ? '✓' : '·'} 8+ characters
                              </span>
                              <span className={/[A-Z]/.test(regPassword) ? 'text-emerald-400' : ''}>
                                {/[A-Z]/.test(regPassword) ? '✓' : '·'} Uppercase letter
                              </span>
                              <span className={/[0-9]/.test(regPassword) ? 'text-emerald-400' : ''}>
                                {/[0-9]/.test(regPassword) ? '✓' : '·'} Number (0–9)
                              </span>
                              <span className={/[^a-zA-Z0-9]/.test(regPassword) ? 'text-emerald-400' : ''}>
                                {/[^a-zA-Z0-9]/.test(regPassword) ? '✓' : '·'} Special character
                              </span>
                            </div>
                          </div>
                        )}
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Confirm Password
                        </label>
                        <input
                          type={showRegPassword ? 'text' : 'password'}
                          value={regConfirmPassword}
                          onChange={(e) => setRegConfirmPassword(e.target.value)}
                          placeholder="Repeat password"
                          className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={regLoading}
                        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm mt-2"
                      >
                        {regLoading ? 'Creating Account...' : 'Register Secure Account'}
                      </button>
                    </form>
                  </div>
                ) : authMode === 'forgot' ? (
                  /* ================= FORGOT PASSWORD ================= */
                  <div>
                    <div className="mb-6">
                      <h2 className="text-xl font-bold text-white tracking-tight">Request Password Reset</h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Generates a single-use, 15-minute cryptographically signed reset token.
                      </p>
                    </div>

                    {forgotSuccess && (
                      <div className="p-3 mb-4 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-xs text-emerald-200">
                        {forgotSuccess}
                        <div className="mt-2 text-[11px] text-slate-300">
                          Check the Simulated Inbox in the <strong>Security Lab</strong> tab to retrieve the active token link!
                        </div>
                      </div>
                    )}

                    {forgotError && (
                      <div className="p-3 mb-4 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-200">
                        {forgotError}
                      </div>
                    )}

                    <form onSubmit={handleForgotPassword} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Account Email Address
                        </label>
                        <input
                          type="email"
                          value={forgotEmail}
                          onChange={(e) => setForgotEmail(e.target.value)}
                          placeholder="Enter your registered email"
                          className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={forgotLoading}
                        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm"
                      >
                        {forgotLoading ? 'Processing...' : 'Send Reset Instructions'}
                      </button>

                      <div className="flex justify-between items-center pt-2 text-xs">
                        <button
                          type="button"
                          onClick={() => setAuthMode('login')}
                          className="text-slate-400 hover:text-white cursor-pointer"
                        >
                          &larr; Return to Sign In
                        </button>
                        <button
                          type="button"
                          onClick={() => setAuthMode('reset')}
                          className="text-blue-400 hover:underline cursor-pointer"
                        >
                          Already have a token?
                        </button>
                      </div>
                    </form>
                  </div>
                ) : (
                  /* ================= RESET PASSWORD FORM ================= */
                  <div>
                    <div className="mb-6">
                      <h2 className="text-xl font-bold text-white tracking-tight">Set New Password</h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Enter your cryptographic reset token and choose a new secure password.
                      </p>
                    </div>

                    {resetSuccess && (
                      <div className="p-3 mb-4 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-xs text-emerald-200">
                        <div>{resetSuccess}</div>
                        <button
                          onClick={() => setAuthMode('login')}
                          className="mt-2 text-xs font-semibold text-white underline cursor-pointer"
                        >
                          Sign In now with new password &rarr;
                        </button>
                      </div>
                    )}

                    {resetError && (
                      <div className="p-3 mb-4 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-200">
                        {resetError}
                      </div>
                    )}

                    <form onSubmit={handleResetPassword} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Cryptographic Reset Token
                        </label>
                        <input
                          type="text"
                          value={resetTokenParam}
                          onChange={(e) => setResetTokenParam(e.target.value)}
                          placeholder="64-character hex token from reset email"
                          className="w-full font-mono py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          New Password
                        </label>
                        <div className="relative">
                          <input
                            type={showResetPassword ? 'text' : 'password'}
                            value={resetNewPassword}
                            onChange={(e) => setResetNewPassword(e.target.value)}
                            placeholder="At least 8 chars with mixed case and symbol"
                            className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors pr-10"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowResetPassword(!showResetPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                          >
                            {showResetPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Confirm New Password
                        </label>
                        <input
                          type={showResetPassword ? 'text' : 'password'}
                          value={resetConfirmPassword}
                          onChange={(e) => setResetConfirmPassword(e.target.value)}
                          placeholder="Repeat new password"
                          className="w-full py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
                          required
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={resetLoading}
                        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer shadow-sm"
                      >
                        {resetLoading ? 'Validating Token...' : 'Update Password & Invalidate Token'}
                      </button>

                      <div className="text-center pt-2 text-xs">
                        <button
                          type="button"
                          onClick={() => setAuthMode('login')}
                          className="text-slate-400 hover:text-white cursor-pointer"
                        >
                          &larr; Return to Sign In
                        </button>
                      </div>
                    </form>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: AUTHENTICATED USER DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {!user ? (
              <div className="border border-slate-800 rounded-xl p-8 bg-slate-900/60 text-center max-w-lg mx-auto">
                <Lock className="w-8 h-8 text-slate-500 mx-auto mb-3" />
                <h3 className="text-lg font-bold text-white mb-2">Access Protected</h3>
                <p className="text-xs text-slate-400 mb-6">
                  You are currently unauthenticated. Sign in or create a test account to view the personalized dashboard.
                </p>
                <button
                  onClick={() => {
                    setActiveTab('auth');
                    setAuthMode('login');
                  }}
                  className="px-5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors cursor-pointer"
                >
                  Proceed to Sign In
                </button>
              </div>
            ) : (
              <>
                {/* User Greeting & Header Strip */}
                <div className="border border-slate-800 rounded-xl p-6 bg-slate-900 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
                      <span>User ID #{user.id}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-emerald-400 font-medium">Active Session Verified</span>
                    </div>
                    <h1 className="text-2xl font-bold text-white tracking-tight">
                      Welcome, {user.username}!
                    </h1>
                    <p className="text-xs text-slate-400 mt-1 font-mono">
                      {user.email} · Registered on {new Date(user.created_at).toLocaleDateString()}
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    {user.is_totp_enabled ? (
                      <button
                        onClick={handleDisable2FA}
                        className="px-3.5 py-2 text-xs font-semibold text-red-300 hover:text-white bg-red-950/40 hover:bg-red-900/60 border border-red-800/80 rounded-lg transition-colors cursor-pointer"
                      >
                        Disable 2FA
                      </button>
                    ) : (
                      <button
                        onClick={handleStart2FASetup}
                        className="px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 shadow-sm"
                      >
                        <QrCode className="w-3.5 h-3.5" />
                        Enable 2FA (TOTP)
                      </button>
                    )}

                    <button
                      onClick={handleLogout}
                      className="px-3.5 py-2 text-xs font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Logout
                    </button>
                  </div>
                </div>

                {/* 2FA Setup Modal Dialog */}
                {setup2FAOpen && (
                  <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="border border-slate-800 bg-slate-900 rounded-xl max-w-md w-full p-6 shadow-xl">
                      <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                        <h3 className="text-base font-bold text-white flex items-center gap-2">
                          <QrCode className="w-4 h-4 text-blue-400" />
                          Set Up Two-Factor Authentication
                        </h3>
                        <button
                          onClick={() => setSetup2FAOpen(false)}
                          className="text-slate-400 hover:text-white text-sm cursor-pointer"
                        >
                          ✕
                        </button>
                      </div>

                      {setup2FASuccess ? (
                        <div className="text-center py-6">
                          <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-2" />
                          <h4 className="text-sm font-bold text-white">2FA Activated!</h4>
                          <p className="text-xs text-slate-400 mt-1">Your account is now protected with RFC 6238 TOTP.</p>
                        </div>
                      ) : (
                        <div>
                          <p className="text-xs text-slate-400 mb-4">
                            Scan this QR code with Google Authenticator, Authy, or Microsoft Authenticator:
                          </p>

                          <div className="flex justify-center p-3 bg-white rounded-lg mb-4">
                            <img src={setup2FAQrUrl} alt="2FA QR Code" className="w-48 h-48" />
                          </div>

                          <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-center mb-4">
                            <span className="text-[11px] text-slate-500 block mb-1">Manual Base32 Secret Key:</span>
                            <code className="text-xs font-mono font-bold text-blue-400 tracking-wider">
                              {setup2FASecret}
                            </code>
                          </div>

                          {setup2FAError && (
                            <div className="p-2.5 mb-3 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-200">
                              {setup2FAError}
                            </div>
                          )}

                          <form onSubmit={handleConfirm2FASetup} className="space-y-3">
                            <input
                              type="text"
                              maxLength={6}
                              value={setup2FACode}
                              onChange={(e) => setSetup2FACode(e.target.value.replace(/\D/g, ''))}
                              placeholder="Enter 6-digit code"
                              className="w-full text-center tracking-[0.3em] font-mono text-lg py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                              required
                            />
                            <button
                              type="submit"
                              disabled={setup2FALoading || setup2FACode.length !== 6}
                              className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg cursor-pointer"
                            >
                              {setup2FALoading ? 'Confirming...' : 'Verify & Enable 2FA'}
                            </button>
                          </form>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Dashboard Grid: Security Controls & Active Sessions */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Active Sessions Card */}
                  <div className="border border-slate-800 rounded-xl p-5 bg-slate-900">
                    <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                      <div>
                        <h2 className="text-sm font-bold text-white flex items-center gap-2">
                          <Laptop className="w-4 h-4 text-blue-400" />
                          Active Sessions & Invalidation
                        </h2>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Cryptographically unique 256-bit tokens in HttpOnly cookies.
                        </p>
                      </div>
                      {sessions.length > 1 && (
                        <button
                          onClick={() => handleRevokeSession(undefined, true)}
                          className="px-2.5 py-1 text-[11px] font-semibold text-red-300 hover:text-white bg-red-950/40 border border-red-800/80 rounded transition-colors cursor-pointer"
                        >
                          Revoke All Others
                        </button>
                      )}
                    </div>

                    <div className="space-y-2.5">
                      {sessionsLoading ? (
                        <div className="text-xs text-slate-500 py-4 text-center">Loading sessions...</div>
                      ) : sessions.length === 0 ? (
                        <div className="text-xs text-slate-500 py-4 text-center">No active sessions found.</div>
                      ) : (
                        sessions.map((s) => (
                          <div
                            key={s.id}
                            className={`p-3 rounded-lg border flex items-center justify-between text-xs ${
                              s.is_current
                                ? 'bg-blue-950/20 border-blue-800/50'
                                : 'bg-slate-950 border-slate-800'
                            }`}
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-medium text-slate-200">
                                  {s.ip_address}
                                </span>
                                {s.is_current && (
                                  <span className="text-[10px] text-emerald-400 font-semibold px-1.5 py-0.5 bg-emerald-950/60 border border-emerald-800/50 rounded">
                                    Current Device
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] text-slate-400 truncate max-w-xs mt-0.5">
                                {s.user_agent}
                              </p>
                              <span className="text-[10px] text-slate-500 block font-mono mt-0.5">
                                Created: {new Date(s.created_at).toLocaleString()}
                              </span>
                            </div>

                            <button
                              onClick={() => handleRevokeSession(s.id)}
                              className="text-[11px] text-red-400 hover:text-red-300 hover:underline cursor-pointer ml-3 shrink-0"
                            >
                              Terminate
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Change Password Panel */}
                  <div className="border border-slate-800 rounded-xl p-5 bg-slate-900">
                    <h2 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-slate-800 mb-4">
                      <Key className="w-4 h-4 text-amber-400" />
                      Update Account Password
                    </h2>

                    {changePassSuccess && (
                      <div className="p-2.5 mb-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-xs text-emerald-200">
                        {changePassSuccess}
                      </div>
                    )}

                    {changePassError && (
                      <div className="p-2.5 mb-3 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-200">
                        {changePassError}
                      </div>
                    )}

                    <form onSubmit={handleChangePassword} className="space-y-3">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          Current Password
                        </label>
                        <input
                          type="password"
                          value={currentPass}
                          onChange={(e) => setCurrentPass(e.target.value)}
                          placeholder="Verify current password"
                          className="w-full py-1.5 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          New Password
                        </label>
                        <input
                          type="password"
                          value={newPass}
                          onChange={(e) => setNewPass(e.target.value)}
                          placeholder="New password (8+ chars, symbols)"
                          className="w-full py-1.5 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          Confirm New Password
                        </label>
                        <input
                          type="password"
                          value={confirmNewPass}
                          onChange={(e) => setConfirmNewPass(e.target.value)}
                          placeholder="Repeat new password"
                          className="w-full py-1.5 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                          required
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={changePassLoading}
                        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-colors cursor-pointer mt-1"
                      >
                        {changePassLoading ? 'Updating...' : 'Save New Password'}
                      </button>
                    </form>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* TAB 3: INTERACTIVE CYBERSECURITY STUDENT LAB */}
        {activeTab === 'lab' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                Interactive Cybersecurity Defense Lab
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Real-time penetration test verification suite: observe how SQL injection defense, Bcrypt work factors, CSRF double-submits, and rate limiting function in practice.
              </p>
            </div>

            {/* Sub-navigation tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg max-w-xl">
              <button
                onClick={() => setLabSection('sqli')}
                className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  labSection === 'sqli' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                }`}
              >
                SQLi Immunity Probe
              </button>
              <button
                onClick={() => setLabSection('bcrypt')}
                className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  labSection === 'bcrypt' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                }`}
              >
                Bcrypt Work Factor
              </button>
              <button
                onClick={() => setLabSection('csrf')}
                className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  labSection === 'csrf' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                }`}
              >
                CSRF Defense
              </button>
              <button
                onClick={() => setLabSection('audit')}
                className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  labSection === 'audit' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-white'
                }`}
              >
                Audit Telemetry
              </button>
            </div>

            {/* SECTION 1: SQL INJECTION PROBE */}
            {labSection === 'sqli' && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-emerald-400" />
                      SQL Injection Resistance Test
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Execute test injection payloads against the parameterized SQLite engine to verify that malicious syntax is neutralized into plain literals.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Target Query Input Payload
                    </label>
                    <input
                      type="text"
                      value={sqliInput}
                      onChange={(e) => setSqliInput(e.target.value)}
                      className="w-full font-mono text-xs py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white"
                    />
                  </div>

                  <div className="flex flex-wrap gap-1.5 pt-1">
                    <span className="text-[11px] text-slate-400 self-center mr-1">Presets:</span>
                    {[
                      "admin@example.com' OR '1'='1",
                      "admin'--",
                      "'; DROP TABLE users;--",
                      "' UNION SELECT 1, 'hacked', 'pwned'--",
                    ].map((preset) => (
                      <button
                        key={preset}
                        type="button"
                        onClick={() => setSqliInput(preset)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 font-mono text-[10px] text-slate-300 rounded cursor-pointer"
                      >
                        {preset}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={runSqliProbe}
                    disabled={sqliLoading}
                    className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg cursor-pointer"
                  >
                    {sqliLoading ? 'Executing Prepared Statement...' : 'Execute Parameterized Query'}
                  </button>
                </div>

                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Query Execution & Architectural Analysis
                  </h3>

                  {sqliResponse ? (
                    <div className="space-y-3 text-xs">
                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px]">
                        <span className="text-slate-500 block">Prepared SQL Statement:</span>
                        <span className="text-blue-400">{sqliResponse.parameterizedQueryUsed}</span>
                        <span className="text-slate-500 block mt-2">Bound Literal Parameter:</span>
                        <span className="text-amber-300">"{sqliResponse.boundParameter}"</span>
                        <span className="text-slate-500 block mt-2">Records Matched:</span>
                        <span className="text-emerald-400 font-bold">{sqliResponse.matchCount} records</span>
                        <span className="text-slate-500 block mt-2">Execution Latency:</span>
                        <span className="text-slate-300">{sqliResponse.executionTimeMicroseconds} μs</span>
                      </div>

                      <div className="p-3 bg-emerald-950/20 border border-emerald-800/40 rounded-lg text-emerald-200 text-xs leading-relaxed">
                        <strong>Defensive Outcome: </strong>
                        {sqliResponse.securityExplanation}
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                      Click "Execute Parameterized Query" to test the SQL payload against the SQLite prepared statement engine.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SECTION 2: BCRYPT WORK FACTOR */}
            {labSection === 'bcrypt' && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-2">
                      <Lock className="w-4 h-4 text-blue-400" />
                      Bcrypt Cost Factor Analyzer
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Bcrypt uses the Eksblowfish algorithm with an exponential cost parameter (2<sup>rounds</sup> iterations) to thwart GPU-based brute forcing.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Plaintext Password Input
                    </label>
                    <input
                      type="text"
                      value={bcryptPassInput}
                      onChange={(e) => setBcryptPassInput(e.target.value)}
                      className="w-full font-mono text-xs py-2 px-3 bg-slate-950 border border-slate-700 rounded-lg text-white"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-xs mb-1">
                      <span className="font-semibold text-slate-300">Work Factor (Rounds): {bcryptRounds}</span>
                      <span className="font-mono text-amber-400">2^{bcryptRounds} = {(2 ** bcryptRounds).toLocaleString()} passes</span>
                    </div>
                    <input
                      type="range"
                      min="8"
                      max="13"
                      value={bcryptRounds}
                      onChange={(e) => setBcryptRounds(Number(e.target.value))}
                      className="w-full accent-blue-500"
                    />
                    <div className="flex justify-between text-[10px] text-slate-500">
                      <span>8 (Fast / Test)</span>
                      <span>10 (Legacy)</span>
                      <span>12 (Production Recommended)</span>
                      <span>13 (High Security)</span>
                    </div>
                  </div>

                  <button
                    onClick={runBcryptProbe}
                    disabled={bcryptLoading}
                    className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg cursor-pointer"
                  >
                    {bcryptLoading ? 'Computing Salt & Eksblowfish Hashes...' : 'Hash with Bcrypt'}
                  </button>
                </div>

                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Cryptographic Hash Breakdown
                  </h3>

                  {bcryptResponse ? (
                    <div className="space-y-3 text-xs">
                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] break-all">
                        <span className="text-slate-500 block">Complete Stored Hash:</span>
                        <span className="text-blue-400 font-bold">{bcryptResponse.fullHash}</span>
                        <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-slate-800 text-[11px]">
                          <div>
                            <span className="text-slate-500 block">Identifier:</span>
                            <span className="text-emerald-400">{bcryptResponse.breakdown.algorithm}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Cost Factor:</span>
                            <span className="text-amber-400">{bcryptResponse.breakdown.costFactor}</span>
                          </div>
                          <div className="col-span-2">
                            <span className="text-slate-500 block">Cryptographic 128-bit Salt:</span>
                            <span className="text-slate-300">{bcryptResponse.breakdown.salt}</span>
                          </div>
                        </div>
                      </div>

                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Server Execution Time:</span>
                        <span className="font-mono font-bold text-emerald-400 text-sm">
                          {bcryptResponse.durationMs} ms
                        </span>
                      </div>

                      <div className="p-3 bg-blue-950/20 border border-blue-800/40 rounded-lg text-blue-200 text-xs">
                        <strong>Brute Force Resistance: </strong>
                        {bcryptResponse.securityAnalysis.bruteForceResistance}
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                      Generate a Bcrypt hash to inspect the 22-character cryptographic salt and cost parameters.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SECTION 3: CSRF DEFENSE SIMULATOR */}
            {labSection === 'csrf' && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-amber-400" />
                      Cross-Site Request Forgery (CSRF) Simulator
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Our system enforces a Double-Submit Cookie pattern with HMAC verification. An attacker triggering cross-origin requests cannot forge this token.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono">
                    <span className="text-slate-500 block mb-1">Your Browser's Current Active CSRF Token:</span>
                    <span className="text-blue-400 text-[11px] break-all">{csrfToken || 'Fetching...'}</span>
                  </div>

                  <div className="flex gap-3">
                    <button
                      onClick={() => runCsrfTest(true)}
                      disabled={csrfTesting}
                      className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg cursor-pointer"
                    >
                      Test with Valid CSRF Header
                    </button>
                    <button
                      onClick={() => runCsrfTest(false)}
                      disabled={csrfTesting}
                      className="flex-1 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg cursor-pointer"
                    >
                      Simulate Attack (Missing Token)
                    </button>
                  </div>
                </div>

                <div className="lg:col-span-6 border border-slate-800 rounded-xl p-5 bg-slate-900 space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Shield className="w-4 h-4 text-blue-400" />
                    CSRF Filter Inspection Response
                  </h3>

                  {csrfTestResult ? (
                    <div className="space-y-3 text-xs">
                      <div
                        className={`p-3 rounded-lg border ${
                          csrfTestResult.blocked
                            ? 'bg-red-950/20 border-red-800/60'
                            : 'bg-emerald-950/20 border-emerald-800/60'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono font-bold mb-1">
                          <span>HTTP {csrfTestResult.statusCode} {csrfTestResult.statusText}</span>
                          <span>
                            {csrfTestResult.blocked ? 'BLOCKED BY CSRF FILTER' : 'CSRF CHECK PASSED'}
                          </span>
                        </div>
                        <p className="text-[11px] mt-2 font-mono text-slate-300">
                          {JSON.stringify(csrfTestResult.response, null, 2)}
                        </p>
                      </div>

                      <p className="text-xs text-slate-400">
                        {csrfTestResult.blocked
                          ? 'Notice how the server returned HTTP 403 Forbidden with code "CSRF_FAILED". Because malicious external scripts cannot read the origin cookie or provide the valid HMAC header, the state change was aborted.'
                          : 'Valid CSRF token was supplied and verified via timing-safe HMAC equality. The request proceeded to authentication evaluation.'}
                      </p>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                      Simulate a legitimate vs forged request to inspect the anti-forgery token verification.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SECTION 4: AUDIT TELEMETRY & RESET INBOX */}
            {labSection === 'audit' && (
              <div className="space-y-6">
                {/* Simulated Out-Of-Band Reset Inbox */}
                <div className="border border-slate-800 rounded-xl p-5 bg-slate-900">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
                    <div>
                      <h2 className="text-sm font-bold text-white flex items-center gap-2">
                        <Mail className="w-4 h-4 text-blue-400" />
                        Simulated Out-of-Band Password Reset Inbox
                      </h2>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        In production, these single-use tokens are emailed. For this lab, dispatched reset links appear here for instant verification.
                      </p>
                    </div>
                    <button
                      onClick={loadResetInbox}
                      className="px-2 py-1 text-xs text-slate-300 hover:text-white bg-slate-800 rounded cursor-pointer"
                    >
                      Refresh
                    </button>
                  </div>

                  {resetInbox.length === 0 ? (
                    <p className="text-xs text-slate-500 py-3 text-center">
                      No reset tokens dispatched yet. Use "Forgot Password" on the Auth Portal to generate one.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {resetInbox.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs flex items-center justify-between"
                        >
                          <div>
                            <div className="font-semibold text-slate-200">
                              Recipient: <span className="text-blue-400">{item.email}</span>
                            </div>
                            <div className="font-mono text-[11px] text-slate-400 mt-1 break-all">
                              Token: {item.token}
                            </div>
                            <span className="text-[10px] text-slate-500 block mt-0.5">
                              Dispatched: {new Date(item.sentAt).toLocaleTimeString()} · Expires in 15 minutes
                            </span>
                          </div>

                          <button
                            onClick={() => {
                              setActiveTab('auth');
                              setAuthMode('reset');
                              setResetTokenParam(item.token);
                            }}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded transition-colors cursor-pointer shrink-0 ml-3"
                          >
                            Use Token
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Live Security Audit Log Viewer */}
                <div className="border border-slate-800 rounded-xl p-5 bg-slate-900">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                    <div>
                      <h2 className="text-sm font-bold text-white flex items-center gap-2">
                        <Clock className="w-4 h-4 text-emerald-400" />
                        Live Security Audit Telemetry
                      </h2>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Centralized event logging capturing authentication outcomes and security violations.
                      </p>
                    </div>
                    <button
                      onClick={loadSecurityLogs}
                      className="px-2.5 py-1 text-xs text-slate-300 hover:text-white bg-slate-800 rounded cursor-pointer flex items-center gap-1"
                    >
                      <RefreshCw className="w-3 h-3" />
                      Refresh
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse font-sans">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2.5 px-3">Event Type</th>
                          <th className="py-2.5 px-3">Details</th>
                          <th className="py-2.5 px-3">Account</th>
                          <th className="py-2.5 px-3">IP Address</th>
                          <th className="py-2.5 px-3 text-right">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {securityLogs.slice(0, 15).map((log) => (
                          <tr key={log.id} className="hover:bg-slate-800/30">
                            <td className="py-2 px-3 font-mono font-semibold">
                              <span
                                className={`text-[11px] ${
                                  log.event_type.includes('SUCCESS') || log.event_type.includes('VERIFIED')
                                    ? 'text-emerald-400'
                                    : log.event_type.includes('FAILED') || log.event_type.includes('LIMITED')
                                    ? 'text-red-400'
                                    : 'text-blue-400'
                                }`}
                              >
                                {log.event_type}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-slate-300 text-xs">{log.details}</td>
                            <td className="py-2 px-3 text-slate-400 font-mono text-[11px]">
                              {log.username ? `@${log.username}` : '—'}
                            </td>
                            <td className="py-2 px-3 text-slate-400 font-mono text-[11px]">{log.ip_address}</td>
                            <td className="py-2 px-3 text-right font-mono text-slate-500 text-[11px]">
                              {new Date(log.created_at).toLocaleTimeString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: PYTHON FLASK CODE EXPLORER */}
        {activeTab === 'flask_code' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <Code className="w-5 h-5 text-blue-400" />
                  Python & Flask Security Architecture Explorer
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Complete, standalone Python source files matching the Flask, WTForms, and Pytest implementation requirements.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => copyToClipboard(flaskFiles[selectedFlaskFile] || '')}
                  className="px-3 py-1.5 text-xs font-semibold text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedCode ? 'Copied' : 'Copy File'}
                </button>
              </div>
            </div>

            {/* File Switcher Tabs */}
            <div className="flex flex-wrap gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
              {Object.keys(flaskFiles).map((fileName) => (
                <button
                  key={fileName}
                  onClick={() => setSelectedFlaskFile(fileName)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md font-mono transition-colors cursor-pointer ${
                    selectedFlaskFile === fileName
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {fileName}
                </button>
              ))}
            </div>

            {/* Code Display Area */}
            <div className="border border-slate-800 rounded-xl bg-slate-950 overflow-hidden shadow-sm">
              <div className="px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
                  <FileText className="w-3.5 h-3.5 text-blue-400" />
                  <span>flask_app/{selectedFlaskFile}</span>
                </div>
                <span className="text-[11px] text-slate-500">Python 3 / Flask</span>
              </div>
              <pre className="p-4 overflow-x-auto text-xs font-mono text-slate-200 leading-relaxed max-h-[580px]">
                {flaskFiles[selectedFlaskFile]}
              </pre>
            </div>
          </div>
        )}
      </main>

      {/* ================= FOOTER ================= */}
      <footer className="border-t border-slate-800 py-6 px-6 text-center text-xs text-slate-500 mt-auto">
        <p>
          SecureAuth Defense Platform &copy; 2026. Built with Python, Flask, Express, and Vite for Cybersecurity Education.
        </p>
      </footer>
    </div>
  );
}
