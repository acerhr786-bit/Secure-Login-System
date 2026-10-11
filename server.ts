import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { db, initDatabase } from './server/db.js';
import {
  hashPassword,
  verifyPassword,
  fakePasswordVerification,
  validatePasswordStrength,
  validateEmail,
  validateUsername,
  generateSecureToken,
  hashToken,
  generateCsrfToken,
  verifyCsrfToken,
  checkRateLimit,
  recordFailedAttempt,
  resetRateLimit,
  generateTotpSecret,
  verifyTotpToken,
  generateQrCodeUrl,
  logSecurityEvent,
  BCRYPT_SALT_ROUNDS,
  SESSION_DURATION_HOURS,
  RESET_TOKEN_EXPIRY_MINUTES,
  MAX_LOGIN_ATTEMPTS,
} from './server/security.js';

// Initialize SQLite database
initDatabase();

const app = express();
const PORT = 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Express middleware
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Security Headers Middleware (OWASP recommended)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// CSRF Cookie Setter (sets double-submit token on read requests)
app.use((req: Request, res: Response, next: NextFunction) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    if (!req.cookies['XSRF-TOKEN']) {
      const { token } = generateCsrfToken();
      res.cookie('XSRF-TOKEN', token, {
        httpOnly: false, // Accessible by JavaScript client to send in header
        sameSite: 'strict',
        secure: isProduction,
        path: '/',
      });
    }
  }
  next();
});

// In-memory 2FA pending sessions (short lived 5 min)
interface Pending2FASession {
  userId: number;
  expiresAt: number;
}
const pending2FASessions = new Map<string, Pending2FASession>();

// In-memory record of simulated dispatched password reset tokens (for cybersecurity lab testing)
interface DispatchedResetNotice {
  email: string;
  token: string;
  expiresAt: string;
  sentAt: string;
}
const simulatedResetInbox: DispatchedResetNotice[] = [];

// Helper: Extract authenticated user from session cookie
interface AuthUser {
  id: number;
  username: string;
  email: string;
  is_totp_enabled: number;
  created_at: string;
  last_login_at: string | null;
  sessionToken: string;
}

function getAuthenticatedUser(req: Request): AuthUser | null {
  const sessionToken = req.cookies['session_token'];
  if (!sessionToken) return null;

  try {
    const session = db
      .prepare(`
        SELECT s.token, s.user_id, s.expires_at, u.id, u.username, u.email, u.is_totp_enabled, u.created_at, u.last_login_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
      `)
      .get(sessionToken) as any;

    if (!session) return null;

    // Check expiry
    const expiresAt = new Date(session.expires_at).getTime();
    if (Date.now() > expiresAt) {
      db.prepare('DELETE FROM sessions WHERE token = ?').run(sessionToken);
      return null;
    }

    return {
      id: session.id,
      username: session.username,
      email: session.email,
      is_totp_enabled: Boolean(session.is_totp_enabled) ? 1 : 0,
      created_at: session.created_at,
      last_login_at: session.last_login_at,
      sessionToken: session.token,
    };
  } catch (err) {
    console.error('Error fetching session:', err);
    return null;
  }
}

// Authentication Guard Middleware
function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required. Session is invalid or expired.' });
  }
  (req as any).user = user;
  next();
}

// CSRF Validation Guard for State Changing endpoints
function requireCsrf(req: Request, res: Response, next: NextFunction) {
  // Allow bypassing only if explicit test header is provided in the security lab simulator
  if (req.headers['x-bypass-csrf-for-lab'] === 'true') {
    return next();
  }

  const clientToken = req.headers['x-csrf-token'] as string;
  const cookieToken = req.cookies['XSRF-TOKEN'] as string;

  if (!verifyCsrfToken(clientToken, cookieToken)) {
    return res.status(403).json({
      error: 'CSRF token missing or invalid. State-changing requests require a valid anti-forgery token.',
      code: 'CSRF_FAILED',
    });
  }
  next();
}

// ==================== AUTHENTICATION API ROUTES ====================

// CSRF Token refresh endpoint
app.get('/api/csrf-token', (req: Request, res: Response) => {
  const { token } = generateCsrfToken();
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    sameSite: 'strict',
    secure: isProduction,
    path: '/',
  });
  res.json({ csrfToken: token });
});

// Current User Session check
app.get('/api/auth/me', (req: Request, res: Response) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.json({ authenticated: false, user: null });
  }
  res.json({
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      is_totp_enabled: Boolean(user.is_totp_enabled),
      created_at: user.created_at,
      last_login_at: user.last_login_at,
    },
  });
});

// Registration
app.post('/api/auth/register', requireCsrf, async (req: Request, res: Response) => {
  const { username, email, password } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  // 1. Input Validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields (username, email, password) are required.' });
  }

  if (!validateUsername(username)) {
    return res.status(400).json({
      error: 'Username must be 3-20 characters long and contain only letters, numbers, and underscores.',
    });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const passCheck = validatePasswordStrength(password);
  if (!passCheck.isValid) {
    return res.status(400).json({
      error: 'Password does not meet security requirements.',
      details: passCheck.errors,
    });
  }

  try {
    // 2. Check for duplicate credentials using parameterized query
    const existing = db
      .prepare('SELECT username, email FROM users WHERE username = ? OR email = ?')
      .get(username.trim(), email.trim().toLowerCase()) as any;

    if (existing) {
      if (existing.username.toLowerCase() === username.trim().toLowerCase()) {
        return res.status(409).json({ error: 'Username is already registered. Please choose another.' });
      }
      return res.status(409).json({ error: 'Email address is already registered. Try logging in or resetting password.' });
    }

    // 3. Secure Bcrypt Password Hashing
    const passwordHash = await hashPassword(password);
    const now = new Date().toISOString();

    // 4. Parameterized Insert into users
    const result = db
      .prepare(`
        INSERT INTO users (username, email, password_hash, created_at, last_login_at)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(username.trim(), email.trim().toLowerCase(), passwordHash, now, now);

    const newUserId = Number(result.lastInsertRowid);

    // 5. Create active session
    const sessionToken = generateSecureToken(32);
    const expiresDate = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000).toISOString();
    const userAgent = (req.headers['user-agent'] || 'Unknown').substring(0, 255);

    db.prepare(`
      INSERT INTO sessions (token, user_id, ip_address, user_agent, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionToken, newUserId, clientIp, userAgent, now, expiresDate);

    // Set HttpOnly, SameSite=Strict session cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProduction,
      maxAge: SESSION_DURATION_HOURS * 3600 * 1000,
      path: '/',
    });

    logSecurityEvent('USER_REGISTERED', `Account registered for @${username}`, newUserId, clientIp);
    logSecurityEvent('LOGIN_SUCCESS', 'Initial login upon registration', newUserId, clientIp);

    res.status(201).json({
      message: 'Account registered and authenticated successfully.',
      user: {
        id: newUserId,
        username: username.trim(),
        email: email.trim().toLowerCase(),
        is_totp_enabled: false,
        created_at: now,
        last_login_at: now,
      },
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'An unexpected internal error occurred during registration.' });
  }
});

// Login
app.post('/api/auth/login', requireCsrf, async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const clientIp = req.ip || '127.0.0.1';
  const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (!cleanEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  // 1. Rate Limiting Check (Per IP + Email combination)
  const rateLimitKey = `${clientIp}_${cleanEmail}`;
  const rateCheck = checkRateLimit(rateLimitKey);
  if (rateCheck.isBlocked) {
    logSecurityEvent('RATE_LIMITED', `Brute force defense triggered for ${cleanEmail}`, null, clientIp);
    return res.status(429).json({
      error: `Too many failed login attempts. Account temporarily locked for security. Try again in ${rateCheck.retryAfterSec} seconds.`,
      retryAfter: rateCheck.retryAfterSec,
    });
  }

  try {
    // 2. Parameterized Query
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as any;

    // 3. Constant-time password verification (defense against user enumeration and timing attacks)
    let passwordMatches = false;
    if (user) {
      passwordMatches = await verifyPassword(password, user.password_hash);
    } else {
      // Execute fake bcrypt comparison so response time is indistinguishable
      await fakePasswordVerification(password);
    }

    if (!user || !passwordMatches) {
      recordFailedAttempt(rateLimitKey);
      const updatedCheck = checkRateLimit(rateLimitKey);
      logSecurityEvent('LOGIN_FAILED', `Failed login attempt for ${cleanEmail}`, user?.id || null, clientIp);

      return res.status(401).json({
        error: 'Invalid email or password combination.',
        remainingAttempts: updatedCheck.remainingAttempts,
      });
    }

    // Reset failed rate limit counter upon correct credentials
    resetRateLimit(rateLimitKey);

    // 4. Two-Factor Authentication Check
    if (Boolean(user.is_totp_enabled)) {
      const tempToken = generateSecureToken(24);
      pending2FASessions.set(tempToken, {
        userId: user.id,
        expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes validity
      });

      logSecurityEvent('2FA_PROMPTED', 'Primary credentials valid; 2FA prompt issued', user.id, clientIp);

      return res.json({
        require2FA: true,
        tempToken,
        message: 'Two-factor authentication code required.',
      });
    }

    // 5. Successful login without 2FA
    const now = new Date().toISOString();
    const sessionToken = generateSecureToken(32);
    const expiresDate = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000).toISOString();
    const userAgent = (req.headers['user-agent'] || 'Unknown').substring(0, 255);

    // Update last_login_at
    db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now, user.id);

    // Insert session into DB
    db.prepare(`
      INSERT INTO sessions (token, user_id, ip_address, user_agent, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionToken, user.id, clientIp, userAgent, now, expiresDate);

    // Issue HttpOnly Cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProduction,
      maxAge: SESSION_DURATION_HOURS * 3600 * 1000,
      path: '/',
    });

    logSecurityEvent('LOGIN_SUCCESS', `User authenticated successfully`, user.id, clientIp);

    res.json({
      message: 'Authenticated successfully.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        is_totp_enabled: false,
        created_at: user.created_at,
        last_login_at: now,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal authentication service error.' });
  }
});

// Verify 2FA during Login
app.post('/api/auth/verify-2fa', requireCsrf, async (req: Request, res: Response) => {
  const { tempToken, code } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (!tempToken || !code) {
    return res.status(400).json({ error: 'Temporary token and 6-digit verification code are required.' });
  }

  const pending = pending2FASessions.get(tempToken);
  if (!pending || Date.now() > pending.expiresAt) {
    pending2FASessions.delete(tempToken);
    return res.status(401).json({ error: '2FA session has expired. Please log in again.' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(pending.userId) as any;
    if (!user || !user.totp_secret) {
      pending2FASessions.delete(tempToken);
      return res.status(400).json({ error: '2FA is not configured for this account.' });
    }

    const isValid = verifyTotpToken(String(code).trim(), user.totp_secret);
    if (!isValid) {
      logSecurityEvent('2FA_FAILED', 'Invalid 2FA code supplied', user.id, clientIp);
      return res.status(401).json({ error: 'Invalid verification code. Please check your authenticator app.' });
    }

    // Success - consume pending token
    pending2FASessions.delete(tempToken);

    const now = new Date().toISOString();
    const sessionToken = generateSecureToken(32);
    const expiresDate = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000).toISOString();
    const userAgent = (req.headers['user-agent'] || 'Unknown').substring(0, 255);

    db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now, user.id);
    db.prepare(`
      INSERT INTO sessions (token, user_id, ip_address, user_agent, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionToken, user.id, clientIp, userAgent, now, expiresDate);

    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProduction,
      maxAge: SESSION_DURATION_HOURS * 3600 * 1000,
      path: '/',
    });

    logSecurityEvent('2FA_VERIFIED', '2FA verification succeeded; login completed', user.id, clientIp);

    res.json({
      message: '2FA verification successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        is_totp_enabled: true,
        created_at: user.created_at,
        last_login_at: now,
      },
    });
  } catch (err) {
    console.error('2FA verification error:', err);
    res.status(500).json({ error: 'Failed to verify two-factor authentication.' });
  }
});

// Logout
app.post('/api/auth/logout', requireCsrf, (req: Request, res: Response) => {
  const sessionToken = req.cookies['session_token'];
  const user = getAuthenticatedUser(req);
  const clientIp = req.ip || '127.0.0.1';

  if (sessionToken) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(sessionToken);
  }

  res.clearCookie('session_token', {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
    path: '/',
  });

  if (user) {
    logSecurityEvent('LOGOUT', 'User logged out and session terminated', user.id, clientIp);
  }

  res.json({ message: 'Session invalidated and logged out successfully.' });
});

// Active Sessions List
app.get('/api/auth/sessions', requireAuth, (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;
  const sessions = db
    .prepare(`
      SELECT id, token, ip_address, user_agent, created_at, expires_at
      FROM sessions
      WHERE user_id = ?
      ORDER BY id DESC
    `)
    .all(currentUser.id) as any[];

  const sanitized = sessions.map((s) => ({
    id: s.id,
    ip_address: s.ip_address,
    user_agent: s.user_agent,
    created_at: s.created_at,
    expires_at: s.expires_at,
    is_current: s.token === currentUser.sessionToken,
  }));

  res.json({ sessions: sanitized });
});

// Revoke Session(s)
app.post('/api/auth/sessions/revoke', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;
  const { sessionId, revokeOthers } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (revokeOthers) {
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(currentUser.id, currentUser.sessionToken);
    logSecurityEvent('SESSION_REVOKED', 'Revoked all other active sessions', currentUser.id, clientIp);
    return res.json({ message: 'All other active sessions have been revoked.' });
  }

  if (sessionId) {
    // Check if user owns this session
    const targetSession = db.prepare('SELECT token FROM sessions WHERE id = ? AND user_id = ?').get(sessionId, currentUser.id) as any;
    if (!targetSession) {
      return res.status(404).json({ error: 'Session not found or already expired.' });
    }

    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);

    // If revoking current session, clear cookie
    if (targetSession.token === currentUser.sessionToken) {
      res.clearCookie('session_token', {
        httpOnly: true,
        sameSite: 'strict',
        secure: isProduction,
        path: '/',
      });
    }

    logSecurityEvent('SESSION_REVOKED', `Session #${sessionId} revoked`, currentUser.id, clientIp);
    return res.json({ message: 'Session revoked successfully.' });
  }

  res.status(400).json({ error: 'Please specify sessionId or revokeOthers.' });
});

// Change Password
app.post('/api/auth/change-password', requireAuth, requireCsrf, async (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;
  const { currentPassword, newPassword } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required.' });
  }

  const passCheck = validatePasswordStrength(newPassword);
  if (!passCheck.isValid) {
    return res.status(400).json({
      error: 'New password does not meet security requirements.',
      details: passCheck.errors,
    });
  }

  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(currentUser.id) as any;
  const matches = await verifyPassword(currentPassword, user.password_hash);
  if (!matches) {
    logSecurityEvent('PASSWORD_CHANGE_FAILED', 'Incorrect current password provided', currentUser.id, clientIp);
    return res.status(400).json({ error: 'Current password verification failed.' });
  }

  const newHash = await hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, currentUser.id);

  logSecurityEvent('PASSWORD_CHANGED', 'User updated account password', currentUser.id, clientIp);

  res.json({ message: 'Password changed successfully.' });
});

// Two-Factor Authentication Setup (Start)
app.post('/api/auth/2fa/setup', requireAuth, requireCsrf, async (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;

  const secret = generateTotpSecret(20);
  const qrCodeUrl = await generateQrCodeUrl(secret, currentUser.email, 'SecureAuth');

  // Save candidate secret temporarily
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret, currentUser.id);

  res.json({
    secret,
    qrCodeUrl,
    message: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.).',
  });
});

// Two-Factor Authentication Confirmation (Activate)
app.post('/api/auth/2fa/confirm', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;
  const { code } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (!code) {
    return res.status(400).json({ error: 'Verification code is required.' });
  }

  const user = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(currentUser.id) as any;
  if (!user || !user.totp_secret) {
    return res.status(400).json({ error: '2FA setup has not been initiated.' });
  }

  const isValid = verifyTotpToken(String(code).trim(), user.totp_secret);
  if (!isValid) {
    return res.status(400).json({ error: 'Invalid verification code. Please check the code in your app.' });
  }

  db.prepare('UPDATE users SET is_totp_enabled = 1 WHERE id = ?').run(currentUser.id);
  logSecurityEvent('2FA_ENABLED', 'Two-Factor Authentication activated', currentUser.id, clientIp);

  res.json({ message: 'Two-factor authentication successfully enabled!' });
});

// Two-Factor Authentication Disable
app.post('/api/auth/2fa/disable', requireAuth, requireCsrf, async (req: Request, res: Response) => {
  const currentUser = (req as any).user as AuthUser;
  const { currentPassword } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (!currentPassword) {
    return res.status(400).json({ error: 'Account password is required to disable 2FA.' });
  }

  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(currentUser.id) as any;
  const matches = await verifyPassword(currentPassword, user.password_hash);
  if (!matches) {
    return res.status(400).json({ error: 'Incorrect account password.' });
  }

  db.prepare('UPDATE users SET is_totp_enabled = 0, totp_secret = NULL WHERE id = ?').run(currentUser.id);
  logSecurityEvent('2FA_DISABLED', 'Two-Factor Authentication disabled', currentUser.id, clientIp);

  res.json({ message: 'Two-factor authentication has been disabled.' });
});

// Forgot Password - Token Request
app.post('/api/auth/forgot-password', requireCsrf, (req: Request, res: Response) => {
  const { email } = req.body;
  const clientIp = req.ip || '127.0.0.1';
  const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (!cleanEmail) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(cleanEmail) as any;

  if (user) {
    // Generate secure 32-byte single-use token
    const rawToken = generateSecureToken(32);
    const tokenHash = hashToken(rawToken);
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO password_reset_tokens (token_hash, user_id, created_at, expires_at, used)
      VALUES (?, ?, ?, ?, 0)
    `).run(tokenHash, user.id, now, expiresAt);

    // Save notice to simulated secure inbox for testing
    simulatedResetInbox.unshift({
      email: cleanEmail,
      token: rawToken,
      expiresAt,
      sentAt: now,
    });
    if (simulatedResetInbox.length > 20) simulatedResetInbox.pop();

    logSecurityEvent('PASSWORD_RESET_REQUESTED', `Reset token generated for ${cleanEmail}`, user.id, clientIp);
  }

  // Consistent message prevents email enumeration
  res.json({
    message: 'If an account with that email address exists, a secure password reset link has been dispatched.',
  });
});

// Reset Password - Verify Token & Set New Password
app.post('/api/auth/reset-password', requireCsrf, async (req: Request, res: Response) => {
  const { token, newPassword } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Reset token and new password are required.' });
  }

  const passCheck = validatePasswordStrength(newPassword);
  if (!passCheck.isValid) {
    return res.status(400).json({
      error: 'New password does not meet security requirements.',
      details: passCheck.errors,
    });
  }

  const tokenHash = hashToken(token.trim());
  const resetRecord = db
    .prepare(`
      SELECT r.id, r.user_id, r.expires_at, r.used, u.email
      FROM password_reset_tokens r
      JOIN users u ON r.user_id = u.id
      WHERE r.token_hash = ?
    `)
    .get(tokenHash) as any;

  if (!resetRecord) {
    return res.status(400).json({ error: 'Invalid or malformed password reset token.' });
  }

  if (Boolean(resetRecord.used)) {
    return res.status(400).json({ error: 'This password reset token has already been used and is invalidated.' });
  }

  if (Date.now() > new Date(resetRecord.expires_at).getTime()) {
    return res.status(400).json({ error: 'This password reset token has expired. Please request a new one.' });
  }

  // Valid token: update password and mark token as used
  const newHash = await hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, resetRecord.user_id);
  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').run(resetRecord.id);

  // Invalidate all existing sessions for this user for security
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(resetRecord.user_id);

  logSecurityEvent('PASSWORD_RESET_COMPLETED', `Password successfully reset via token`, resetRecord.user_id, clientIp);

  res.json({ message: 'Password has been reset successfully. Please log in with your new credentials.' });
});

// ==================== CYBERSECURITY LAB / INSPECTOR ROUTES ====================

// Security Audit Log viewer
app.get('/api/security-lab/logs', (req: Request, res: Response) => {
  const logs = db
    .prepare(`
      SELECT l.id, l.event_type, l.details, l.ip_address, l.created_at, u.username
      FROM security_logs l
      LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.id DESC
      LIMIT 50
    `)
    .all();

  res.json({ logs });
});

// Simulated Reset Inbox (view out-of-band reset links for testing)
app.get('/api/security-lab/reset-inbox', (req: Request, res: Response) => {
  res.json({ inbox: simulatedResetInbox });
});

// SQL Injection Defense Probe & Explanation
app.post('/api/security-lab/test-sqli', (req: Request, res: Response) => {
  const { inputEmail } = req.body;
  const rawInput = String(inputEmail || '');

  // 1. Parameterized execution: SQLite binds parameter safely
  const startTime = process.hrtime.bigint();
  const parameterizedResult = db.prepare('SELECT id, username, email FROM users WHERE email = ?').all(rawInput);
  const endTime = process.hrtime.bigint();
  const execTimeUs = Number(endTime - startTime) / 1000;

  // 2. Simulated vulnerable query string (for education only)
  const vulnerableQueryMock = `SELECT id, username, email FROM users WHERE email = '${rawInput.replace(/'/g, "''")}';`;

  res.json({
    rawInput,
    parameterizedQueryUsed: 'SELECT id, username, email FROM users WHERE email = ?',
    boundParameter: rawInput,
    matchCount: parameterizedResult.length,
    matches: parameterizedResult,
    executionTimeMicroseconds: execTimeUs.toFixed(2),
    securityExplanation:
      'Parameterized queries (prepared statements) treat all inputs purely as literal data values, never as executable SQL grammar. Even if the user enters malicious payloads such as "\' OR \'1\'=\'1", the database query engine never interprets the quotation marks or OR condition as SQL commands.',
  });
});

// Bcrypt Hashing & Cost Factor Analyzer
app.post('/api/security-lab/test-bcrypt', async (req: Request, res: Response) => {
  const { password, rounds = 12 } = req.body;
  const testRounds = Math.min(Math.max(Number(rounds) || 12, 8), 13);
  const samplePassword = String(password || 'CyberSec#2026!');

  const start = Date.now();
  const hash = await bcrypt.hash(samplePassword, testRounds);
  const durationMs = Date.now() - start;

  const parts = hash.split('$');
  // Hash format: $2a$12$22charsalt31charhash
  const algorithm = parts[1] || '2a';
  const cost = parts[2] || String(testRounds);
  const saltAndHash = parts[3] || '';
  const salt = saltAndHash.substring(0, 22);
  const checksum = saltAndHash.substring(22);

  res.json({
    password: samplePassword,
    rounds: testRounds,
    durationMs,
    fullHash: hash,
    breakdown: {
      algorithm: `$${algorithm}$`,
      costFactor: cost,
      salt: salt,
      checksum: checksum,
    },
    securityAnalysis: {
      workFactorCalculation: `2^${cost} = ${(2 ** Number(cost)).toLocaleString()} hashing iterations`,
      bruteForceResistance:
        testRounds >= 12
          ? 'High (recommended for production: ~200-400ms prevents high-speed GPU cracking)'
          : 'Medium (faster, but more vulnerable to offline GPU dictionaries)',
    },
  });
});

// Serve frontend in production or mount Vite in development
async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(process.cwd(), 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(process.cwd(), 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SecureAuth] Server operational at http://localhost:${PORT}`);
  });
}

startServer();
