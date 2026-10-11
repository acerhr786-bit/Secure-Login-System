import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';
import { db } from './db.js';

// Configuration
export const BCRYPT_SALT_ROUNDS = 12;
export const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
export const SESSION_DURATION_HOURS = 24;
export const RESET_TOKEN_EXPIRY_MINUTES = 15;
export const MAX_LOGIN_ATTEMPTS = 5;
export const LOCKOUT_DURATION_MINUTES = 15;

// Password Complexity Validator
export interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  score: number; // 0 to 4
}

export function validatePasswordStrength(password: string): PasswordValidationResult {
  const errors: string[] = [];
  let score = 0;

  if (password.length >= 8) score++;
  else errors.push('Password must be at least 8 characters long');

  if (/[a-z]/.test(password)) score++;
  else errors.push('Password must contain at least one lowercase letter (a-z)');

  if (/[A-Z]/.test(password)) score++;
  else errors.push('Password must contain at least one uppercase letter (A-Z)');

  if (/[0-9]/.test(password)) score++;
  else errors.push('Password must contain at least one number (0-9)');

  if (/[^a-zA-Z0-9]/.test(password)) score++;
  else errors.push('Password must contain at least one special character (!@#$%^&*...)');

  // Overall validity requires length >= 8 and at least 3 of the 4 character criteria
  const isValid = password.length >= 8 && errors.length === 0;

  return { isValid, errors, score: Math.min(score, 5) };
}

export function validateEmail(email: string): boolean {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return emailRegex.test(email) && email.length <= 254;
}

export function validateUsername(username: string): boolean {
  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  return usernameRegex.test(username);
}

// Bcrypt Hashing
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Dummy hash for constant-time comparisons when user does not exist (prevents timing attacks)
const DUMMY_HASH = '$2a$12$e80M6l1O3V0sYQ9PzT6.A.j9eYd5F7pWc4jB9j1k2l3m4n5o6p7q8';
export async function fakePasswordVerification(password: string): Promise<boolean> {
  await bcrypt.compare(password, DUMMY_HASH);
  return false;
}

// Cryptographic Tokens
export function generateSecureToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// CSRF Protection (Double Submit Token with HMAC signature)
export function generateCsrfToken(): { token: string; cookieValue: string } {
  const raw = crypto.randomBytes(24).toString('hex');
  const signature = crypto.createHmac('sha256', CSRF_SECRET).update(raw).digest('hex');
  const fullToken = `${raw}.${signature}`;
  return {
    token: fullToken,
    cookieValue: fullToken,
  };
}

export function verifyCsrfToken(submittedToken: string | undefined, cookieToken: string | undefined): boolean {
  if (!submittedToken || !cookieToken) return false;
  if (submittedToken !== cookieToken) return false;

  const parts = submittedToken.split('.');
  if (parts.length !== 2) return false;
  const [raw, signature] = parts;

  const expectedSignature = crypto.createHmac('sha256', CSRF_SECRET).update(raw).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
  } catch {
    return false;
  }
}

// Rate Limiting (Sliding Window in memory)
interface RateLimitRecord {
  attempts: number;
  firstAttemptAt: number;
  blockedUntil?: number;
}

const rateLimitMap = new Map<string, RateLimitRecord>();

export function checkRateLimit(key: string, maxAttempts = MAX_LOGIN_ATTEMPTS, windowMs = 15 * 60 * 1000): { isBlocked: boolean; remainingAttempts: number; retryAfterSec?: number } {
  const now = Date.now();
  const record = rateLimitMap.get(key);

  if (!record) {
    return { isBlocked: false, remainingAttempts: maxAttempts };
  }

  // If blocked
  if (record.blockedUntil && record.blockedUntil > now) {
    const retryAfterSec = Math.ceil((record.blockedUntil - now) / 1000);
    return { isBlocked: true, remainingAttempts: 0, retryAfterSec };
  }

  // If window has passed, reset
  if (now - record.firstAttemptAt > windowMs) {
    rateLimitMap.delete(key);
    return { isBlocked: false, remainingAttempts: maxAttempts };
  }

  const remaining = Math.max(0, maxAttempts - record.attempts);
  return { isBlocked: false, remainingAttempts: remaining };
}

export function recordFailedAttempt(key: string, maxAttempts = MAX_LOGIN_ATTEMPTS, lockoutMs = LOCKOUT_DURATION_MINUTES * 60 * 1000): void {
  const now = Date.now();
  const record = rateLimitMap.get(key);

  if (!record) {
    rateLimitMap.set(key, { attempts: 1, firstAttemptAt: now });
    return;
  }

  record.attempts += 1;
  if (record.attempts >= maxAttempts) {
    record.blockedUntil = now + lockoutMs;
  }
  rateLimitMap.set(key, record);
}

export function resetRateLimit(key: string): void {
  rateLimitMap.delete(key);
}

// RFC 6238 TOTP (Two-Factor Authentication)
// Base32 Alphabet
const RFC4648_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(length = 20): string {
  const bytes = crypto.randomBytes(length);
  let base32 = '';
  for (let i = 0; i < bytes.length; i++) {
    base32 += RFC4648_ALPHABET[bytes[i] % 32];
  }
  return base32;
}

function base32ToBuffer(base32: string): Buffer {
  const clean = base32.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = RFC4648_ALPHABET.indexOf(clean[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function computeTotp(secret: string, counter: number): string {
  const key = base32ToBuffer(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

export function verifyTotpToken(token: string, secret: string, windowSteps = 1): boolean {
  if (!token || token.length !== 6 || !/^\d{6}$/.test(token)) return false;
  const currentStep = Math.floor(Date.now() / 1000 / 30);

  for (let error = -windowSteps; error <= windowSteps; error++) {
    const expected = computeTotp(secret, currentStep + error);
    if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

export async function generateQrCodeUrl(secret: string, email: string, issuer = 'SecureAuth'): Promise<string> {
  const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return QRCode.toDataURL(uri, {
    width: 240,
    margin: 2,
    color: {
      dark: '#0f172a',
      light: '#ffffff',
    },
  });
}

// Security Audit Logger
export function logSecurityEvent(eventType: string, details: string, userId?: number | null, ipAddress?: string): void {
  try {
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      INSERT INTO security_logs (user_id, event_type, ip_address, details, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(userId ?? null, eventType, ipAddress ?? '127.0.0.1', details, now);
  } catch (err) {
    console.error('Failed to log security event:', err);
  }
}
