import { Router } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Resend } from 'resend';

const router = Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);
const SESSION_SECRET = process.env.SESSION_SECRET;
const BASE_URL = process.env.BASE_URL || 'https://your‑domain.com'; // set this in env

// Helper to send verification email
async function sendVerificationEmail(email, username, token) {
  const link = `${BASE_URL}/public/verify.html?token=${token}`;
  const { data, error } = await resend.emails.send({
    from: `ChatApp <no‑reply@yourdomain.com>`,
    to: [email],
    subject: 'Please verify your email',
    html: `<p>Hello ${username},</p>
           <p>Please verify your email by clicking the link below:</p>
           <p><a href="${link}">Verify your email</a></p>`
  });
  if (error) {
    console.error('Error sending email:', error);
    throw new Error('Email sending failed');
  }
  return data;
}

// Register
router.post('/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !password || !username) {
    return res.status(400).json({ error: 'Email, username and password required' });
  }
  try {
    const client = await pool.connect();
    const existing = await client.query('SELECT id FROM users WHERE email=$1', [email]);
    if (existing.rows.length) {
      client.release();
      return res.status(400).json({ error: 'Email already in use' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users(email, username, password_hash) VALUES($1, $2, $3) RETURNING id, username',
      [email, username, password_hash]
    );
    const userId = result.rows[0].id;
    const uname = result.rows[0].username;
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24*60*60*1000);
    await client.query(
      'INSERT INTO verification_tokens(user_id, token, expires_at) VALUES($1, $2, $3)',
      [userId, token, expiresAt]
    );
    await sendVerificationEmail(email, uname, token);
    client.release();
    return res.json({ message: 'Registration successful. Check your email to verify.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Verify email
router.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Invalid or missing token');
  try {
    const client = await pool.connect();
    const vt = await client.query(
      'SELECT user_id, expires_at FROM verification_tokens WHERE token=$1',
      [token]
    );
    if (vt.rows.length === 0) {
      client.release();
      return res.status(400).send('Invalid or expired token');
    }
    const { user_id, expires_at } = vt.rows[0];
    if (new Date(expires_at) < new Date()) {
      client.release();
      return res.status(400).send('Token expired');
    }
    await client.query('UPDATE users SET verified=true WHERE id=$1', [user_id]);
    await client.query('DELETE FROM verification_tokens WHERE user_id=$1', [user_id]);
    client.release();
    return res.send('Email verified! You may now log in.');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error');
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const client = await pool.connect();
    const userQ = await client.query(
      'SELECT id, username, password_hash, verified, role FROM users WHERE email=$1',
      [email]
    );
    if (userQ.rows.length === 0) {
      client.release();
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = userQ.rows[0];
    if (!user.verified) {
      client.release();
      return res.status(403).json({ error: 'Email not verified' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      client.release();
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      SESSION_SECRET,
      { expiresIn: '7d' }
    );
    client.release();
    res.cookie('session', token, { httpOnly: true, secure: true, maxAge: 7*24*60*60*1000 });
    return res.json({ message: 'Login successful', username: user.username, role: user.role });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
