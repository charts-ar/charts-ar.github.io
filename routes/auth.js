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

// Helper to send verification email via Resend
async function sendVerificationEmail(email, username, token) {
  const verifyLink = `${process.env.BASE_URL}/public/verify.html?token=${token}`;
  const { data, error } = await resend.emails.send({
    from: 'YourApp <no-reply@yourdomain.com>',
    to: [email],
    subject: 'Verify your email',
    html: `<p>Hi ${username},</p>
           <p>Please verify your email by clicking <a href="${verifyLink}">this link</a>.</p>`
  });
  if (error) {
    console.error('Resend email error:', error);
    throw new Error('Error sending verification email');
  }
  return data;
}

// Registration
router.post('/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  try {
    const client = await pool.connect();
    const existing = await client.query('SELECT id FROM users WHERE email=$1', [email]);
    if (existing.rows.length) {
      client.release();
      return res.status(400).json({ error: 'Email already registered' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users(email, username, password_hash) VALUES($1,$2,$3) RETURNING id, username',
      [email, username || null, password_hash]
    );
    const userId = result.rows[0].id;
    const uname = result.rows[0].username || email;
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24*60*60*1000); // 24h
    await client.query(
      'INSERT INTO verification_tokens(user_id, token, expires_at) VALUES($1,$2,$3)',
      [userId, token, expiresAt]
    );
    await sendVerificationEmail(email, uname, token);
    client.release();
    return res.json({ message: 'Registered – check your email to verify.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// Email verification
router.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Invalid token');
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
    return res.send('Email verified – you may now log in.');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Internal error');
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const client = await pool.connect();
    const u = await client.query(
      'SELECT id, username, password_hash, verified FROM users WHERE email=$1',
      [email]
    );
    if (u.rows.length === 0) {
      client.release();
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = u.rows[0];
    if (!user.verified) {
      client.release();
      return res.status(403).json({ error: 'Email not verified' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      client.release();
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id, username: user.username }, SESSION_SECRET, { expiresIn: '7d' });
    client.release();
    res.cookie('session', token, { httpOnly: true, secure: true, maxAge: 7*24*60*60*1000 });
    return res.json({ message: 'Logged in', username: user.username });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
