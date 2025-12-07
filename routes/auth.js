import express from 'express';
import Joi from 'joi';
import { query } from '../db.js';
import { hashPassword, checkPassword, signToken } from '../auth.js';
const router = express.Router();
const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  display_name: Joi.string().max(100).optional()
});
router.post('/register', async (req, res, next) => {
  try {
    const payload = await registerSchema.validateAsync(req.body);
    const pwHash = await hashPassword(payload.password);
    const result = await query('INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)', [payload.username, payload.email, pwHash, payload.display_name || null]);
    const userId = result.insertId;
    await query('INSERT INTO user_roles (user_id, role_id) VALUES (?, (SELECT id FROM roles WHERE name=?))', [userId, 'member']);
    const token = signToken({ id: userId, username: payload.username });
    // create session
    req.session.user = { id: userId, username: payload.username, role: 'member' };
    res.status(201).json({ user: { id: userId, username: payload.username, email: payload.email }, token });
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Username or email already exists' });
    next(err);
  }
});
const loginSchema = Joi.object({ username: Joi.string().required(), password: Joi.string().required() });
router.post('/login', async (req, res, next) => {
  try {
    const payload = await loginSchema.validateAsync(req.body);
    const rows = await query('SELECT id, username, password_hash FROM users WHERE username = ?', [payload.username]);
    if (!rows || rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const ok = await checkPassword(payload.password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ id: user.id, username: user.username });
    // create session
    const roleRows = await query('SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?', [user.id]);
    const role = roleRows.length ? roleRows[0].name : 'member';
    req.session.user = { id: user.id, username: user.username, role };
    res.json({ token });
  } catch (err) {
    next(err);
  }
});
router.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ ok: true });
  });
});
export default router;
