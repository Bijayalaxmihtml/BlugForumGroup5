import express from 'express';
import Joi from 'joi';
import { query } from '../db.js';
import acl from '../acl.js';
const router = express.Router();
router.get('/', acl, async (req, res, next) => {
  try {
    const forums = await query('SELECT id, title, description, created_at, is_public FROM forums WHERE is_blocked = 0 AND is_public = 1 ORDER BY created_at DESC');
    res.json({ forums });
  } catch (err) { next(err); }
});
const createSchema = Joi.object({ title: Joi.string().min(3).max(200).required(), description: Joi.string().max(2000).optional(), is_public: Joi.boolean().optional() });
router.post('/', acl, async (req, res, next) => {
  try {
    if (!req.session.user) return res.status(401).json({ error: 'Login required' });
    const payload = await createSchema.validateAsync(req.body);
    const r = await query('INSERT INTO forums (title, description, created_by, is_public) VALUES (?, ?, ?, ?)', [payload.title, payload.description || null, req.session.user.id, payload.is_public ? 1 : 0]);
    const rows = await query('SELECT * FROM forums WHERE id = ?', [r.insertId]);
    res.status(201).json({ forum: rows[0] });
  } catch (err) { next(err); }
});
export default router;
