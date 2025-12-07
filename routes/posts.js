import express from 'express';
import Joi from 'joi';
import { query } from '../db.js';
import acl from '../acl.js';
const router = express.Router();
const createPostSchema = Joi.object({ thread_id: Joi.number().integer().required(), content: Joi.string().min(1).max(5000).required() });
router.get('/thread/:threadId', acl, async (req, res, next) => {
  try {
    const posts = await query('SELECT * FROM posts WHERE thread_id = ? AND is_blocked = 0 ORDER BY created_at ASC', [req.params.threadId]);
    res.json({ posts });
  } catch (err) { next(err); }
});
router.post('/', acl, async (req, res, next) => {
  try {
    if (!req.session.user) return res.status(401).json({ error: 'Login required' });
    const payload = await createPostSchema.validateAsync(req.body);
    const r = await query('INSERT INTO posts (thread_id, content, created_by) VALUES (?, ?, ?)', [payload.thread_id, payload.content, req.session.user.id]);
    const rows = await query('SELECT * FROM posts WHERE id = ?', [r.insertId]);
    res.status(201).json({ post: rows[0] });
  } catch (err) { next(err); }
});
export default router;
