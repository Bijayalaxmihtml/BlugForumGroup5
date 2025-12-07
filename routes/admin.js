import express from 'express';
import { database } from '../db.js'; // your database pool
import { requireLogin } from '../middleware.js'; // if you want
const router = express.Router();

// Middleware to check admin
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "administrator")
    return res.status(403).json({ message: "Admin only" });
  next();
}

// Get all users
router.get('/users', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute("SELECT id, username, email, display_name, role, is_blocked FROM users");
    res.json(rows);
  } catch (err) { next(err); }
});

// Block/unblock a user
router.patch('/users/:userId/block', requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { blocked } = req.body;
    await database.execute("UPDATE users SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, userId]);
    res.json({ message: `User ${blocked ? "blocked" : "unblocked"}` });
  } catch (err) { next(err); }
});

// Get all threads
router.get('/threads', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute("SELECT * FROM threads");
    res.json(rows);
  } catch (err) { next(err); }
});

// Get all posts
router.get('/posts', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute("SELECT * FROM posts");
    res.json(rows);
  } catch (err) { next(err); }
});

export default router;
