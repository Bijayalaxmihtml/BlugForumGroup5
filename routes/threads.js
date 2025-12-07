import express from 'express';
import { database } from '../db.js'; // adjust import if your db.js exports default pool
import { requireLogin, requireAdmin } from '../middleware.js';

const router = express.Router();

// Middleware to check if user is thread owner
async function requireOwner(req, res, next) {
const { threadId } = req.params;
const userId = req.session.user?.id;
if (!userId) return res.status(401).json({ message: "Not logged in" });

const [rows] = await database.execute(
"SELECT owner_id FROM threads WHERE id = ?",
[threadId]
);

if (!rows.length) return res.status(404).json({ message: "Thread not found" });

if (rows[0].owner_id !== userId && req.session.user.role !== "administrator") {
return res.status(403).json({ message: "Thread owner or admin only" });
}

next();
}

// Middleware to check if user is thread moderator
async function requireModerator(req, res, next) {
const { threadId } = req.params;
const userId = req.session.user?.id;
if (!userId) return res.status(401).json({ message: "Not logged in" });

const [rows] = await database.execute(
"SELECT * FROM thread_moderators WHERE thread_id = ? AND user_id = ?",
[threadId, userId]
);

if (!rows.length && req.session.user.role !== "administrator") {
return res.status(403).json({ message: "Moderator or admin only" });
}

next();
}

// ======================
// Thread Endpoints
// ======================

// List all threads
router.get("/", async (req, res, next) => {
try {
const [rows] = await database.execute("SELECT * FROM threads");
res.json(rows);
} catch (err) { next(err); }
});

// Get specific thread
router.get("/:threadId", async (req, res, next) => {
try {
const { threadId } = req.params;
const [rows] = await database.execute("SELECT * FROM threads WHERE id = ?", [threadId]);
if (!rows.length) return res.status(404).json({ message: "Thread not found" });
res.json(rows[0]);
} catch (err) { next(err); }
});

// Create a new thread
router.post("/:forumId", requireLogin, async (req, res, next) => {
try {
const { forumId } = req.params;
const { title, is_private } = req.body;
if (!title) return res.status(400).json({ message: "Title required" });

```
const [result] = await database.execute(
  "INSERT INTO threads (forum_id, title, created_by, is_private, owner_id) VALUES (?, ?, ?, ?, ?)",
  [forumId, title, req.session.user.id, is_private ? 1 : 0, req.session.user.id]
);

res.status(201).json({ message: "Thread created", threadId: result.insertId });
```

} catch (err) { next(err); }
});

// Update thread
router.put("/:threadId", requireLogin, requireOwner, async (req, res, next) => {
try {
const { threadId } = req.params;
const { title, is_private } = req.body;
await database.execute(
"UPDATE threads SET title = ?, is_private = ? WHERE id = ?",
[title, is_private ? 1 : 0, threadId]
);
res.json({ message: "Thread updated" });
} catch (err) { next(err); }
});

// Block/unblock thread (admin only)
router.patch("/:threadId/block", requireAdmin, async (req, res, next) => {
try {
const { threadId } = req.params;
const { blocked } = req.body;
await database.execute("UPDATE threads SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, threadId]);
res.json({ message: `Thread ${blocked ? "blocked" : "unblocked"}` });
} catch (err) { next(err); }
});

// Make thread public/private
router.patch("/:threadId/privacy", requireOwner, async (req, res, next) => {
try {
const { threadId } = req.params;
const { is_private } = req.body;
await database.execute("UPDATE threads SET is_private = ? WHERE id = ?", [is_private ? 1 : 0, threadId]);
res.json({ message: `Thread is now ${is_private ? "private" : "public"}` });
} catch (err) { next(err); }
});

// Add moderator
router.post("/:threadId/moderators", requireOwner, async (req, res, next) => {
try {
const { threadId } = req.params;
const { userId } = req.body;
await database.execute("INSERT INTO thread_moderators (thread_id, user_id) VALUES (?, ?)", [threadId, userId]);
res.json({ message: "Moderator added" });
} catch (err) { next(err); }
});

// Remove moderator
router.delete("/:threadId/moderators/:userId", requireOwner, async (req, res, next) => {
try {
const { threadId, userId } = req.params;
await database.execute("DELETE FROM thread_moderators WHERE thread_id = ? AND user_id = ?", [threadId, userId]);
res.json({ message: "Moderator removed" });
} catch (err) { next(err); }
});

// Invite user to private thread
router.post("/:threadId/users", requireModerator, async (req, res, next) => {
try {
const { threadId } = req.params;
const { userId } = req.body;
await database.execute("INSERT INTO thread_users (thread_id, user_id) VALUES (?, ?)", [threadId, userId]);
res.json({ message: "User invited to thread" });
} catch (err) { next(err); }
});

// Remove user from private thread
router.delete("/:threadId/users/:userId", requireModerator, async (req, res, next) => {
try {
const { threadId, userId } = req.params;
await database.execute("DELETE FROM thread_users WHERE thread_id = ? AND user_id = ?", [threadId, userId]);
res.json({ message: "User removed from thread" });
} catch (err) { next(err); }
});

// Transfer thread ownership
router.patch("/:threadId/owner", requireOwner, async (req, res, next) => {
try {
const { threadId } = req.params;
const { newOwnerId } = req.body;
await database.execute("UPDATE threads SET owner_id = ? WHERE id = ?", [newOwnerId, threadId]);
res.json({ message: "Thread ownership transferred" });
} catch (err) { next(err); }
});

export default router;
