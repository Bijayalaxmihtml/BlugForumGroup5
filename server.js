import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import session from "express-session";
import mysql from "mysql2/promise";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import {
  requireLogin,
  requireAdmin,
  requireThreadOwner,
  requireThreadModerator,
  requireThreadAccess
} from "./middleware/authMiddleware.js";



const password = "Admin123!";
const hash = await bcrypt.hash(password, 10);
console.log(hash);


dotenv.config();

let database;

try {
  database = mysql.createPool({
    host: process.env.DB_HOST || "5.189.183.23",
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 4567,
    user: process.env.DB_USER || "dsak24-11",
    password: process.env.DB_PASSWORD || "GSUFQ20228",
    database: process.env.DB_NAME || "dsak24-11",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
  const conn = await database.getConnection();
  conn.release();
  console.log("Database connected (pool)!");
} catch (err) {
  console.error("Database connection failed:", err);
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "super-secret",
  resave: false,
  saveUninitialized: true
}));
app.use(rateLimit({ windowMs: 60000, max: 200 }));

app.use((req, res, next) => {
  req.url = req.url.replace(/%0A/g, '').replace(/%0D/g, '').trim();
  next();
});

// Home
app.get("/", (req, res) => res.send("<h1>Blug Backend Running</h1>"));

// ===== AUTHENTICATION =====
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { username, email, password, display_name, is_admin } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "Missing username, email, or password" });
    const hash = await bcrypt.hash(password, 10);
    const [result] = await database.execute(
      "INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)",
      [username, email, hash, display_name || null]
    );
    const userId = result.insertId;
    
    // Assign role (default: member, or admin if is_admin=true)
    const roleId = is_admin ? 1 : 3; // 1=administrator, 3=member
    try {
      await database.execute(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        [userId, roleId]
      );
    } catch (e) {
      console.log("Warning: Could not assign role");
    }
    
    res.status(201).json({ message: "User registered", userId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: "Username or email already taken" });
    next(err);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [rows] = await database.execute("SELECT * FROM users WHERE username = ?", [username]);
    if (!rows.length) return res.status(400).json({ message: "Invalid username" });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ message: "Incorrect password" });
    
    // Get user role (with fallback to member if no role assigned)
    const [roleRows] = await database.execute(
      "SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ? LIMIT 1",
      [user.id]
    );
    let userRole = roleRows.length > 0 ? roleRows[0].name : "member";
    
    // Auto-assign member role if none exists
    if (!roleRows.length) {
      try {
        await database.execute(
          "INSERT INTO user_roles (user_id, role_id) VALUES (?, 3)",
          [user.id]
        );
      } catch (e) {
        // Role already assigned or duplicate, ignore
      }
    }
    
    req.session.user = { id: user.id, username: user.username, role: userRole };
    res.json({ message: "Logged in", user: req.session.user });
  } catch (err) { next(err); }
});

app.get("/api/auth/session", (req, res) => res.json({ user: req.session.user || null }));

app.delete("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out" }));
});

// Update user profile (admin or self)
app.patch("/api/users/:userId", requireLogin, async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { username, email, display_name } = req.body;

    // Only admin or the user themselves can update
    if (req.session.user.role !== "administrator" && req.session.user.id != userId) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const updates = [];
    const values = [];

    if (username) { updates.push("username = ?"); values.push(username); }
    if (email) { updates.push("email = ?"); values.push(email); }
    if (display_name) { updates.push("display_name = ?"); values.push(display_name); }

    if (!updates.length) return res.status(400).json({ message: "No fields to update" });

    values.push(userId);
    await database.execute(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, values);

    res.json({ message: "User updated" });
  } catch (err) { next(err); }
});
// Delete user (admin or self)
app.delete("/api/users/:userId", requireLogin, async (req, res, next) => {
  try {
    const { userId } = req.params;

    if (req.session.user.role !== "administrator" && req.session.user.id != userId) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await database.execute("DELETE FROM users WHERE id = ?", [userId]);
    res.json({ message: "User deleted" });
  } catch (err) { next(err); }
});

// ===== FORUMS =====
app.get("/api/forums", async (req, res, next) => {
  try {
    const [rows] = await database.execute(
      "SELECT id, title, description, created_by, created_at, is_blocked, is_public FROM forums WHERE is_blocked = 0 AND is_public = 1"
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get("/api/forums/:forumId", async (req, res, next) => {
  try {
    const [rows] = await database.execute("SELECT * FROM forums WHERE is_blocked = 0");
    res.json(rows);
  } catch (err) { next(err); }
});

app.post("/api/forums", requireLogin, async (req, res, next) => {
  try {
    const { title, description } = req.body;
    if (!title) return res.status(400).json({ message: "Title required" });
    await database.execute(
      "INSERT INTO forums (title, description, created_by, is_public) VALUES (?, ?, ?, 1)",
      [title, description || null, req.session.user.id]
    );
    res.status(201).json({ message: "Forum created" });
  } catch (err) { next(err); }
});

app.delete("/api/forums/:forumId", requireAdmin, async (req, res, next) => {
  try {
    const { forumId } = req.params;
    await database.execute("DELETE FROM forums WHERE id = ?", [forumId]);
    res.json({ message: "Forum deleted" });
  } catch (err) { next(err); }
});

app.patch("/api/forums/:forumId/block", requireAdmin, async (req, res, next) => {
  try {
    const { forumId } = req.params;
    const { blocked } = req.body;
    await database.execute("UPDATE forums SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, forumId]);
    res.json({ message: blocked ? "Forum blocked" : "Forum unblocked" });
  } catch (err) { next(err); }
});

// ===== THREADS =====
app.get("/api/forums/:forumId/threads", async (req, res, next) => {
  try {
    const { forumId } = req.params;
    const userId = req.session?.user?.id;
    
    // If logged in, can see public + private they're member of
    if (userId) {
      const [rows] = await database.execute(
        `SELECT t.* FROM threads t
         WHERE t.forum_id = ? AND t.is_blocked = 0 AND (
           t.is_public = 0 OR
           t.owner_id = ? OR
           EXISTS (SELECT 1 FROM thread_moderators tm WHERE tm.thread_id = t.id AND tm.user_id = ?) OR
           EXISTS (SELECT 1 FROM thread_members tmem WHERE tmem.thread_id = t.id AND tmem.user_id = ?)
         )`,
        [forumId, userId, userId, userId]
      );
      return res.json(rows);
    }
    
    // Not logged in: only public threads
    const [rows] = await database.execute(
      "SELECT * FROM threads WHERE forum_id = ? AND is_public = 0 AND is_blocked = 0",
      [forumId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.post("/api/forums/:forumId/threads", requireLogin, async (req, res, next) => {
  try {
    const { forumId } = req.params;
    const { title, body, is_private } = req.body;

    if (!title) return res.status(400).json({ message: "Title required" });
    if (!body) return res.status(400).json({ message: "Body required" }); // ensure body is sent

    // Insert thread
    const [result] = await database.execute(
      `INSERT INTO threads (forum_id, title, owner_id, body, is_public) VALUES (?, ?, ?, ?, ?)`,
      [forumId, title, req.session.user.id, body, is_private ? 0 : 1] // 0 = private, 1 = public
    );

    res.status(201).json({ message: "Thread created", threadId: result.insertId });
  } catch (err) {
    console.error("POST /api/forums/:forumId/threads error:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});


app.get("/api/threads/:threadId", requireThreadAccess(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const [rows] = await database.execute("SELECT * FROM threads WHERE id = ?", [threadId]);
    if (!rows.length) return res.status(404).json({ message: "Thread not found" });
    
    const [moderators] = await database.execute(
      "SELECT u.id, u.username FROM thread_moderators tm JOIN users u ON tm.user_id = u.id WHERE tm.thread_id = ?",
      [threadId]
    );
    
    const thread = rows[0];
    thread.moderators = moderators;
    res.json(thread);
  } catch (err) { next(err); }
});


// CREATE NEW THREAD
app.post("/api/threads", requireLogin, async (req, res, next) => {
  try {
    const { title, content, is_public } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: "Title and content required" });
    }

    // create thread
    const [threadResult] = await database.execute(
      "INSERT INTO threads (forum_id, title, owner_id, created_by, is_public) VALUES (?, ?, ?, ?, ?)",
      [
        2, // or correct forum id
        title,
        req.session.user.id,
        req.session.user.id,
        is_public ? 1 : 0
      ]
    );

    const threadId = threadResult.insertId;

    // create first post
    await database.execute(
      "INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)",
      [threadId, req.session.user.id, content]
    );

    res.status(201).json({
      message: "Thread created",
      threadId: threadId
    });

  } catch (err) {
    next(err);
  }
});


app.patch("/api/threads/:threadId", requireThreadOwner(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { title, is_private } = req.body;
    
    if (title) {
      await database.execute("UPDATE threads SET title = ? WHERE id = ?", [title, threadId]);
    }
    if (typeof is_private !== 'undefined') {
      await database.execute("UPDATE threads SET is_private = ? WHERE id = ?", [is_private ? 1 : 0, threadId]);
    }
    
    res.json({ message: "Thread updated" });
  } catch (err) { next(err); }
});

app.delete("/api/threads/:threadId", requireThreadOwner(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    await database.execute("DELETE FROM threads WHERE id = ?", [threadId]);
    res.json({ message: "Thread deleted" });
  } catch (err) { next(err); }
});

app.patch("/api/threads/:threadId/block", requireThreadModerator(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { blocked } = req.body;
    await database.execute("UPDATE threads SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, threadId]);
    res.json({ message: blocked ? "Thread blocked" : "Thread unblocked" });
  } catch (err) { next(err); }
});

// ===== THREAD OWNERSHIP & MODERATORS =====
app.post("/api/threads/:threadId/owner", requireThreadOwner(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { newOwnerId } = req.body;
    if (!newOwnerId) return res.status(400).json({ message: "newOwnerId required" });
    
    // Verify new owner exists
    const [users] = await database.execute("SELECT id FROM users WHERE id = ?", [newOwnerId]);
    if (!users.length) return res.status(404).json({ message: "User not found" });
    
    await database.execute("UPDATE threads SET owner_id = ? WHERE id = ?", [newOwnerId, threadId]);
    res.json({ message: "Ownership transferred" });
  } catch (err) { next(err); }
});

app.post("/api/threads/:threadId/moderators", requireThreadOwner(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: "userId required" });
    
    // Verify user exists
    const [users] = await database.execute("SELECT id FROM users WHERE id = ?", [userId]);
    if (!users.length) return res.status(404).json({ message: "User not found" });
    
    // Add moderator
    await database.execute(
      "INSERT INTO thread_moderators (thread_id, user_id) VALUES (?, ?)",
      [threadId, userId]
    );
    res.status(201).json({ message: "Moderator appointed" });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: "User is already a moderator" });
    next(err);
  }
});

app.delete("/api/threads/:threadId/moderators/:userId", requireThreadOwner(database), async (req, res, next) => {
  try {
    const { threadId, userId } = req.params;
    await database.execute(
      "DELETE FROM thread_moderators WHERE thread_id = ? AND user_id = ?",
      [threadId, userId]
    );
    res.json({ message: "Moderator removed" });
  } catch (err) { next(err); }
});

// ===== PRIVATE THREADS =====
app.post("/api/threads/:threadId/members", requireThreadModerator(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: "userId required" });
    
    // Verify user exists
    const [users] = await database.execute("SELECT id FROM users WHERE id = ?", [userId]);
    if (!users.length) return res.status(404).json({ message: "User not found" });
    
    // Add member
    await database.execute(
      "INSERT INTO thread_members (thread_id, user_id) VALUES (?, ?)",
      [threadId, userId]
    );
    res.status(201).json({ message: "User invited to thread" });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: "User already has access" });
    next(err);
  }
});

app.delete("/api/threads/:threadId/members/:userId", requireThreadModerator(database), async (req, res, next) => {
  try {
    const { threadId, userId } = req.params;
    await database.execute(
      "DELETE FROM thread_members WHERE thread_id = ? AND user_id = ?",
      [threadId, userId]
    );
    res.json({ message: "User removed from thread" });
  } catch (err) { next(err); }
});

app.get("/api/threads/:threadId/members", requireThreadAccess(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    
    // Get moderators
    const [moderators] = await database.execute(
      "SELECT u.id, u.username, 'moderator' as role FROM thread_moderators tm JOIN users u ON tm.user_id = u.id WHERE tm.thread_id = ?",
      [threadId]
    );
    
    // Get regular members
    const [members] = await database.execute(
      "SELECT u.id, u.username, 'member' as role FROM thread_members tm JOIN users u ON tm.user_id = u.id WHERE tm.thread_id = ?",
      [threadId]
    );
    
    // Get owner
    const [owner] = await database.execute(
      "SELECT u.id, u.username FROM threads t JOIN users u ON t.owner_id = u.id WHERE t.id = ?",
      [threadId]
    );
    
    res.json({
      owner: owner.length > 0 ? owner[0] : null,
      moderators,
      members
    });
  } catch (err) { next(err); }
});

// ===== POSTS =====

// Get all posts in a thread (unblocked only)
app.get("/api/threads/:threadId/posts", requireThreadAccess(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const [rows] = await database.execute(
      "SELECT p.*, u.username FROM posts p JOIN users u ON p.created_by = u.id WHERE p.thread_id = ? AND p.is_blocked = 0",
      [threadId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// Create a new post in a thread
app.post("/api/threads/:threadId/posts", requireThreadAccess(database), async (req, res, next) => {
  try {
    const { threadId } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ message: "Content required" });

    await database.execute(
      "INSERT INTO posts (thread_id, created_by, content) VALUES (?, ?, ?)",
      [threadId, req.session.user.id, content]
    );
    res.status(201).json({ message: "Post created" });
  } catch (err) { next(err); }
});

// Get a single post (unblocked only)
app.get("/api/posts/:postId", async (req, res, next) => {
  try {
    const { postId } = req.params;
    const [rows] = await database.execute(
      "SELECT p.*, u.username FROM posts p JOIN users u ON p.created_by = u.id WHERE p.id = ? AND p.is_blocked = 0",
      [postId]
    );
    if (!rows.length) return res.status(404).json({ message: "Post not found" });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// Edit a post (owner/admin only)
app.patch("/api/posts/:postId", requireLogin, async (req, res, next) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ message: "Content required" });

    const [posts] = await database.execute(
      "SELECT created_by FROM posts WHERE id = ?",
      [postId]
    );
    if (!posts.length) return res.status(404).json({ message: "Post not found" });

    const postOwnerId = posts[0].created_by;
    const sessionUserId = req.session.user.id;
    const sessionUserRole = req.session.user.role;

    if (postOwnerId !== sessionUserId && sessionUserRole !== "administrator") {
      return res.status(403).json({ message: "Can only edit your own posts" });
    }

    await database.execute(
      "UPDATE posts SET content = ?, updated_at = NOW() WHERE id = ?",
      [content, postId]
    );
    res.json({ message: "Post updated successfully" });
  } catch (err) { next(err); }
});

// Delete a post (author/moderator/owner/admin)
app.delete("/api/posts/:postId", requireLogin, async (req, res, next) => {
  try {
    const { postId } = req.params;

    const [posts] = await database.execute(
      "SELECT created_by, thread_id FROM posts WHERE id = ?",
      [postId]
    );
    if (!posts.length) return res.status(404).json({ message: "Post not found" });

    const post = posts[0];
    const isAuthor = post.created_by === req.session.user.id;
    const isAdmin = req.session.user.role === "administrator";

    const [mods] = await database.execute(
      "SELECT 1 FROM thread_moderators tm WHERE tm.thread_id = ? AND tm.user_id = ?",
      [post.thread_id, req.session.user.id]
    );
    const [thread] = await database.execute(
      "SELECT owner_id FROM threads WHERE id = ?",
      [post.thread_id]
    );
    const isOwner = thread.length > 0 && thread[0].owner_id === req.session.user.id;
    const isModerator = mods.length > 0;

    if (!isAuthor && !isModerator && !isOwner && !isAdmin) {
      return res.status(403).json({ message: "Cannot delete this post" });
    }

    await database.execute("DELETE FROM posts WHERE id = ?", [postId]);
    res.json({ message: "Post deleted" });
  } catch (err) { next(err); }
});

// Block/unblock a post (moderator/owner/admin)
app.patch("/api/posts/:postId/block", requireLogin, async (req, res, next) => {
  try {
    const { postId } = req.params;
    const { blocked } = req.body;

    const [posts] = await database.execute(
      "SELECT created_by, thread_id FROM posts WHERE id = ?",
      [postId]
    );
    if (!posts.length) return res.status(404).json({ message: "Post not found" });

    const post = posts[0];

    const [mods] = await database.execute(
      "SELECT 1 FROM thread_moderators tm WHERE tm.thread_id = ? AND tm.user_id = ?",
      [post.thread_id, req.session.user.id]
    );
    const [thread] = await database.execute(
      "SELECT owner_id FROM threads WHERE id = ?",
      [post.thread_id]
    );
    const isOwner = thread.length > 0 && thread[0].owner_id === req.session.user.id;
    const isModerator = mods.length > 0;
    const isAdmin = req.session.user.role === "administrator";

    if (!isModerator && !isOwner && !isAdmin) {
      return res.status(403).json({ message: "Only moderator, owner, or admin can block posts" });
    }

    await database.execute("UPDATE posts SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, postId]);
    res.json({ message: blocked ? "Post blocked" : "Post unblocked" });
  } catch (err) { next(err); }
});


// ===== ADMIN =====
app.get("/api/administrator/users", requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute(
      "SELECT u.id, u.username, u.email, u.display_name, u.is_blocked, GROUP_CONCAT(r.name) as roles FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id LEFT JOIN roles r ON ur.role_id = r.id GROUP BY u.id"
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.patch("/api/administrator/users/:userId/block", requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { blocked } = req.body;
    await database.execute("UPDATE users SET is_blocked = ? WHERE id = ?", [blocked ? 1 : 0, userId]);
    res.json({ message: blocked ? "User blocked" : "User unblocked" });
  } catch (err) { next(err); }
});

app.patch("/api/administrator/users/:userId/role", requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { roleId } = req.body;
    if (!roleId) return res.status(400).json({ message: "roleId required" });
    
    // Verify role exists
    const [roles] = await database.execute("SELECT id FROM roles WHERE id = ?", [roleId]);
    if (!roles.length) return res.status(404).json({ message: "Role not found" });
    
    // Remove existing roles
    await database.execute("DELETE FROM user_roles WHERE user_id = ?", [userId]);
    
    // Add new role
    await database.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleId]);
    res.json({ message: "Role updated" });
  } catch (err) { next(err); }
});

app.get("/api/admin/threads", requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute(
      "SELECT t.*, u.username as owner_name FROM threads t JOIN users u ON t.owner_id = u.id"
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.get("/api/admin/posts", requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await database.execute(
      "SELECT p.*, u.username, t.title as thread_title FROM posts p JOIN users u ON p.user_id = u.id JOIN threads t ON p.thread_id = t.id"
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.get("/api/admin/blocked", requireAdmin, async (req, res, next) => {
  try {
    const [blockedUsers] = await database.execute(
      "SELECT id, username, 'user' as type FROM users WHERE is_blocked = 1"
    );
    const [blockedForums] = await database.execute(
      "SELECT id, title, 'forum' as type FROM forums WHERE is_blocked = 1"
    );
    const [blockedThreads] = await database.execute(
      "SELECT id, title, 'thread' as type FROM threads WHERE is_blocked = 1"
    );
    const [blockedPosts] = await database.execute(
      "SELECT id, 'post' as type FROM posts WHERE is_blocked = 1"
    );
    
    res.json({
      users: blockedUsers,
      forums: blockedForums,
      threads: blockedThreads,
      posts: blockedPosts
    });
  } catch (err) { next(err); }
});

// ===== SETUP ENDPOINT =====
// Make first user admin (for setup purposes)
app.post("/api/setup/make-admin", async (req, res, next) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ message: "Username required" });
    
    const [users] = await database.execute("SELECT id FROM users WHERE username = ?", [username]);
    if (!users.length) return res.status(404).json({ message: "User not found" });
    
    const userId = users[0].id;
    
    // Remove existing roles
    await database.execute("DELETE FROM user_roles WHERE user_id = ?", [userId]);
    
    // Add admin role
    await database.execute(
      "INSERT INTO user_roles (user_id, role_id) VALUES (?, 1)",
      [userId]
    );
    
    res.json({ message: `User ${username} is now admin` });
  } catch (err) { next(err); }
});

// ===== ERROR HANDLING =====
app.use((req, res) => res.status(404).json({ message: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Server error", error: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
