import { verifyToken } from "../auth.js";

// Middleware to check if user is logged in
export function requireLogin(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).json({ message: "Not logged in" });
}

// Middleware to check if user is admin
export function requireAdmin(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ message: "Not logged in" });
  if (req.session.user.role !== "administrator") return res.status(403).json({ message: "Admin only" });
  next();
}

// Generic role-based middleware
export function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    const userRole = req.session?.user?.role;
    if (!userRole) return res.status(401).json({ message: "Not logged in" });
    if (!allowedRoles.includes(userRole) && userRole !== "administrator") {
      return res.status(403).json({ message: "Forbidden: insufficient permissions" });
    }
    next();
  };
}

// Middleware to check if user is thread owner
export function requireThreadOwner(pool) {
  return async (req, res, next) => {
    if (!req.session?.user) return res.status(401).json({ message: "Not logged in" });
    
    const threadId = req.params.threadId || req.params.id;
    if (!threadId) return res.status(400).json({ message: "Missing threadId" });
    
    try {
      const [threads] = await pool.query("SELECT owner_id FROM threads WHERE id = ?", [threadId]);
      if (!threads.length) return res.status(404).json({ message: "Thread not found" });
      
      const thread = threads[0];
      if (thread.owner_id !== req.session.user.id && req.session.user.role !== "administrator") {
        return res.status(403).json({ message: "Only thread owner or admin can perform this action" });
      }
      req.thread = thread;
      next();
    } catch (err) {
      res.status(500).json({ message: "Error checking thread ownership", error: err.message });
    }
  };
}

// Middleware to check if user is thread moderator or owner
export function requireThreadModerator(pool) {
  return async (req, res, next) => {
    if (!req.session?.user) return res.status(401).json({ message: "Not logged in" });
    
    const threadId = req.params.threadId || req.params.id;
    if (!threadId) return res.status(400).json({ message: "Missing threadId" });
    
    try {
      const [threads] = await pool.query("SELECT owner_id FROM threads WHERE id = ?", [threadId]);
      if (!threads.length) return res.status(404).json({ message: "Thread not found" });
      
      const thread = threads[0];
      const isOwner = thread.owner_id === req.session.user.id;
      const isAdmin = req.session.user.role === "administrator";
      
      // Check if moderator
      const [mods] = await pool.query(
        "SELECT 1 FROM thread_moderators WHERE thread_id = ? AND user_id = ?",
        [threadId, req.session.user.id]
      );
      const isModerator = mods.length > 0;
      
      if (!isOwner && !isModerator && !isAdmin) {
        return res.status(403).json({ message: "Only moderator, owner, or admin can perform this action" });
      }
      
      req.thread = thread;
      next();
    } catch (err) {
      res.status(500).json({ message: "Error checking moderator status", error: err.message });
    }
  };
}

// Middleware to check access to thread (for viewing private threads)
export function requireThreadAccess(pool) {
  return async (req, res, next) => {
    const threadId = req.params.threadId || req.params.id;
    if (!threadId) return res.status(400).json({ message: "Missing threadId" });
    
    try {
      const [threads] = await pool.query(
        "SELECT id, is_public, owner_id FROM threads WHERE id = ?",
        [threadId]
      );
      if (!threads.length) return res.status(404).json({ message: "Thread not found" });
      
      const thread = threads[0];
      const userId = req.session?.user?.id;
      const isAdmin = req.session?.user?.role === "administrator";
      
      // If public, anyone can access
      if (!thread.is_private) {
        req.thread = thread;
        return next();
      }
      
      // If private, only owner, moderators, members, or admin
      if (!userId) return res.status(401).json({ message: "Not logged in" });
      if (isAdmin) return next();
      
      const isOwner = thread.owner_id === userId;
      if (isOwner) return next();
      
      // Check if moderator
      const [mods] = await pool.query(
        "SELECT 1 FROM thread_moderators WHERE thread_id = ? AND user_id = ?",
        [threadId, userId]
      );
      if (mods.length > 0) return next();
      
      // Check if member
      const [members] = await pool.query(
        "SELECT 1 FROM thread_members WHERE thread_id = ? AND user_id = ?",
        [threadId, userId]
      );
      if (members.length > 0) return next();
      
      return res.status(403).json({ message: "You don't have access to this private thread" });
    } catch (err) {
      res.status(500).json({ message: "Error checking thread access", error: err.message });
    }
  };
}

// Optional middleware if you want JWT later (currently not used)
export async function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).json({ message: "Authentication required" });
}
