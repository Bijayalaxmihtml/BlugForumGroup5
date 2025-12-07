-- Phase 2 Migration: Thread Ownership, Moderators, Private Threads, and Blocking

-- Add thread_members table for private thread access control
CREATE TABLE thread_members (
  thread_id INT NOT NULL,
  user_id INT NOT NULL,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (thread_id, user_id),
  FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Ensure threads have owner_id (should already exist from schema.sql)
-- If not present, run: ALTER TABLE threads ADD COLUMN owner_id INT REFERENCES users(id);

-- Add post blocking (should already exist from schema.sql)
-- If not present, run: ALTER TABLE posts ADD COLUMN is_blocked TINYINT(1) DEFAULT 0;

-- Create indexes for performance
CREATE INDEX idx_thread_moderators ON thread_moderators (user_id);
CREATE INDEX idx_thread_members ON thread_members (user_id);
CREATE INDEX idx_threads_owner ON threads (owner_id);
CREATE INDEX idx_threads_private ON threads (is_private);
CREATE INDEX idx_posts_blocked ON posts (is_blocked);
CREATE INDEX idx_threads_blocked ON threads (is_blocked);
