-- Seed file. Replace <BCRYPT_HASH> placeholders with hashes generated locally.
INSERT INTO users (username, email, password_hash, display_name, is_blocked)
VALUES ('admin', 'admin@blug.local', '<BCRYPT_HASH_ADMIN>', 'Administrator', 0);

INSERT INTO user_roles (user_id, role_id)
VALUES ((SELECT id FROM users WHERE username='admin'), (SELECT id FROM roles WHERE name='administrator'));

INSERT INTO users (username, email, password_hash, display_name)
VALUES ('alice', 'alice@example.com', '<BCRYPT_HASH_MEMBER>', 'Alice');

INSERT INTO user_roles (user_id, role_id)
VALUES ((SELECT id FROM users WHERE username='alice'), (SELECT id FROM roles WHERE name='member'));

INSERT INTO forums (title, description, created_by, is_public) VALUES ('General','All-purpose forum',(SELECT id FROM users WHERE username='alice'),1);
INSERT INTO threads (forum_id, title, created_by, is_private, owner_id) VALUES ((SELECT id FROM forums WHERE title='General'),'Welcome thread',(SELECT id FROM users WHERE username='alice'),0,(SELECT id FROM users WHERE username='alice'));
INSERT INTO posts (thread_id, content, created_by) VALUES ((SELECT id FROM threads WHERE title='Welcome thread'),'Hello Blug! This is a seeded post.', (SELECT id FROM users WHERE username='alice'));
