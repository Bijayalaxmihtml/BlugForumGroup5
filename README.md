# BlugForumGroup5
Group5 assignment files will be stored in this repository
This project is a ready-to-run backend for the Blug assignment using MySQL.

## Setup
1. Copy .env
2. Install dependencies:
   ```bash
   npm install
 2. Create a `.env` (DB credentials + `SESSION_SECRET`) next to `server.js`.

   3. Initialize the database using `db/schema.sql` and `db/seed.sql` (MySQL)

   4. Start the server:

   ```bash
   node server.js
   ```

   Main endpoints
   --------------

   - `POST /api/auth/register` — register
   - `POST /api/auth/login` — login
   - `GET /api/auth/session` — current session
   - `GET /api/forums` — list public forums
   - `POST /api/forums` — create forum (auth)
   - `POST /api/forums/:forumId/threads` — create thread
   - `POST /api/threads/:threadId/posts` — create post
   - `GET /api/administrator/users` — admin: list users

  

   Project files 
   -----------------------------

   - `server.js` — Main Express application and route wiring.
   - `db.js` — Database connection pool and helper functions.
   - `auth.js` — Authentication helpers (password hashing, session helpers).
   - `.env` — Environment variables (DB creds, session secret).
   - `package.json` — NPM scripts and dependencies.
   - `routes/auth.js` — Auth endpoints (register, login, logout, session).
   - `routes/forums.js` — Forum CRUD endpoints.
   - `routes/threads.js` — Thread CRUD, ownership, moderators, and members.
   - `routes/posts.js` — Post CRUD and block/unblock endpoints.
   - `routes/admin.js` — Admin-only management endpoints.
   - `middleware/authMiddleware.js` — requireLogin/requireAdmin/thread-level middleware.
   - `acl.js` — Role/permission utility functions.
   - `db/schema.sql` — Database DDL for development (MySQL) 
   - `db/seed.sql` — Seed data for roles and initial admin user.
   -`Blug.postman_collection.json` — Postman collection for manual testing.
   - PHASE2_API.md` — Full endpoint documentation (present in repo).
     

  
   - 

