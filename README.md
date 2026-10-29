# Business Deals — full-stack website

This is a full-stack starter project with a colorful responsive site, application submission, SQLite database, password-hashed admin account, admin replies/statuses, session-based login, CSRF tokens, security headers, and login rate limiting.

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set `ADMIN_PASSWORD` to a strong, unique password of at least 10 characters and set a long random `SESSION_SECRET`.
4. In this folder, run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000`. Admin panel: `http://localhost:3000/admin`.

## Important before public launch
- This project is code, not a published live website. Deploy it to a Node.js host with persistent disk storage and HTTPS.
- Set `NODE_ENV=production`, use a strong `SESSION_SECRET`, and use a strong admin password. Do not use the requested short password `221133` on a public site.
- The SQLite database and session store require persistent writable disk. If your host has ephemeral storage, use a managed database and session store instead.
- Configure backups, privacy policy/consent, monitoring, and a transactional email service if applicants should receive replies by email. Email sending is not configured in this starter.
- Change the default admin username if desired. Protect `.env`; never upload it to a public repository.
- Review security and local legal/privacy requirements before collecting real personal data.

## Features
- Public form for Job Application, Business Idea, and Business Deal.
- Admin login with bcrypt-hashed password stored in SQLite.
- Admin can review up to 500 newest applications, reply, change status, and delete.
- Server-side validation, CSRF token checks, secure session cookie settings, security headers, and rate limiting for login attempts.
