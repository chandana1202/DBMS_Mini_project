# Web app (Next.js 16)

Login, role-based pages and API routes for the Supply-Chain Vulnerability DB.
See the main `README.md` in the project root for full setup.

```
npm install
copy .env.example .env.local      (Windows)   |   cp .env.example .env.local
npm run seed:passwords            # sets Demo@1234 for the four demo users
npm run dev                       # http://localhost:3000
npm run test:api                  # in a second terminal, while dev is running
```

| Folder | What is inside |
|---|---|
| `app/login`, `app/dashboard`, `app/my-projects`, `app/analyst`, `app/nosql`, `app/admin`, `app/forbidden` | Pages |
| `app/api/...` | Route handlers (backend). Each one checks the role, then queries MySQL or MongoDB |
| `lib/auth.js` | JWT sign/verify (httpOnly cookie, 2 h) |
| `lib/db.js` | One MySQL pool per role (`app_admin`, `app_analyst`, `app_developer`) + login-only pool (`app_auth`) |
| `lib/mongo.js` | MongoDB connection and audit helper |
| `lib/api.js` | `guard()` role check and MySQL/Mongo error handling |
| `proxy.js` | Next 16 "proxy" (formerly middleware): sends logged-out users to /login and wrong roles to /forbidden |
| `components/` | Shared layout (`Shell.js`) and UI pieces (`ui.js`) |
| `scripts/seed-passwords.mjs` | Writes bcrypt hashes into `app_user.password_hash` |
| `tests/api-smoke.mjs` | 30 end-to-end checks of login, roles and data access |
