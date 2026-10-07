# Zero Sign-On

**Passwordless authentication with WebAuthn and discoverable passkeys.**

A university team project developed at **VILNIUS TECH** for *Information Technology Security Methods* in November 2025. It explores how browser-based public-key authentication connects to a Node.js backend, relational credential storage and cookie-based sessions.

**Project status:** educational proof of concept for a controlled lab environment. End-to-end operation has not been revalidated during this documentation update; this is not a production authentication service.

## What the project demonstrates

- Passkey registration using an email address as the account identifier.
- A usernameless login flow based on discoverable credentials.
- Server-side WebAuthn response verification against the configured challenge, origin and relying-party ID.
- Storage of credential IDs, public keys and signature counters.
- JWT-based sessions in HttpOnly cookies and an authenticated `/api/me` endpoint.
- A university deployment using Apache HTTPS, a Linux server and MySQL/MariaDB.

“Zero Sign-On” is the project name. The implementation explores authentication within one application, rather than federation across several applications.

## Architecture

| Component | Role |
| --- | --- |
| Browser and authenticator | Create a passkey and produce signed authentication responses |
| HTML and JavaScript | Start WebAuthn ceremonies and submit their results |
| Apache | Terminate HTTPS and proxy requests to the application |
| Node.js and Express | Verify WebAuthn responses and manage authenticated requests |
| MySQL/MariaDB | Store users and public-key credential records |

The Express server defaults to `127.0.0.1:3000` and trusts one reverse-proxy hop. The database layer supports TCP or a configured Unix socket. Pending challenges are stored in process memory.

## Technology

**Backend:** JavaScript ES modules, Node.js, Express, SimpleWebAuthn, mysql2, jsonwebtoken  
**Frontend:** HTML, CSS and browser JavaScript  
**Infrastructure:** Apache, Linux, MySQL/MariaDB; Proxmox in the documented university lab

## Repository guide

| Path | Contents |
| --- | --- |
| `backend/server.js` | Express setup, application routes and shutdown handling |
| `backend/webauthn.js` | Passkey registration and login logic |
| `backend/auth.js` | JWT issuance, verification and cookie options |
| `backend/db.js` | Database configuration and connection pool |
| `public/index.html` | Active user interface with inline JavaScript |
| `package.json` / `package-lock.json` | Scripts and dependency definitions |
| `.env.example` | Placeholder configuration for a local lab |
| `zsoo.sql` | Original shell snippet that writes the database schema |
| `ssl.txt`, `systemd.txt`, `local.server.txt`, `localdb.txt` | Original deployment notes |

The SQL-named file contains shell commands and destructive table-reset statements. It is not a migration to import blindly into an existing database.

## Lab setup outline

1. Prepare an isolated Linux test environment, compatible Node.js runtime, MySQL/MariaDB and a WebAuthn-capable browser/authenticator.
2. Review the existing setup notes and create the schema in an **empty test database**. Align its name with `DB_NAME`; the schema snippet uses `zso`.
3. Copy `.env.example` to `.env` and fill in local credentials and a random JWT secret. For example, generate a secret locally with:
   ```sh
   node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
   ```
4. Install dependencies from the lockfile with `npm ci`.
5. Configure the HTTPS reverse proxy, trusted certificate, exact `ORIGIN` and matching `RPID` for the lab hostname.
6. Start the application with `npm start` or use `npm run dev` for the nodemon workflow.
7. Validate registration, login, access to `/api/me` and logout with test accounts.

These are setup requirements, not a verified one-command deployment. Browser/server library compatibility and the existing authentication flows need validation before presenting a live demo.

## Learning outcomes

- Understanding WebAuthn registration and assertion verification.
- Connecting authentication ceremonies to database records and sessions.
- Configuring HTTPS and reverse-proxy deployment in a virtualized lab.
- Distinguishing the intended design from tested security properties.

## Further development

- Reproducible setup and automated integration tests.
- Dependency and frontend version alignment.
- Further review of enrollment, session and challenge handling.
- Production-appropriate logging, configuration validation and request controls.
- Clear separation of maintained application files and historical lab notes.

## Team

**Eyüphan Bayram · Jonas Schmitt · Saba Nadiradze**

This was a collaborative university project. Team attribution is retained; individual responsibilities should be documented after confirmation.

No new license is assigned by this documentation update.
