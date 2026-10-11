# Amir Nano Railway — PostgreSQL Admin Panel

A small Persian RTL admin dashboard for manually maintaining Hosts, Nodes, Cores, Groups, Users, and VLESS/VMess/Trojan configuration records. Usage is entered manually. Subscription URLs return enabled config text assigned to the user's group (or ungrouped configs when the user has no group).

## Required Railway variables

- `ADMIN_USERNAME`: admin login username.
- `ADMIN_PASSWORD`: strong, unique admin password. Do not leave empty.
- `SESSION_SECRET`: long random secret (32+ random bytes recommended).
- `DATABASE_URL`: add a PostgreSQL service and reference its `DATABASE_URL` variable to the web service.
- `COOKIE_HTTPS_ONLY=true` for Railway's HTTPS domain.

## Deploy

1. Upload the project files to a GitHub repository (root should contain `main.py`, `requirements.txt`, and `railway.json`).
2. In Railway create a project and deploy from that GitHub repo.
3. Add a PostgreSQL service to the same Railway project.
4. In the app service Variables, add `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `SESSION_SECRET`.
5. Reference the Postgres service's `DATABASE_URL` into the app service as `DATABASE_URL` (Railway's variable reference picker is recommended).
6. Generate a public domain in the app service's Settings / Networking.
7. Open `/login` and sign in.

## Usage

Create a Group first, then a User with that Group ID, then Config records assigned to the same Group ID. Open Users and copy the user's subscription URL. If a user has no group, only configs with no group are returned.

The `group_id` and `host_id` fields are database record IDs shown in edit URLs or database rows; this MVP does not yet have dropdown selectors. Usage is manual and is not actual network accounting. Configs are stored as entered; the app does not create server-side inbounds or validate that a node is running.

## Important limitations

- This is an MVP, not a hardened production product. Keep the panel private, use a strong password and session secret, and back up the database.
- Public subscription URLs are bearer links: anyone who has a URL can read that subscription. Treat them as secrets and rotate a user's subscription token manually in PostgreSQL if it leaks.
- Database schema changes are not migrated automatically. Back up before changing model definitions.
- `create_all()` initializes missing tables only; it does not alter existing tables.
