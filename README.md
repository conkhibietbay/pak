# PAK Command Center — Render OneClick

## Deploy

This package is prepared for a Render Blueprint deployment. The repository root must contain `server.js`, `package.json`, `render.yaml`, and `public/`.

Use Render **New → Blueprint** and select the Git repository containing this `render.yaml`. The Blueprint creates the Web Service and the Render Postgres database, then injects the Postgres `connectionString` into `DATABASE_URL`.

During the initial Blueprint creation, Render will prompt for `ADMIN_PASSWORD` because it is intentionally declared with `sync: false`. Do not commit the password into Git.

Admin username is fixed as `han_jeu`. The password is whatever secret you enter for `ADMIN_PASSWORD`.

Start command:

```text
node ./server.js
```

Health endpoint:

```text
/health
```

## Repository layout

```text
server.js
package.json
render.yaml
public/
  index.html
  assets/
    logo.jpg
```

Do not upload the ZIP itself as the repository contents. Extract it and put these files at the repository root.

## Security

- Passwords are stored as bcrypt hashes.
- Session tokens are stored only as SHA-256 digests.
- Activation keys are stored as hashes and plaintext is returned only at creation time.
- Admin password is not stored in source code or logged.
- HTTP-only, Secure, SameSite=Strict session cookie in production.
- Helmet security headers and CSP.
- Same-origin checks for state-changing requests.
- Parameterized PostgreSQL queries.
- Login throttling.

## Render Free-plan limitation

Render currently offers Free Web Services and Free Postgres, but Free Postgres expires 30 days after creation and has no backups. For long-lived account/key data, use a paid Postgres plan or upgrade before expiry.
