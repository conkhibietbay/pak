# PAK Command Center — Render One-Click V7

This build does not require PostgreSQL to start. It uses a protected local JSON store when `DATABASE_URL` is unavailable, so the Render Web Service can boot without `DATABASE_NOT_CONFIGURED`.

## Repository root

```text
server.js
package.json
render.yaml
.node-version
public/
  index.html
  assets/
    logo.jpg
```

## Deploy

1. Extract this ZIP.
2. Upload the files inside it to the repository root.
3. Deploy the repository as a Render Web Service or Blueprint.
4. `startCommand` is `node ./server.js`.
5. Optional: set `ADMIN_PASSWORD` in Render Environment. If omitted, the bootstrap password is the current project default and should be changed before real use.

## Storage

Without a Render persistent disk, local data can be lost when the service is redeployed or restarted. The app is designed to run without PostgreSQL, but durable production account/key storage requires a persistent volume or an external database.

If a persistent disk is attached at `/var/data`, the app uses `/var/data/pak-command-center/store.json`.

Passwords are stored as bcrypt hashes. Activation-key plaintext is returned only once at creation and only its SHA-256 hash is stored.
