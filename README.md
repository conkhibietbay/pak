# PAK Command Center — Render V4 FIXED

## V4 startup fix

Lỗi ảnh chụp màn hình là:

```text
Error: ADMIN_PASSWORD is missing.
```

V4 xử lý bằng 2 lớp:

1. `render.yaml` khai báo `ADMIN_PASSWORD=21022010@` để Blueprint có giá trị ngay khi tạo/sync.
2. `server.js` có bootstrap fallback `21022010@`, nên Web Service cũ cũng không chết chỉ vì thiếu Environment Variable.

> Vì password này được ông chủ yêu cầu cố định, nó đang xuất hiện trong cấu hình/source. Sau khi hệ thống chạy ổn, nên đổi `ADMIN_PASSWORD` sang secret riêng trong Render Environment.

## Deploy

Khuyến nghị dùng **Render Blueprint** từ repository chứa `render.yaml`. Blueprint sẽ tạo Web Service + Render Postgres và inject `DATABASE_URL` bằng `fromDatabase`.

Nếu ông chủ đang dùng Web Service đã tạo thủ công, chỉ cần redeploy code V4; database vẫn phải có `DATABASE_URL` trong Environment.

### Commands

```text
Build: npm install
Start: npm start
Health: /health
````

## Admin

```text
Username: han_jeu
Password: 21022010@
```

## Account flow

```text
Create Account
      ↓
Create Key
      ↓
Link Key → Account
      ↓
User Login + Password + Key
      ↓
Key = USED
      ↓
Account = ACTIVE
```

## Security

- bcrypt password hashing
- DB-backed random 256-bit session token; only SHA-256 token digest in DB
- HttpOnly + Secure production + SameSite=Strict cookie
- session expiration 8h
- login throttling IP + username
- same-origin checks on state-changing requests
- Helmet + CSP + HSTS production
- parameterized PostgreSQL queries
- activation key plaintext returned only once
- key assigned to a single pending account
- disable account revokes sessions
- delete account revokes unused assigned keys

## Current Render facts

Render Blueprints use `render.yaml` at the repository root. Node web services use `runtime: node`, and web services must listen on `0.0.0.0` and the Render port. Render supports `fromDatabase` to inject a Postgres `connectionString`.
