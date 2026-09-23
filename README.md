# PAK Command Center — Render Server

Backend + Admin UI cho workflow:

`Tạo Account → Tạo Key → Link Key vào Account → User đăng nhập lần đầu bằng Username + Password + Key → Key được consume → Account ACTIVE`

## Thông tin Admin bootstrap hiện tại

- Username: `han_jeu`
- Password bootstrap theo yêu cầu hiện tại: `21022010@`

Password **không còn hardcode trong runtime source**; server yêu cầu biến môi trường `ADMIN_PASSWORD`. Với Render, nhập password vào Environment Secret. Password bootstrap này nên được đổi trước khi dùng production.

## Files

```text
pak-admin-server/
├── server.js
├── package.json
├── render.yaml
├── .env.example
├── .gitignore
├── README.md
└── public/
    ├── index.html
    └── assets/
        └── logo.jpg
```

## Render

1. Push folder này lên GitHub.
2. Trong Render tạo Blueprint từ `render.yaml` hoặc tạo Web Service + Postgres.
3. Set:
   - `NODE_ENV=production`
   - `ADMIN_USERNAME=han_jeu`
   - `ADMIN_PASSWORD=<secret-production-mới>`
   - `DATABASE_URL=<Render Postgres connection string>`
4. Build: `npm install`
5. Start: `npm start`
6. Health: `/health`

## Account lifecycle

### 1) Create account

Admin nhập username + password hoặc bấm `Sinh password mạnh`.

Server:
- validate username/password
- bcrypt hash password
- lưu hash vào PostgreSQL
- không lưu plaintext password

UI chỉ hiện plaintext password ở màn hình "Account created" để ông chủ copy lại ngay. Sau khi reload/đi khỏi màn hình, server không có API xem lại password.

### 2) Create key

Chọn account `PENDING KEY`, chọn 16/24/32/48 ký tự rồi `Tạo key & liên kết account`.

Server:
- tạo key bằng CSPRNG
- lowercase `a-z`
- SHA-256 key
- lưu digest + 4 ký tự cuối + assigned user
- trả plaintext key đúng một lần

### 3) First user login

User account POST `/api/auth/login` cần:
- username
- password
- activationKey

Nếu account chưa active:
- key phải đúng account
- key phải ở trạng thái `unused`
- server atomically chuyển key → `used`
- server ghi `users.activated_at`
- tạo HttpOnly session

Admin login không cần activation key.

## Security baseline

- bcrypt password hashing, cost 12
- DB-backed random 256-bit session token, chỉ hash token trong DB
- HttpOnly + Secure (production) + SameSite=Strict cookie
- session expiration 8h
- login throttling theo IP + username
- same-origin check cho state-changing requests
- Helmet security headers
- CSP
- HSTS khi production
- PostgreSQL parameterized queries
- activation key không lưu plaintext
- account lock/disable
- disable account sẽ revoke session
- xóa account sẽ revoke các key unused đang gắn account

## API

Public:
- `GET /health`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

Admin:
- `GET /api/admin/overview`
- `GET /api/admin/users`
- `POST /api/admin/users`
- `PATCH /api/admin/users/:id/status`
- `DELETE /api/admin/users/:id`
- `GET /api/admin/keys`
- `POST /api/admin/keys`
- `POST /api/admin/keys/:id/revoke`
- `DELETE /api/admin/keys/:id`

## Important

Không commit `.env` có secret thật lên GitHub. `.env.example` chỉ là template.

Password được hiển thị trong Admin UI ngay sau khi tạo account vì đó là thông tin plaintext mà Admin vừa nhập/sinh; database không có đường ngược để xem lại password.


## Render: xử lý lỗi `Exited with status 1`

Bản V3 có log startup rõ ràng với prefix `[PAK][FATAL]`.

Hai cấu hình bắt buộc:

```text
ADMIN_PASSWORD=<secret>
DATABASE_URL=<Render Postgres Internal Database URL>
```

Cách deploy khuyến nghị: chọn **New → Blueprint** và chọn repository có `render.yaml`. Blueprint sẽ provision Web Service + Postgres và inject `DATABASE_URL` bằng `fromDatabase`.

Nếu ông chủ tạo **Web Service** thủ công, `render.yaml` không tự provision database. Khi đó phải tạo Render Postgres riêng, vào **Connect**, lấy **Internal Database URL**, rồi thêm biến `DATABASE_URL` vào Environment của Web Service.

Web service được cấu hình bind `0.0.0.0:$PORT`; Render yêu cầu web service lắng nghe trên `0.0.0.0` và port từ `$PORT`.
