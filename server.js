const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = "0.0.0.0";
const DATABASE_URL = process.env.DATABASE_URL || "";
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "han_jeu").trim().toLowerCase();
// Bootstrap credential requested by the owner. Render Environment can override it.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "21022010@";

function resolveDatabaseConfig() {
  if (DATABASE_URL) return { connectionString: DATABASE_URL };
  const host = process.env.PGHOST, database = process.env.PGDATABASE;
  const user = process.env.PGUSER, password = process.env.PGPASSWORD;
  const port = Number(process.env.PGPORT || 5432);
  if (host && database && user && password) return { host, database, user, password, port };
  throw new Error("DATABASE CONFIG MISSING: set DATABASE_URL or PGHOST/PGDATABASE/PGUSER/PGPASSWORD");
}

const isProd = process.env.NODE_ENV === "production";
const dbConfig = resolveDatabaseConfig();

const pool = new Pool({
  ...dbConfig,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 8,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: isProd ? [] : null
    }
  },
  referrerPolicy: { policy: "no-referrer" },
  frameguard: { action: "deny" },
  noSniff: true,
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false
}));
app.use(compression());
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: false, limit: "8kb" }));
app.use(cookieParser());

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const attempts = new Map();
const ALPHABET = "abcdefghijklmnopqrstuvwxyz";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function cleanAttempts(key) {
  const now = Date.now();
  const fresh = (attempts.get(key) || []).filter(t => now - t < LOGIN_WINDOW_MS);
  attempts.set(key, fresh);
  return fresh;
}
function allowedLogin(key) { return cleanAttempts(key).length < MAX_LOGIN_ATTEMPTS; }
function recordFailure(key) {
  const fresh = cleanAttempts(key);
  fresh.push(Date.now());
  attempts.set(key, fresh);
}
function clearFailures(key) { attempts.delete(key); }

function validUsername(value) {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{2,31}$/.test(value);
}
function validUserPassword(value) {
  return typeof value === "string" &&
    value.length >= 12 && value.length <= 128 &&
    /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
}
function newId() { return crypto.randomUUID(); }

function sameOrigin(req) {
  const origin = req.get("origin");
  if (!origin) return true;
  try {
    return origin === `${req.protocol}://${req.get("host")}`;
  } catch {
    return false;
  }
}
function requireSameOrigin(req, res, next) {
  if (!sameOrigin(req)) return res.status(403).json({ error: "Cross-origin request blocked" });
  next();
}

function makeToken() {
  return crypto.randomBytes(32).toString("base64url");
}

async function issueSession(res, userId, role) {
  const token = makeToken();
  const tokenHash = sha256(token);
  await pool.query(
    `INSERT INTO sessions(token_hash,user_id,role,expires_at)
     VALUES($1,$2,$3,NOW()+INTERVAL '8 hours')`,
    [tokenHash, userId, role]
  );
  res.cookie("pak_session", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: "strict",
    maxAge: SESSION_TTL_MS,
    path: "/"
  });
}

async function sessionFrom(req) {
  const token = req.cookies.pak_session;
  if (!token) return null;
  const { rows } = await pool.query(`
    SELECT s.token_hash, s.user_id, s.role, s.expires_at,
           u.username, u.disabled, u.activated_at
    FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=$1 AND s.expires_at>NOW()
    LIMIT 1
  `, [sha256(token)]);
  const row = rows[0];
  if (!row || row.disabled) return null;
  return { ...row, token };
}

async function requireAdmin(req, res, next) {
  try {
    const s = await sessionFrom(req);
    if (!s || s.role !== "admin") return res.status(401).json({ error: "Unauthorized" });
    req.session = s;
    next();
  } catch (e) { next(e); }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(16) NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      disabled BOOLEAN NOT NULL DEFAULT FALSE
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS activation_keys (
      id UUID PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      key_last4 CHAR(4) NOT NULL,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      status VARCHAR(16) NOT NULL DEFAULT 'unused',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64) PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(16) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_users_status ON users(disabled, activated_at);
    CREATE INDEX IF NOT EXISTS idx_keys_created ON activation_keys(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_keys_assigned ON activation_keys(assigned_user_id, status);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
  `);

  // Keep exactly one bootstrap admin. Its secret comes from Render Environment.
  const { rows } = await pool.query("SELECT id FROM users WHERE role='admin' ORDER BY created_at ASC LIMIT 1");
  const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  if (!rows.length) {
    await pool.query(
      `INSERT INTO users(id,username,password_hash,role,activated_at)
       VALUES($1,$2,$3,'admin',NOW())`,
      [newId(), ADMIN_USERNAME, adminHash]
    );
  } else {
    await pool.query(
      `UPDATE users SET username=$1,password_hash=$2,disabled=false,activated_at=COALESCE(activated_at,NOW())
       WHERE id=$3`,
      [ADMIN_USERNAME, adminHash, rows[0].id]
    );
  }

  await pool.query("DELETE FROM sessions WHERE expires_at<=NOW()");
}

setInterval(() => {
  pool.query("DELETE FROM sessions WHERE expires_at<=NOW()").catch(() => {});
  for (const [key] of attempts) {
    if (!cleanAttempts(key).length) attempts.delete(key);
  }
}, 10 * 60 * 1000).unref();

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "pak-admin", time: new Date().toISOString() });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post("/api/auth/login", requireSameOrigin, async (req, res, next) => {
  try {
    const ip = req.ip || "unknown";
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const activationKey = String(req.body.activationKey || "").trim().toLowerCase();
    const attemptKey = `${ip}:${username}`;

    if (!validUsername(username)) return res.status(400).json({ error: "Invalid username format" });
    if (!allowedLogin(attemptKey)) return res.status(429).json({ error: "Too many attempts. Try again later." });

    const { rows } = await pool.query(`
      SELECT id,username,password_hash,role,disabled,activated_at
      FROM users WHERE username=$1 LIMIT 1
    `, [username]);
    const user = rows[0];

    let keyOk = true;
    if (user && user.role === "user" && !user.activated_at) {
      if (!activationKey) keyOk = false;
      if (activationKey) {
        const kr = await pool.query(
          `SELECT id FROM activation_keys
           WHERE key_hash=$1 AND assigned_user_id=$2 AND status='unused'
           LIMIT 1`,
          [sha256(activationKey), user.id]
        );
        keyOk = !!kr.rows[0];
      }
    }

    const passwordOk = !!user && !user.disabled && await bcrypt.compare(password, user.password_hash);
    if (!passwordOk || !keyOk) {
      recordFailure(attemptKey);
      if (user && user.role === "user" && !user.activated_at && !keyOk) {
        return res.status(401).json({ error: "Account requires its assigned activation key" });
      }
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Consume the activation key atomically during first user login.
    if (user.role === "user" && !user.activated_at) {
      const consume = await pool.query(`
        UPDATE activation_keys
        SET status='used',used_at=NOW()
        WHERE key_hash=$1 AND assigned_user_id=$2 AND status='unused'
        RETURNING id
      `, [sha256(activationKey), user.id]);
      if (!consume.rowCount) return res.status(409).json({ error: "Activation key is no longer available" });
      await pool.query("UPDATE users SET activated_at=NOW() WHERE id=$1", [user.id]);
    }

    clearFailures(attemptKey);
    await issueSession(res, user.id, user.role);
    res.json({
      ok: true,
      user: {
        username: user.username,
        role: user.role,
        activated: true
      }
    });
  } catch (e) { next(e); }
});

app.post("/api/auth/logout", requireSameOrigin, async (req, res, next) => {
  try {
    const token = req.cookies.pak_session;
    if (token) await pool.query("DELETE FROM sessions WHERE token_hash=$1", [sha256(token)]);
    res.clearCookie("pak_session", {
      httpOnly: true, secure: isProd, sameSite: "strict", path: "/"
    });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get("/api/auth/me", async (req, res, next) => {
  try {
    const s = await sessionFrom(req);
    if (!s) return res.status(401).json({ error: "Unauthorized" });
    res.json({
      user: {
        username: s.username,
        role: s.role,
        activated: !!s.activated_at
      }
    });
  } catch (e) { next(e); }
});

app.get("/api/admin/overview", requireAdmin, async (_req, res, next) => {
  try {
    const [{ rows: users }, { rows: keyStats }] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE role='user')::int AS accounts,
          COUNT(*) FILTER (WHERE role='user' AND activated_at IS NULL AND disabled=false)::int AS pending,
          COUNT(*) FILTER (WHERE role='user' AND activated_at IS NOT NULL AND disabled=false)::int AS active,
          COUNT(*) FILTER (WHERE role='user' AND disabled=true)::int AS disabled
        FROM users
      `),
      pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status='unused')::int AS unused,
          COUNT(*) FILTER (WHERE status='used')::int AS used,
          COUNT(*) FILTER (WHERE status='revoked')::int AS revoked
        FROM activation_keys
      `)
    ]);
    res.json({ users: users[0], keys: keyStats[0] });
  } catch (e) { next(e); }
});

app.get("/api/admin/users", requireAdmin, async (_req, res, next) => {
  try {
    const { rows } = await pool.query(`
      SELECT id,username,role,created_at,disabled,activated_at
      FROM users ORDER BY created_at DESC
    `);
    res.json({ users: rows });
  } catch (e) { next(e); }
});

app.post("/api/admin/users", requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validUsername(username)) return res.status(400).json({ error: "Username: 3-32 ký tự, bắt đầu bằng a-z; chỉ a-z, 0-9, _, -." });
    if (!validUserPassword(password)) return res.status(400).json({ error: "Password: 12-128 ký tự, cần chữ thường + chữ hoa + số." });

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users(id,username,password_hash,role)
       VALUES($1,$2,$3,'user')
       RETURNING id,username,role,created_at,activated_at`,
      [newId(), username, hash]
    );
    res.status(201).json({ user: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Username đã tồn tại" });
    next(e);
  }
});

app.patch("/api/admin/users/:id/status", requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const disabled = Boolean(req.body.disabled);
    const { rows } = await pool.query("SELECT role FROM users WHERE id=$1 LIMIT 1", [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: "Account not found" });
    if (rows[0].role === "admin") return res.status(400).json({ error: "Không khóa Admin tại đây" });

    await pool.query("UPDATE users SET disabled=$1 WHERE id=$2", [disabled, req.params.id]);
    if (disabled) await pool.query("DELETE FROM sessions WHERE user_id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/admin/users/:id", requireAdmin, requireSameOrigin, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query("SELECT role FROM users WHERE id=$1 FOR UPDATE", [req.params.id]);
    if (!rows[0]) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Account not found" }); }
    if (rows[0].role === "admin") { await client.query("ROLLBACK"); return res.status(400).json({ error: "Admin account cannot be deleted" }); }

    await client.query(`
      UPDATE activation_keys
      SET status='revoked',revoked_at=NOW()
      WHERE assigned_user_id=$1 AND status='unused'
    `, [req.params.id]);
    await client.query("DELETE FROM users WHERE id=$1", [req.params.id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    next(e);
  } finally { client.release(); }
});

app.get("/api/admin/keys", requireAdmin, async (_req, res, next) => {
  try {
    const { rows } = await pool.query(`
      SELECT k.id,k.key_last4,k.status,k.created_at,k.used_at,k.revoked_at,
             u.username AS assigned_username
      FROM activation_keys k
      LEFT JOIN users u ON u.id=k.assigned_user_id
      ORDER BY k.created_at DESC
    `);
    res.json({ keys: rows });
  } catch (e) { next(e); }
});

app.post("/api/admin/keys", requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const assignedUserId = String(req.body.userId || "");
    const length = Math.min(64, Math.max(8, Number(req.body.length) || 24));

    const ur = await pool.query(
      "SELECT id,username,role,disabled,activated_at FROM users WHERE id=$1 LIMIT 1",
      [assignedUserId]
    );
    const user = ur.rows[0];
    if (!user || user.role !== "user") return res.status(400).json({ error: "Chọn một user account hợp lệ" });
    if (user.disabled) return res.status(400).json({ error: "Account đang bị khóa" });
    if (user.activated_at) return res.status(400).json({ error: "Account đã activated; hãy tạo account mới cho key mới" });

    let key = "";
    for (let i = 0; i < length; i++) key += ALPHABET[crypto.randomInt(ALPHABET.length)];
    const keyHash = sha256(key);
    const id = newId();

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(
        "SELECT activated_at,disabled FROM users WHERE id=$1 FOR UPDATE",
        [user.id]
      );
      if (!locked.rows[0] || locked.rows[0].disabled) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Account đang bị khóa hoặc không còn tồn tại" });
      }
      if (locked.rows[0].activated_at) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Account đã activated; hãy tạo account mới cho key mới" });
      }
      const existing = await client.query(
        "SELECT id FROM activation_keys WHERE assigned_user_id=$1 AND status='unused' LIMIT 1",
        [user.id]
      );
      if (existing.rows[0]) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Account này đã có một key UNUSED. Thu hồi key cũ trước khi tạo key mới." });
      }
      await client.query(
        `INSERT INTO activation_keys(id,key_hash,key_last4,assigned_user_id)
         VALUES($1,$2,$3,$4)`,
        [id, keyHash, key.slice(-4), user.id]
      );
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      client.release();
    }

    res.status(201).json({
      id,
      key,
      target: user.username,
      length,
      status: "unused",
      warning: "Copy key now. Server/database never stores plaintext."
    });
  } catch (e) { next(e); }
});

app.post("/api/admin/keys/:id/revoke", requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const r = await pool.query(`
      UPDATE activation_keys
      SET status='revoked',revoked_at=NOW()
      WHERE id=$1 AND status='unused'
    `, [req.params.id]);
    if (!r.rowCount) return res.status(409).json({ error: "Key không còn ở trạng thái unused" });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/admin/keys/:id", requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const r = await pool.query("DELETE FROM activation_keys WHERE id=$1", [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: "Key not found" });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use(express.static("public", {
  index: "index.html",
  maxAge: isProd ? "1h" : 0
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

async function start() {
  try {
    await initDb();
    const server = app.listen(PORT, HOST, () => {
      console.log(`[PAK] listening on http://${HOST}:${PORT}`);
      console.log(`[PAK] database: configured`);
      console.log(`[PAK] admin username: ${ADMIN_USERNAME}`);
    });
    server.keepAliveTimeout = 120000;
    server.headersTimeout = 125000;
  } catch (err) {
    console.error("[PAK][FATAL] Startup failed.");
    console.error(String(err && err.stack || err));
    console.error("[PAK][HELP] Check DATABASE_URL/Render Postgres and ADMIN_PASSWORD.");
    process.exitCode = 1;
  }
}
start();
