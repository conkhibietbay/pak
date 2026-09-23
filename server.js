const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = "0.0.0.0";
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "han_jeu").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "21022010@");
const IS_PROD = process.env.NODE_ENV === "production";
const DATA_DIR = process.env.PAK_DATA_DIR || (fs.existsSync("/var/data") ? "/var/data/pak-command-center" : path.join(__dirname, ".data"));
const DATA_FILE = path.join(DATA_DIR, "store.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

function uid() { return crypto.randomUUID(); }
function sha256(v) { return crypto.createHash("sha256").update(v).digest("hex"); }
function token() { return crypto.randomBytes(32).toString("base64url"); }
function now() { return new Date().toISOString(); }
function atomicWrite(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function defaultStore() {
  return { version: 1, users: [], keys: [], sessions: [] };
}
function loadStore() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    return { ...defaultStore(), ...data };
  } catch {
    return defaultStore();
  }
}
let store = loadStore();
function saveStore() { atomicWrite(DATA_FILE, store); }

function validUsername(v) { return typeof v === "string" && /^[a-z][a-z0-9_-]{2,31}$/.test(v); }
function validPassword(v) { return typeof v === "string" && v.length >= 12 && v.length <= 128 && /[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v); }
function cleanSessions() {
  const cutoff = Date.now();
  const before = store.sessions.length;
  store.sessions = store.sessions.filter(s => Date.parse(s.expiresAt) > cutoff);
  if (before !== store.sessions.length) saveStore();
}
function publicUser(u) { return { id: u.id, username: u.username, role: u.role, created_at: u.createdAt, disabled: u.disabled, activated_at: u.activatedAt || null }; }
function sessionUser(req) {
  cleanSessions();
  const raw = req.cookies.pak_session;
  if (!raw) return null;
  const s = store.sessions.find(x => x.tokenHash === sha256(raw));
  if (!s) return null;
  const u = store.users.find(x => x.id === s.userId);
  if (!u || u.disabled || Date.parse(s.expiresAt) <= Date.now()) return null;
  return { session: s, user: u };
}
function sameOrigin(req) {
  const origin = req.get("origin");
  return !origin || origin === `${req.protocol}://${req.get("host")}`;
}
function requireOrigin(req, res, next) {
  if (!sameOrigin(req)) return res.status(403).json({ error: "Cross-origin request blocked" });
  next();
}
function requireAdmin(req, res, next) {
  const auth = sessionUser(req);
  if (!auth || auth.user.role !== "admin") return res.status(401).json({ error: "Unauthorized" });
  req.auth = auth;
  next();
}
function issueSession(res, user) {
  const raw = token();
  store.sessions.push({ tokenHash: sha256(raw), userId: user.id, role: user.role, createdAt: now(), expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString() });
  saveStore();
  res.cookie("pak_session", raw, { httpOnly: true, secure: IS_PROD, sameSite: "strict", maxAge: 8 * 60 * 60 * 1000, path: "/" });
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], baseUri: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], upgradeInsecureRequests: IS_PROD ? [] : null } }, referrerPolicy: { policy: "no-referrer" }, frameguard: { action: "deny" }, noSniff: true, hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false }));
app.use(compression());
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: false, limit: "8kb" }));
app.use(cookieParser());

async function ensureAdmin() {
  let admin = store.users.find(u => u.role === "admin");
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  if (!admin) {
    admin = { id: uid(), username: ADMIN_USERNAME, passwordHash: hash, role: "admin", createdAt: now(), disabled: false, activatedAt: now() };
    store.users.push(admin);
  } else if (admin.username !== ADMIN_USERNAME || !admin.passwordHash) {
    admin.username = ADMIN_USERNAME;
    admin.passwordHash = hash;
    admin.disabled = false;
    admin.activatedAt ||= now();
  }
  saveStore();
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "pak-admin", storage: "local", mode: "ready" }));
app.get("/api/config-status", (_req, res) => res.json({ databaseConfigured: true, adminConfigured: true, mode: "ready", storage: "local" }));

app.post("/api/auth/login", requireOrigin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validUsername(username)) return res.status(400).json({ error: "Invalid username format" });
    const user = store.users.find(u => u.username === username);
    if (!user || user.disabled || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: "Invalid credentials" });
    issueSession(res, user);
    res.json({ ok: true, user: { username: user.username, role: user.role, activated: true } });
  } catch (e) { next(e); }
});

app.post("/api/auth/logout", requireOrigin, (req, res) => {
  const raw = req.cookies.pak_session;
  if (raw) { store.sessions = store.sessions.filter(s => s.tokenHash !== sha256(raw)); saveStore(); }
  res.clearCookie("pak_session", { httpOnly: true, secure: IS_PROD, sameSite: "strict", path: "/" });
  res.json({ ok: true });
});
app.get("/api/auth/me", (req, res) => {
  const a = sessionUser(req);
  if (!a) return res.status(401).json({ error: "Unauthorized" });
  res.json({ user: { username: a.user.username, role: a.user.role, activated: true } });
});

app.get("/api/admin/overview", requireAdmin, (_req, res) => {
  const users = store.users;
  const keys = store.keys;
  res.json({ users: { total: users.length, accounts: users.filter(u => u.role === "user").length, pending: users.filter(u => u.role === "user" && !u.activatedAt && !u.disabled).length, active: users.filter(u => u.role === "user" && u.activatedAt && !u.disabled).length, disabled: users.filter(u => u.role === "user" && u.disabled).length }, keys: { total: keys.length, unused: keys.filter(k => k.status === "unused").length, used: keys.filter(k => k.status === "used").length, revoked: keys.filter(k => k.status === "revoked").length } });
});
app.get("/api/admin/users", requireAdmin, (_req, res) => res.json({ users: [...store.users].sort((a,b) => Date.parse(b.createdAt)-Date.parse(a.createdAt)).map(publicUser) }));
app.post("/api/admin/users", requireAdmin, requireOrigin, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validUsername(username)) return res.status(400).json({ error: "Username: 3-32 ký tự, bắt đầu bằng a-z; chỉ a-z, 0-9, _, -." });
    if (!validPassword(password)) return res.status(400).json({ error: "Password: 12-128 ký tự, cần chữ thường + chữ hoa + số." });
    if (store.users.some(u => u.username === username)) return res.status(409).json({ error: "Username đã tồn tại" });
    const u = { id: uid(), username, passwordHash: await bcrypt.hash(password, 12), role: "user", createdAt: now(), disabled: false, activatedAt: null };
    store.users.push(u); saveStore(); res.status(201).json({ user: publicUser(u) });
  } catch (e) { next(e); }
});
app.patch("/api/admin/users/:id/status", requireAdmin, requireOrigin, (req, res) => {
  const u = store.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: "Account not found" });
  if (u.role === "admin") return res.status(400).json({ error: "Không khóa Admin tại đây" });
  u.disabled = Boolean(req.body.disabled);
  if (u.disabled) store.sessions = store.sessions.filter(s => s.userId !== u.id);
  saveStore(); res.json({ ok: true });
});
app.delete("/api/admin/users/:id", requireAdmin, requireOrigin, (req, res) => {
  const u = store.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: "Account not found" });
  if (u.role === "admin") return res.status(400).json({ error: "Admin account cannot be deleted" });
  for (const k of store.keys) if (k.assignedUserId === u.id && k.status === "unused") { k.status = "revoked"; k.revokedAt = now(); }
  store.users = store.users.filter(x => x.id !== u.id);
  store.sessions = store.sessions.filter(s => s.userId !== u.id);
  saveStore(); res.json({ ok: true });
});

app.get("/api/admin/keys", requireAdmin, (_req, res) => res.json({ keys: [...store.keys].sort((a,b) => Date.parse(b.createdAt)-Date.parse(a.createdAt)).map(k => ({ id:k.id, key_last4:k.keyLast4, status:k.status, created_at:k.createdAt, used_at:k.usedAt || null, revoked_at:k.revokedAt || null, assigned_username:(store.users.find(u=>u.id===k.assignedUserId)||{}).username || null })) }));
app.post("/api/admin/keys", requireAdmin, requireOrigin, (req, res) => {
  const userId = String(req.body.userId || "");
  const length = Math.min(64, Math.max(8, Number(req.body.length) || 24));
  const u = store.users.find(x => x.id === userId && x.role === "user");
  if (!u) return res.status(400).json({ error: "Chọn một user account hợp lệ" });
  if (u.disabled) return res.status(400).json({ error: "Account đang bị khóa" });
  if (u.activatedAt) return res.status(400).json({ error: "Account đã activated; hãy tạo account mới cho key mới" });
  if (store.keys.some(k => k.assignedUserId === u.id && k.status === "unused")) return res.status(409).json({ error: "Account này đã có một key UNUSED. Thu hồi key cũ trước khi tạo key mới." });
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let key = ""; for (let i=0;i<length;i++) key += alphabet[crypto.randomInt(alphabet.length)];
  const k = { id: uid(), keyHash: sha256(key), keyLast4: key.slice(-4), assignedUserId: u.id, status: "unused", createdAt: now(), usedAt: null, revokedAt: null };
  store.keys.push(k); saveStore();
  res.status(201).json({ id:k.id, key, target:u.username, length, status:k.status, warning:"Copy key now. Server never stores plaintext." });
});
app.post("/api/admin/keys/:id/revoke", requireAdmin, requireOrigin, (req,res) => {
  const k=store.keys.find(x=>x.id===req.params.id); if(!k)return res.status(404).json({error:"Key not found"});
  if(k.status!=="unused")return res.status(409).json({error:"Key không còn ở trạng thái unused"}); k.status="revoked";k.revokedAt=now();saveStore();res.json({ok:true});
});
app.delete("/api/admin/keys/:id", requireAdmin, requireOrigin, (req,res) => { const k=store.keys.find(x=>x.id===req.params.id);if(!k)return res.status(404).json({error:"Key not found"});store.keys=store.keys.filter(x=>x.id!==k.id);saveStore();res.json({ok:true}); });

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.use((err, _req, res, _next) => { console.error("[PAK][ERROR]", err); res.status(500).json({ error: "Internal server error" }); });

ensureAdmin().then(() => app.listen(PORT, HOST, () => console.log(`[PAK] listening on ${HOST}:${PORT}; storage=local`))).catch(err => { console.error("[PAK][FATAL]", err); process.exit(1); });
