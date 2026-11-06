
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

const PROTOCOLS = ["ssh", "vmess", "vless", "trojan", "zivpn"];
const ACCOUNT_PACKAGE_DAYS = 30;
const ACCOUNT_PACKAGE_PRICE = 5000;
const MEMBER_BASE_IP = 2;
const MEMBER_EXTRA_IP_PRICE = 2000;
const V2RAY_PROTOCOLS = new Set(["vmess", "vless", "trojan"]);

// Gmail SMTP (gunakan Gmail App Password, bukan password Gmail utama).
const SMTP_USER = String(process.env.GMAIL_USER || "").trim();
const SMTP_PASS = String(process.env.GMAIL_APP_PASSWORD || "").replace(/\\s+/g, "");
const mailTransporter = SMTP_USER && SMTP_PASS
  ? nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    })
  : null;

// OTP disimpan sementara di memori; restart server otomatis membatalkan OTP aktif.
const pendingRegistrations = new Map();
const registrationRate = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(value) {
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,}$/.test(value) && value.length <= 254;
}

function otpDigest(email, code) {
  return crypto.createHmac("sha256", SESSION_SECRET)
    .update(`${email}:${code}`)
    .digest("hex");
}

function registrationIp(req) {
  return req.ip || req.socket.remoteAddress || "unknown";
}

function cleanApiKey(value) {
  return String(value || "")
    .trim()
    .replace(/^Authorization:\s*/i, "")
    .replace(/^Bearer\s+/i, "")
    .trim()
    .replace(/^("|')(.*)\1$/, "$2");
}

function cleanApiBase(value, fallback) {
  return String(value || fallback)
    .trim()
    .replace(/\/+$/, "")
    .replace(/\/ping$/i, "");
}

const SERVERS = {
  sg1: {
    id: "sg1",
    name: "Singapore 1",
    base: cleanApiBase(
      process.env.VPN_SG1_API_BASE_URL,
      "https://sg1.misubufuruvpn.my.id/api/v1"
    ),
    key: cleanApiKey(process.env.VPN_SG1_API_KEY)
  },
  sg2: {
    id: "sg2",
    name: "Singapore 2",
    base: cleanApiBase(
      process.env.VPN_SG2_API_BASE_URL ||
      process.env.SG2_API_BASE ||
      process.env.VPN_API_BASE_URL ||
      process.env.VPN_API_BASE,
      "https://sg2.misubufuruvpn.my.id/api/v1"
    ),
    key: cleanApiKey(
      process.env.VPN_SG2_API_KEY ||
      process.env.SG2_API_KEY ||
      process.env.VPN_API_KEY
    )
  },
  sg3: {
    id: "sg3",
    name: "Singapore 3",
    base: cleanApiBase(
      process.env.VPN_SG3_API_BASE_URL ||
      process.env.SG3_API_BASE,
      "https://sg3.misubufuruvpn.my.id/api/v1"
    ),
    key: cleanApiKey(
      process.env.VPN_SG3_API_KEY ||
      process.env.SG3_API_KEY
    )
  }
};

function validProto(proto) {
  return PROTOCOLS.includes(proto);
}

function validUsername(username) {
  return typeof username === "string" &&
    /^[A-Za-z0-9_.-]{1,32}$/.test(username);
}

function makeId() {
  return crypto.randomBytes(16).toString("hex");
}

function defaultDatabase() {
  return {
    users: [],
    accounts: [],
    ledger: [],
    prices: {
      ssh: 1000,
      vmess: 1000,
      vless: 1000,
      trojan: 1000,
      zivpn: 1000
    },
    settings: {
      trialLimit: 3
    }
  };
}

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(defaultDatabase(), null, 2)
  );
}

let db;

try {
  db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
} catch {
  throw new Error("database.json rusak atau tidak bisa dibaca.");
}

db.users ||= [];
db.accounts ||= [];
db.ledger ||= [];
db.prices ||= defaultDatabase().prices;
db.settings ||= { trialLimit: 3 };
// Normalize legacy balances so comparisons and arithmetic always use numbers.
for (const user of db.users) {
  const balance = Number(user.balance ?? 0);
  user.balance = Number.isFinite(balance) && balance >= 0 ? balance : 0;
}

// Semua perubahan database dijalankan berurutan agar tidak saling menimpa.
let writeQueue = Promise.resolve();
const accountCreationLocks = new Set();

function saveDatabase() {
  const tempFile = `${DB_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DB_FILE);
}

function mutateDatabase(callback) {
  const operation = writeQueue.then(async () => {
    const result = await callback();
    saveDatabase();
    return result;
  });

  writeQueue = operation.catch(() => {});
  return operation;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    balance: user.balance,
    servers: user.servers,
    active: user.active
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, user) {
  const hash = crypto.scryptSync(password, user.salt, 64);
  const original = Buffer.from(user.passwordHash, "hex");

  return original.length === hash.length &&
    crypto.timingSafeEqual(hash, original);
}

function signSession(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    exp: Date.now() + SESSION_TTL
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function verifySession(token) {
  if (!token || typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest();

  let supplied;

  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) return null;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!data.id || data.exp < Date.now()) return null;

    const user = db.users.find(
      item => item.id === data.id && item.active !== false
    );

    return user || null;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || "").split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");
    if (index < 0) continue;

    const key = item.slice(0, index).trim();
    if (key === name) {
      return decodeURIComponent(item.slice(index + 1).trim());
    }
  }

  return "";
}

function setSessionCookie(res, token) {
  const parts = [
    `vpn_session=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${Math.floor(SESSION_TTL / 1000)}`
  ];

  if (COOKIE_SECURE) parts.push("Secure");

  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = [
    "vpn_session=",
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0"
  ];

  if (COOKIE_SECURE) parts.push("Secure");

  res.setHeader("Set-Cookie", parts.join("; "));
}

function auth(req, res, next) {
  const user = verifySession(getCookie(req, "vpn_session"));

  if (!user) {
    return res.status(401).json({
      message: "Silakan login terlebih dahulu."
    });
  }

  req.user = user;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Akses khusus admin."
    });
  }

  next();
}

function checkOrigin(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const origin = req.get("Origin");

  if (origin) {
    try {
      if (new URL(origin).host !== req.get("Host")) {
        return res.status(403).json({
          message: "Origin tidak diizinkan."
        });
      }
    } catch {
      return res.status(403).json({
        message: "Origin tidak valid."
      });
    }
  }

  next();
}

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(checkOrigin);

// Login rate limit sederhana per alamat IP.
const loginAttempts = new Map();

function loginRateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (record && record.blockedUntil > now) {
    return res.status(429).json({
      message: "Terlalu banyak percobaan login. Coba lagi nanti."
    });
  }

  if (record && now - record.startedAt > 15 * 60 * 1000) {
    loginAttempts.delete(ip);
  }

  next();
}

// Admin pertama dibuat dari environment.
async function initializeAdmin() {
  const username = String(process.env.ADMIN_USERNAME || "admin").trim();
  const password = String(process.env.ADMIN_PASSWORD || "");

  if (password.length < 6) {
    throw new Error(
      "ADMIN_PASSWORD wajib diisi minimal 6 karakter di .env."
    );
  }

  const existing = db.users.find(user => user.role === "admin");

  if (existing) return;

  const credentials = hashPassword(password);

  db.users.push({
    id: makeId(),
    username,
    role: "admin",
    salt: credentials.salt,
    passwordHash: credentials.hash,
    balance: 0,
    servers: ["sg1", "sg2", "sg3"],
    active: true,
    createdAt: new Date().toISOString()
  });

  saveDatabase();
}

function selectedServer(req) {
  const id = String(
    req.get("X-VPN-Server") || "sg2"
  ).toLowerCase();

  return SERVERS[id] || null;
}

function checkServerAccess(req, res) {
  const server = selectedServer(req);

  if (!server) {
    res.status(400).json({ message: "Server tidak valid." });
    return null;
  }

  if (
    req.user.role !== "admin" &&
    !req.user.servers.includes(server.id)
  ) {
    res.status(403).json({
      message: "Kamu tidak memiliki akses ke server ini."
    });
    return null;
  }

  return server;
}

async function vpnRequest(server, route, options = {}) {
  if (!server) {
    const error = new Error("Server tidak valid.");
    error.status = 400;
    throw error;
  }

  if (!server.key) {
    const error = new Error(
      `API key ${server.id.toUpperCase()} belum diatur di .env.`
    );
    error.status = 503;
    throw error;
  }

  let response;

  try {
    response = await fetch(`${server.base}${route}`, {
      method: options.method || "GET",
      headers: {
        Authorization: `Bearer ${server.key}`,
        Accept: "application/json",
        ...(options.body ? {
          "Content-Type": "application/json"
        } : {})
      },
      signal: AbortSignal.timeout(20000),
      ...(options.body ? {
        body: JSON.stringify(options.body)
      } : {})
    });
  } catch (error) {
    const err = new Error(
      `Tidak bisa menghubungi API ${server.id.toUpperCase()}: ${error.name === "TimeoutError" ? "koneksi timeout" : (error.cause?.code || error.message || "periksa koneksi dan URL API")}.`
    );
    err.status = 502;
    throw err;
  }

  const raw = await response.text();

  let data;

  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = {
      message: raw.slice(0, 500) ||
        `Respons API kosong (HTTP ${response.status}).`
    };
  }

  const failed =
    data.status === "error" ||
    data.success === false ||
    data.ok === false;

  if (!response.ok || failed) {
    let message =
      data.message ||
      data.error ||
      data.detail ||
      `API menolak permintaan (HTTP ${response.status}).`;

    if (typeof message !== "string") {
      message = JSON.stringify(message);
    }

    const error = new Error(message);
    error.status = response.status || 502;
    throw error;
  }

  return data;
}

function errorResponse(res, error) {
  return res.status(error.status || 502).json({
    message: error.message || "Permintaan gagal."
  });
}

function accountKey(server, proto, username) {
  return `${server}:${proto}:${username.toLowerCase()}`;
}

function findOwnedAccount(server, proto, username) {
  return db.accounts.find(account =>
    account.key === accountKey(server, proto, username)
  );
}

function canManageAccount(req, server, proto, username) {
  if (req.user.role === "admin") return true;

  const account = findOwnedAccount(server.id, proto, username);

  return !!account && account.ownerId === req.user.id;
}

function getPrice(proto, days = 30, ipLimit = MEMBER_BASE_IP) {
  if (!validProto(proto)) return 0;

  const basePrice = Number(days) === 7 ? 2000 : 5000;
  const extraIps = Math.max(
    0,
    Number(ipLimit || MEMBER_BASE_IP) - MEMBER_BASE_IP
  );

  return basePrice + extraIps * MEMBER_EXTRA_IP_PRICE;
}

function extractUsername(value, depth = 0) {
  if (!value || depth > 5) return null;

  if (typeof value === "string") {
    return validUsername(value) ? value : null;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = extractUsername(item, depth + 1);
      if (found) return found;
    }
    return null;
  }

  if (typeof value === "object") {
    for (const key of [
      "username",
      "user",
      "account",
      "data",
      "result"
    ]) {
      if (value[key] !== undefined) {
        const found = extractUsername(value[key], depth + 1);
        if (found) return found;
      }
    }
  }

  return null;
}

function utcDay() {
  return new Date().toISOString().slice(0, 10);
}

function trialCount(userId) {
  return db.ledger.filter(item =>
    item.userId === userId &&
    item.type === "trial" &&
    item.day === utcDay()
  ).length;
}

async function chargeBalance(userId, amount, description) {
  return mutateDatabase(() => {
    const user = db.users.find(item => item.id === userId);

    const currentBalance = Number(user?.balance ?? 0);
    if (!user || !Number.isFinite(currentBalance) || currentBalance < amount) {
      const error = new Error("Saldo tidak mencukupi. Saldo saat ini: Rp" + (Number.isFinite(currentBalance) ? currentBalance.toLocaleString("id-ID") : "0") + ". Biaya: Rp" + amount.toLocaleString("id-ID") + ".");
      error.status = 402;
      throw error;
    }

    user.balance = currentBalance - amount;

    db.ledger.push({
      id: makeId(),
      userId,
      type: "debit",
      amount,
      description,
      balanceAfter: user.balance,
      createdAt: new Date().toISOString()
    });

    return user.balance;
  });
}

async function refundBalance(userId, amount, description) {
  if (!amount) return;

  await mutateDatabase(() => {
    const user = db.users.find(item => item.id === userId);
    if (!user) return;

    user.balance = Number(user.balance || 0) + Number(amount);

    db.ledger.push({
      id: makeId(),
      userId,
      type: "refund",
      amount,
      description,
      balanceAfter: user.balance,
      createdAt: new Date().toISOString()
    });
  });
}

// --------------------------------------------------
// AUTH
// --------------------------------------------------

// Registrasi member mandiri: kirim OTP ke email Gmail.
app.post("/api/auth/register/request-otp", async (req, res) => {
  if (!mailTransporter) {
    return res.status(503).json({
      message: "Fitur email belum dikonfigurasi. Admin perlu mengatur GMAIL_USER dan GMAIL_APP_PASSWORD di .env."
    });
  }

  const username = String(req.body?.username || "").trim();
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");
  const ip = registrationIp(req);
  const now = Date.now();

  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({ message: "Username harus 3–32 karakter (huruf, angka, titik, _ atau -)." });
  }
  if (!validEmail(email)) {
    return res.status(400).json({ message: "Alamat email tidak valid." });
  }
  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({ message: "Password harus 6–128 karakter." });
  }

  const rate = registrationRate.get(ip);
  if (rate && rate.count >= 5 && now - rate.startedAt < 60 * 60 * 1000) {
    return res.status(429).json({ message: "Terlalu banyak permintaan OTP dari jaringan ini. Coba lagi nanti." });
  }

  const previous = pendingRegistrations.get(email);
  if (previous && previous.expiresAt > now && previous.lastSentAt + OTP_RESEND_MS > now) {
    return res.status(429).json({ message: "Tunggu 60 detik sebelum meminta kode OTP lagi." });
  }

  if (db.users.some(user =>
    user.username.toLowerCase() === username.toLowerCase() ||
    (user.email && user.email.toLowerCase() === email)
  )) {
    return res.status(409).json({ message: "Username atau email sudah terdaftar." });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const credentials = hashPassword(password);
  const expiresAt = now + OTP_TTL_MS;

  try {
    await mailTransporter.sendMail({
      from: `"VPN Control" <${SMTP_USER}>`,
      to: email,
      subject: "Kode verifikasi VPN Control",
      text: `Kode OTP registrasi VPN Control kamu: ${code}\\n\\nKode berlaku selama 10 menit. Jangan bagikan kode ini kepada siapa pun.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;color:#172033"><h2>Verifikasi email VPN Control</h2><p>Gunakan kode berikut untuk menyelesaikan pendaftaran:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px;padding:16px;background:#eef3fb;border-radius:12px;text-align:center">${code}</div><p>Kode berlaku selama 10 menit. Jangan bagikan kode ini kepada siapa pun.</p></div>`
    });

    pendingRegistrations.set(email, {
      username,
      email,
      salt: credentials.salt,
      passwordHash: credentials.hash,
      otpHash: otpDigest(email, code),
      expiresAt,
      lastSentAt: now,
      attempts: 0
    });

    const currentRate = rate && now - rate.startedAt < 60 * 60 * 1000
      ? rate
      : { count: 0, startedAt: now };
    currentRate.count++;
    registrationRate.set(ip, currentRate);

    return res.json({
      message: "Kode OTP berhasil dikirim. Periksa inbox atau folder spam Gmail kamu.",
      expiresIn: 600,
      resendAfter: 60
    });
  } catch (error) {
    console.error("Gagal mengirim email OTP:", error.message);
    return res.status(502).json({ message: "Gagal mengirim email OTP. Periksa konfigurasi Gmail pengirim." });
  }
});

app.post("/api/auth/register/verify", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.otp || "").trim();

  if (!validEmail(email) || !/^\\d{6}$/.test(code)) {
    return res.status(400).json({ message: "Email atau kode OTP tidak valid." });
  }

  const pending = pendingRegistrations.get(email);
  if (!pending || pending.expiresAt < Date.now()) {
    pendingRegistrations.delete(email);
    return res.status(400).json({ message: "Kode OTP kedaluwarsa atau belum diminta. Minta kode baru." });
  }

  pending.attempts++;
  if (pending.attempts > OTP_MAX_ATTEMPTS) {
    pendingRegistrations.delete(email);
    return res.status(429).json({ message: "Batas percobaan OTP terlampaui. Minta kode baru." });
  }

  const supplied = Buffer.from(otpDigest(email, code), "hex");
  const expected = Buffer.from(pending.otpHash, "hex");
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(400).json({ message: `Kode OTP salah. Sisa percobaan: ${OTP_MAX_ATTEMPTS - pending.attempts}.` });
  }

  try {
    const user = await mutateDatabase(() => {
      if (db.users.some(item =>
        item.username.toLowerCase() === pending.username.toLowerCase() ||
        (item.email && item.email.toLowerCase() === email)
      )) {
        const error = new Error("Username atau email sudah terdaftar. Silakan login.");
        error.status = 409;
        throw error;
      }

      const newUser = {
        id: makeId(),
        username: pending.username,
        email,
        role: "member",
        salt: pending.salt,
        passwordHash: pending.passwordHash,
        balance: 0,
        servers: ["sg2"],
        active: true,
        emailVerified: true,
        createdAt: new Date().toISOString()
      };

      db.users.push(newUser);
      return newUser;
    });

    pendingRegistrations.delete(email);
    setSessionCookie(res, signSession(user));
    return res.status(201).json({
      message: "Email berhasil diverifikasi. Akun member kamu sudah aktif.",
      user: publicUser(user)
    });
  } catch (error) {
    errorResponse(res, error);
  }
});

app.post("/api/auth/login", loginRateLimit, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  const user = db.users.find(item =>
    item.username.toLowerCase() === username.toLowerCase()
  );

  if (
    !user ||
    user.active === false ||
    !verifyPassword(password, user)
  ) {
    const now = Date.now();
    let record = loginAttempts.get(ip);

    if (!record || now - record.startedAt > 15 * 60 * 1000) {
      record = {
        count: 0,
        startedAt: now,
        blockedUntil: 0
      };
    }

    record.count++;

    if (record.count >= 5) {
      record.blockedUntil = now + 15 * 60 * 1000;
    }

    loginAttempts.set(ip, record);

    return res.status(401).json({
      message: "Username atau password salah."
    });
  }

  loginAttempts.delete(ip);
  setSessionCookie(res, signSession(user));

  res.json({
    user: publicUser(user)
  });
});

app.post("/api/auth/logout", auth, (req, res) => {
  clearSessionCookie(res);
  res.json({ message: "Berhasil logout." });
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// --------------------------------------------------
// MEMBER AREA
// --------------------------------------------------

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: publicUser(req.user),
    prices: Object.fromEntries(PROTOCOLS.map(proto => [proto, ACCOUNT_PACKAGE_PRICE])),
    packageDays: ACCOUNT_PACKAGE_DAYS,
    packagePrice: ACCOUNT_PACKAGE_PRICE,
    trialLimit: db.settings.trialLimit
  });
});

app.get("/api/servers", auth, (req, res) => {
  const allowed = req.user.role === "admin"
    ? ["sg1", "sg2", "sg3"]
    : req.user.servers;

  res.json({
    servers: allowed.map(id => {
      const server = SERVERS[id];

      return {
        id: server.id,
        name: server.name,
        configured: !!server.key
      };
    })
  });
});

// --------------------------------------------------
// ADMIN: MEMBERS
// --------------------------------------------------

app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  res.json({
    users: db.users
      .filter(user => user.role === "member")
      .map(publicUser)
  });
});

app.post("/api/admin/users", auth, adminOnly, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const servers = req.body?.servers;

  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({
      message: "Username harus 3–32 karakter."
    });
  }

  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({
      message: "Password member harus 6–128 karakter."
    });
  }

  if (
    !Array.isArray(servers) ||
    servers.length < 1 ||
    servers.some(id => !SERVERS[id])
  ) {
    return res.status(400).json({
      message: "Pilih minimal satu server yang valid."
    });
  }

  try {
    const user = await mutateDatabase(() => {
      if (db.users.some(item =>
        item.username.toLowerCase() === username.toLowerCase()
      )) {
        const error = new Error("Username sudah digunakan.");
        error.status = 409;
        throw error;
      }

      const credentials = hashPassword(password);

      const newUser = {
        id: makeId(),
        username,
        role: "member",
        salt: credentials.salt,
        passwordHash: credentials.hash,
        balance: 0,
        servers: [...new Set(servers)],
        active: true,
        createdAt: new Date().toISOString()
      };

      db.users.push(newUser);
      return publicUser(newUser);
    });

    res.status(201).json({ user });
  } catch (error) {
    errorResponse(res, error);
  }
});

app.patch("/api/admin/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const user = await mutateDatabase(() => {
      const target = db.users.find(item =>
        item.id === req.params.id && item.role === "member"
      );

      if (!target) {
        const error = new Error("Member tidak ditemukan.");
        error.status = 404;
        throw error;
      }

      if (Array.isArray(req.body?.servers)) {
        const servers = req.body.servers;

        if (
          servers.length < 1 ||
          servers.some(id => !SERVERS[id])
        ) {
          const error = new Error("Daftar server tidak valid.");
          error.status = 400;
          throw error;
        }

        target.servers = [...new Set(servers)];
      }

      if (typeof req.body?.active === "boolean") {
        target.active = req.body.active;
      }

      if (req.body?.password) {
        const password = String(req.body.password);

        if (password.length < 6 || password.length > 128) {
          const error = new Error("Password harus 6–128 karakter.");
          error.status = 400;
          throw error;
        }

        const credentials = hashPassword(password);
        target.salt = credentials.salt;
        target.passwordHash = credentials.hash;
      }

      return publicUser(target);
    });

    res.json({ user });
  } catch (error) {
    errorResponse(res, error);
  }
});

app.delete("/api/admin/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const removed = await mutateDatabase(() => {
      const index = db.users.findIndex(item =>
        item.id === req.params.id && item.role === "member"
      );

      if (index === -1) {
        const error = new Error("Member tidak ditemukan.");
        error.status = 404;
        throw error;
      }

      const [user] = db.users.splice(index, 1);

      return {
        id: user.id,
        username: user.username
      };
    });

    res.json({
      message: `Member ${removed.username} berhasil dihapus.`,
      user: removed
    });
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// ADMIN: BALANCE & PRICES
// --------------------------------------------------

app.post(
  "/api/admin/users/:id/balance",
  auth,
  adminOnly,
  async (req, res) => {
    const amount = Number(req.body?.amount);
    const note = String(req.body?.note || "Penyesuaian saldo admin");

    if (!Number.isSafeInteger(amount) || amount === 0) {
      return res.status(400).json({
        message: "Nominal harus bilangan bulat dan tidak boleh nol."
      });
    }

    try {
      const result = await mutateDatabase(() => {
        const user = db.users.find(item =>
          item.id === req.params.id && item.role === "member"
        );

        if (!user) {
          const error = new Error("Member tidak ditemukan.");
          error.status = 404;
          throw error;
        }

        const currentBalance = Number(user.balance ?? 0);
        if (!Number.isFinite(currentBalance) || currentBalance + amount < 0) {
          const error = new Error("Saldo tidak boleh negatif.");
          error.status = 400;
          throw error;
        }

        user.balance = currentBalance + amount;

        db.ledger.push({
          id: makeId(),
          userId: user.id,
          type: amount > 0 ? "credit" : "debit_admin",
          amount: Math.abs(amount),
          note,
          balanceAfter: user.balance,
          adminId: req.user.id,
          createdAt: new Date().toISOString()
        });

        return publicUser(user);
      });

      res.json({ user: result });
    } catch (error) {
      errorResponse(res, error);
    }
  }
);

app.get("/api/admin/prices", auth, adminOnly, (req, res) => {
  res.json({ prices: Object.fromEntries(PROTOCOLS.map(proto => [proto, ACCOUNT_PACKAGE_PRICE])) });
});

app.put("/api/admin/prices", auth, adminOnly, (req, res) => {
  res.status(403).json({ message: "Harga paket dikunci: 30 hari / Rp5.000." });
});

app.get("/api/admin/ledger", auth, adminOnly, (req, res) => {
  res.json({
    ledger: [...db.ledger].reverse().slice(0, 500)
  });
});

// --------------------------------------------------
// VPN SERVER STATUS
// --------------------------------------------------

app.get("/api/ping", auth, async (req, res) => {
  const server = checkServerAccess(req, res);
  if (!server) return;

  try {
    res.json(await vpnRequest(server, "/ping"));
  } catch (error) {
    errorResponse(res, error);
  }
});


app.get("/api/server", auth, async (req, res) => {
  const server = checkServerAccess(req, res);
  if (!server) return;

  try {
    res.json(await vpnRequest(server, "/server"));
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// VPN ACCOUNT LIST
// --------------------------------------------------

app.get("/api/accounts/:proto", auth, async (req, res) => {
  const { proto } = req.params;

  if (!validProto(proto)) {
    return res.status(400).json({ message: "Protocol tidak valid." });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  try {
    if (req.user.role === "admin") {
      return res.json(
        await vpnRequest(server, `/${proto}/accounts`)
      );
    }

    const accounts = db.accounts.filter(account =>
      account.ownerId === req.user.id &&
      account.server === server.id &&
      account.proto === proto
    );

    res.json({ accounts });
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// CREATE ACCOUNT WITH BALANCE
// --------------------------------------------------

app.post("/api/accounts/:proto", auth, async (req, res) => {
  const { proto } = req.params;

  if (!validProto(proto)) {
    return res.status(400).json({ message: "Protocol tidak valid." });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  const {
    username,
    password,
    uuid,
    days,
    ip_limit,
    quota_gb
  } = req.body || {};

  if (!validUsername(username)) {
    return res.status(400).json({
      message: "Username hanya boleh 1–32 karakter: huruf, angka, titik, _ atau -."
    });
  }

  const nDays = Number(days);
  const nIp = Number(ip_limit ?? 0);
  const nQuota = Number(quota_gb ?? 0);

  if (req.user.role === "member" && ![7, 30].includes(nDays)) {
    return res.status(400).json({ message: "Member hanya bisa membuat akun 7 atau 30 hari." });
  }
  if (req.user.role === "admin" && (!Number.isInteger(nDays) || nDays < 1 || nDays > 3650)) {
    return res.status(400).json({ message: "Masa aktif admin harus 1–3650 hari." });
  }

  if (!Number.isInteger(nIp) || nIp < (req.user.role === "member" ? 2 : 0) || nIp > 1000) {
    return res.status(400).json({
      message: "Batas IP harus 0–1000."
    });
  }

  if (!Number.isFinite(nQuota) || nQuota < 0 || nQuota > 100000) {
    return res.status(400).json({
      message: "Kuota harus 0 atau lebih."
    });
  }

  if (
    proto === "ssh" &&
    (typeof password !== "string" ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(password))
  ) {
    return res.status(400).json({
      message: "Password SSH wajib 1–64 karakter."
    });
  }

  if (
    proto === "zivpn" &&
    password &&
    !/^[A-Za-z0-9_-]{1,64}$/.test(password)
  ) {
    return res.status(400).json({
      message: "Password ZiVPN tidak valid."
    });
  }

  const key = accountKey(server.id, proto, username);

  if (db.accounts.some(account => account.key === key)) {
    return res.status(409).json({
      message: "Username ini sudah tercatat di panel."
    });
  }

  const price = getPrice(proto, nDays, nIp);

  if (!Number.isSafeInteger(price) || price < 0) {
    return res.status(400).json({
      message: "Harga akun tidak valid."
    });
  }

  if (accountCreationLocks.has(key)) {
    return res.status(409).json({
      message: "Permintaan akun ini sedang diproses. Tunggu sebentar dan jangan klik Buat Akun berulang kali."
    });
  }
  accountCreationLocks.add(key);

  let charged = false;

  try {
    if (req.user.role === "member" && price > 0) {
      await chargeBalance(
        req.user.id,
        price,
        `Buat akun ${proto} ${username} di ${server.id.toUpperCase()}`
      );
      charged = true;
    }

    // Member V2Ray packages have fixed base quotas; extra IPs scale quota proportionally.
   const effectiveQuota = req.user.role === "member" && V2RAY_PROTOCOLS.has(proto)
  ? Math.round((nDays === 7 ? 30 : 250) * (nIp / MEMBER_BASE_IP))
  : nQuota;

const body = {
  username,
  days: nDays,
  ip_limit: nIp,
  quota_gb: effectiveQuota
};

    if (proto === "ssh") body.password = password;
    if (proto === "zivpn" && password) body.password = password;

    if (
      uuid &&
      ["vmess", "vless", "trojan"].includes(proto)
    ) {
      body.uuid = uuid;
    }

    const result = await vpnRequest(
      server,
      `/${proto}/accounts`,
      { method: "POST", body }
    );

    await mutateDatabase(() => {
      db.accounts.push({
        id: makeId(),
        key,
        ownerId: req.user.id,
        username,
        proto,
        server: server.id,
        price,
        ip_limit: nIp,
        days: nDays,
        quota_gb: effectiveQuota,
        createdAt: new Date().toISOString()
      });
    });

    res.status(201).json({
      result,
      charged: req.user.role === "member" ? price : 0
    });
  } catch (error) {
    if (charged) {
      await refundBalance(
        req.user.id,
        price,
        `Refund pembuatan akun ${username} gagal`
      );
    }

    errorResponse(res, error);
  } finally {
    accountCreationLocks.delete(key);
  }
});

// --------------------------------------------------
// TRIAL: MAXIMUM 3 PER MEMBER PER UTC DAY
// --------------------------------------------------

app.post("/api/accounts/:proto/trial", auth, async (req, res) => {
  const { proto } = req.params;

  if (!validProto(proto)) {
    return res.status(400).json({ message: "Protocol tidak valid." });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  const minutes = Number(req.body?.minutes ?? 60);

  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
    return res.status(400).json({
      message: "Durasi trial 1–1440 menit."
    });
  }

  if (req.user.role === "member") {
    if (trialCount(req.user.id) >= db.settings.trialLimit) {
      return res.status(429).json({
        message: `Batas trial ${db.settings.trialLimit} akun per hari sudah tercapai.`
      });
    }
  }

  try {
    const result = await vpnRequest(
      server,
      `/${proto}/trial`,
      {
        method: "POST",
        body: { minutes }
      }
    );

    const username = extractUsername(result);

    await mutateDatabase(() => {
      db.ledger.push({
        id: makeId(),
        userId: req.user.id,
        type: "trial",
        day: utcDay(),
        server: server.id,
        proto,
        username,
        createdAt: new Date().toISOString()
      });

      if (username) {
        const key = accountKey(server.id, proto, username);

        if (!db.accounts.some(account => account.key === key)) {
          db.accounts.push({
            id: makeId(),
            key,
            ownerId: req.user.id,
            username,
            proto,
            server: server.id,
            trial: true,
            createdAt: new Date().toISOString()
          });
        }
      }
    });

    res.status(201).json({
      result,
      remaining:
        req.user.role === "admin"
          ? null
          : Math.max(0, db.settings.trialLimit - trialCount(req.user.id))
    });
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// ACCOUNT DETAIL
// --------------------------------------------------

app.get("/api/accounts/:proto/:username", auth, async (req, res) => {
  const { proto, username } = req.params;

  if (!validProto(proto) || !validUsername(username)) {
    return res.status(400).json({
      message: "Protocol atau username tidak valid."
    });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  if (!canManageAccount(req, server, proto, username)) {
    return res.status(404).json({
      message: "Akun tidak ditemukan."
    });
  }

  try {
    res.json(await vpnRequest(
      server,
      `/${proto}/accounts/${encodeURIComponent(username)}`
    ));
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// RENEW ACCOUNT
// --------------------------------------------------

app.post(
  "/api/accounts/:proto/:username/renew",
  auth,
  async (req, res) => {
    const { proto, username } = req.params;
    const days = Number(req.body?.days);

    if (!validProto(proto) || !validUsername(username)) {
      return res.status(400).json({
        message: "Protocol atau username tidak valid."
      });
    }

    const server = checkServerAccess(req, res);
    if (!server) return;

    const account = findOwnedAccount(server.id, proto, username);

    if (!canManageAccount(req, server, proto, username)) {
      return res.status(404).json({
        message: "Akun tidak ditemukan."
      });
    }

    if (req.user.role === "member") {
      if (![7, 30].includes(days)) {
        return res.status(400).json({
          message: "Member hanya bisa renew selama 7 atau 30 hari."
        });
      }
    } else if (!Number.isInteger(days) || days < 1 || days > 3650) {
      return res.status(400).json({
        message: "Durasi renew admin harus 1–3650 hari."
      });
    }

    const storedIpLimit = Number(account?.ip_limit ?? MEMBER_BASE_IP);
    const ipLimit = Number.isInteger(storedIpLimit) &&
      storedIpLimit >= 0 && storedIpLimit <= 1000
      ? storedIpLimit
      : MEMBER_BASE_IP;

    const price = req.user.role === "member"
      ? getPrice(proto, days, ipLimit)
      : 0;

    let charged = false;

    try {
      if (price > 0) {
        await chargeBalance(
          req.user.id,
          price,
          `Perpanjang ${proto} ${username} selama ${days} hari (${ipLimit} IP)`
        );
        charged = true;
      }

      const result = await vpnRequest(
        server,
        `/${proto}/accounts/${encodeURIComponent(username)}/renew`,
        {
          method: "POST",
          body: { days }
        }
      );

      res.json({
        result,
        charged: req.user.role === "member" ? price : 0,
        days,
        ip_limit: ipLimit
      });
    } catch (error) {
      if (charged) {
        try {
          await refundBalance(
            req.user.id,
            price,
            `Refund perpanjangan ${username} gagal`
          );
        } catch (refundError) {
          console.error("Gagal mengembalikan saldo setelah renew gagal:", refundError);
        }
      }

      errorResponse(res, error);
    }
  }
);

// --------------------------------------------------
// LOCK / UNLOCK
// --------------------------------------------------

for (const action of ["lock", "unlock"]) {
  app.post(
    `/api/accounts/:proto/:username/${action}`,
    auth,
    async (req, res) => {
      const { proto, username } = req.params;

      if (!validProto(proto) || !validUsername(username)) {
        return res.status(400).json({
          message: "Protocol atau username tidak valid."
        });
      }

      const server = checkServerAccess(req, res);
      if (!server) return;

      if (
        req.user.role !== "admin" &&
        !canManageAccount(req, server, proto, username)
      ) {
        return res.status(404).json({
          message: "Akun tidak ditemukan."
        });
      }

      try {
        res.json(await vpnRequest(
          server,
          `/${proto}/accounts/${encodeURIComponent(username)}/${action}`,
          {
            method: "POST",
            body: {}
          }
        ));
      } catch (error) {
        errorResponse(res, error);
      }
    }
  );
}

// --------------------------------------------------
// DELETE ACCOUNT
// --------------------------------------------------

app.delete("/api/accounts/:proto/:username", auth, async (req, res) => {
  const { proto, username } = req.params;

  if (!validProto(proto) || !validUsername(username)) {
    return res.status(400).json({
      message: "Protocol atau username tidak valid."
    });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  if (!canManageAccount(req, server, proto, username)) {
    return res.status(404).json({
      message: "Akun tidak ditemukan."
    });
  }

  try {
    const result = await vpnRequest(
      server,
      `/${proto}/accounts/${encodeURIComponent(username)}`,
      { method: "DELETE" }
    );

    await mutateDatabase(() => {
      db.accounts = db.accounts.filter(account =>
        account.key !== accountKey(server.id, proto, username)
      );
    });

    res.json(result);
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// ONLINE ACCOUNTS
// --------------------------------------------------

app.get("/api/online/:proto", auth, async (req, res) => {
  const { proto } = req.params;

  if (!validProto(proto)) {
    return res.status(400).json({ message: "Protocol tidak valid." });
  }

  const server = checkServerAccess(req, res);
  if (!server) return;

  try {
    const result = await vpnRequest(server, `/${proto}/online`);

    if (req.user.role === "admin") {
      return res.json(result);
    }

    const owned = new Set(
      db.accounts
        .filter(account =>
          account.ownerId === req.user.id &&
          account.server === server.id &&
          account.proto === proto
        )
        .map(account => account.username.toLowerCase())
    );

    function filterOnline(value) {
      if (Array.isArray(value)) {
        return value.filter(item => {
          const username =
            typeof item === "string"
              ? item
              : item?.username || item?.user;

          return username && owned.has(String(username).toLowerCase());
        });
      }

      if (value && typeof value === "object") {
        const output = { ...value };

        for (const key of Object.keys(output)) {
          if (Array.isArray(output[key])) {
            output[key] = filterOnline(output[key]);
          }
        }

        return output;
      }

      return value;
    }

    res.json(filterOnline(result));
  } catch (error) {
    errorResponse(res, error);
  }
});

// --------------------------------------------------
// FRONTEND
// --------------------------------------------------

app.use(express.static(path.join(__dirname, "public"), {
  setHeaders(res, filePath) {
    const ext = require("path").extname(filePath).toLowerCase();

    if (ext === ".html") {
      res.setHeader("Cache-Control", "no-store");
    } else if (ext === ".js" || ext === ".css") {
      res.setHeader("Cache-Control", "no-cache, must-revalidate");
    }
  }
}));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --------------------------------------------------
// START
// --------------------------------------------------

initializeAdmin()
  .then(() => {
    if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
      throw new Error(
        "SESSION_SECRET wajib diisi minimal 32 karakter di .env."
      );
    }

    app.listen(PORT, HOST, () => {
      console.log(`VPN dashboard running at http://${HOST}:${PORT}`);
      console.log("Role system: Admin + Member");
      console.log("Servers: SG1 + SG2 + SG3");
    });
  })
  .catch(error => {
    console.error("Gagal menjalankan server:", error.message);
    process.exit(1);
  });
