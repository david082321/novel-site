// ===== P3修复：常量定义（消除魔法数字） =====

// 密码哈希相关常量
const PBKDF2_ITERATIONS = 100000;  // PBKDF2迭代次数，平衡安全性与性能
const SALT_LENGTH = 16;            // 盐值长度（字节）
const HASH_LENGTH = 256;           // 哈希输出长度（位）

// 会话相关常量
const SESSION_MAX_AGE_DAYS = 7;                    // 会话最大有效期（天）
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;  // 毫秒
const MAX_SESSIONS_PER_USER = 10;                  // 单用户最大活跃会话数

// 认证限流常量
const AUTH_MAX_ATTEMPTS = 5;                       // 最大失败尝试次数
const AUTH_LOCK_DURATION_MS = 10 * 60 * 1000;      // 锁定时长（10分钟）

// Token相关常量
const TOKEN_LENGTH = 32;           // Token长度（字节）

// 清理概率
const CLEANUP_PROBABILITY = 0.1;   // 每次请求清理过期数据的概率（10%）

// ===== 密码哈希（PBKDF2 + 随机盐） =====

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, key, HASH_LENGTH
  );
  const hashHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = [...salt].map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  // 兼容旧格式（纯64位hex = 无盐SHA-256）→ 验证后自动迁移
  if (!stored.startsWith('pbkdf2:')) {
    const oldHash = await sha256Legacy(password);
    const a = new TextEncoder().encode(oldHash);
    const b = new TextEncoder().encode(stored);
    let diff = a.length ^ b.length;
    for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] || 0) ^ (b[i] || 0);
    return { match: diff === 0, needsMigration: true };
  }
  const [, iterations, saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: Number(iterations), hash: 'SHA-256' }, key, 256
  );
  const computed = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  let diff = computed.length ^ hashHex.length;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ (hashHex.charCodeAt(i) || 0);
  return { match: diff === 0, needsMigration: false };
}

async function sha256Legacy(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const bytes = new Uint8Array(TOKEN_LENGTH);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

// SHA-256哈希（用于token和IP的存储哈希）
export async function sha256Hash(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== Schema迁移（兼容旧数据库） =====

let _schemaEnsured = false;

async function ensureSchema(env) {
  if (_schemaEnsured) return;
  try {
    try {
      await env.DB.prepare('ALTER TABLE admin_users ADD COLUMN password_locked INTEGER DEFAULT 0').run();
    } catch {}
    // 书籍所有者
    try {
      await env.DB.prepare('ALTER TABLE books ADD COLUMN created_by INTEGER DEFAULT NULL').run();
    } catch {}
    // 书籍封面
    try {
      await env.DB.prepare('ALTER TABLE books ADD COLUMN cover_key TEXT DEFAULT NULL').run();
    } catch {}
    // 标签系统
    try {
      await env.DB.prepare('CREATE TABLE IF NOT EXISTS tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, color TEXT DEFAULT \'#888\')').run();
    } catch {}
    try {
      await env.DB.prepare('CREATE TABLE IF NOT EXISTS book_tags (book_id INTEGER, tag_id INTEGER, PRIMARY KEY (book_id, tag_id))').run();
    } catch {}
    // GitHub OAuth
    try {
      await env.DB.prepare('ALTER TABLE admin_users ADD COLUMN github_id INTEGER DEFAULT NULL').run();
    } catch {}
    try {
      await env.DB.prepare('ALTER TABLE admin_users ADD COLUMN github_login TEXT DEFAULT NULL').run();
    } catch {}
    try {
      await env.DB.prepare('ALTER TABLE admin_users ADD COLUMN avatar_url TEXT DEFAULT NULL').run();
    } catch {}
    try {
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_github_id ON admin_users(github_id) WHERE github_id IS NOT NULL').run();
    } catch {}
    // 章节乐观锁版本号
    try {
      await env.DB.prepare('ALTER TABLE chapters ADD COLUMN version INTEGER DEFAULT 0').run();
    } catch {}
    // 章节排序唯一约束（防重试导致重复章节）
    try {
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_chapters_book_sort ON chapters(book_id, sort_order)').run();
    } catch {}
    // 书籍状态：normal(正常) / unlisted(下架) / deleted(待删除)
    try {
      await env.DB.prepare("ALTER TABLE books ADD COLUMN status TEXT DEFAULT 'normal'").run();
    } catch {}
    // 书籍定时删除时间
    try {
      await env.DB.prepare('ALTER TABLE books ADD COLUMN delete_at TEXT DEFAULT NULL').run();
    } catch {}
    // 🟢-4: 回填已有书籍的 status（ALTER TABLE 不回填默认值到已有行）
    try {
      await env.DB.prepare("UPDATE books SET status = 'normal' WHERE status IS NULL").run();
    } catch {}

    // ===== 批注系统 v2 =====
    // 批注主表
    try {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS annotations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chapter_id INTEGER NOT NULL,
        book_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        para_idx INTEGER NOT NULL,
        sent_idx INTEGER NOT NULL,
        sent_hash TEXT NOT NULL,
        sent_text TEXT NOT NULL,
        content TEXT NOT NULL,
        visibility TEXT NOT NULL DEFAULT 'public',
        status TEXT NOT NULL DEFAULT 'normal',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE,
        FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES admin_users(id)
      )`).run();
    } catch {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_anno_chapter ON annotations(chapter_id, para_idx, sent_idx)').run(); } catch {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_anno_book ON annotations(book_id, status)').run(); } catch {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_anno_user ON annotations(user_id, created_at)').run(); } catch {}
    // 书籍批注开关
    try { await env.DB.prepare('ALTER TABLE books ADD COLUMN annotation_enabled INTEGER NOT NULL DEFAULT 0').run(); } catch {}
    try { await env.DB.prepare('ALTER TABLE books ADD COLUMN annotation_locked INTEGER NOT NULL DEFAULT 0').run(); } catch {}

    // 所有迁移成功完成，标记为已完成
    _schemaEnsured = true;
  } catch (e) {
    // DB不可用等严重错误，不设标志，下次请求重试
    console.error('ensureSchema failed:', e);
  }
}

// ===== 默认管理员（拒绝无密码创建） =====

async function ensureDefaultAdmin(env) {
  if (!env.ADMIN_PASSWORD) {
    console.error('FATAL: ADMIN_PASSWORD env not set, refusing to create default admin');
    return;
  }
  try {
    const existing = await env.DB.prepare('SELECT id FROM admin_users WHERE username = ?').bind('admin').first();
    if (existing) return;
    const hash = await hashPassword(env.ADMIN_PASSWORD);
    await env.DB.prepare("INSERT OR IGNORE INTO admin_users (username, password_hash, role) VALUES (?, ?, 'super_admin')")
      .bind('admin', hash).run();
  } catch {}
}

// Cookie 工具函数
export function makeAuthCookie(token) {
  return `auth_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`;
}

export function clearAuthCookie() {
  return 'auth_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

function getTokenFromRequest(request) {
  // 优先从 cookie 读取
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)auth_token=([^;]+)/);
  if (match && match[1] && match[1].length >= 10) return match[1];
  // fallback: Bearer header
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    if (token && token.length >= 10) return token;
  }
  return null;
}

// ===== Session验证 =====

export async function checkAdmin(request, env) {
  await ensureSchema(env);

  const token = getTokenFromRequest(request);
  if (!token) return { ok: false, reason: 'missing' };

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hash(ip);
  const locked = await isIpLocked(env, ipHash);
  if (locked) return { ok: false, reason: 'locked' };

  // 对token做哈希后查找
  const tokenHash = await sha256Hash(token);
  const session = await env.DB.prepare(
    "SELECT s.user_id, s.expires_at, u.username, u.role, u.password_locked FROM admin_sessions s JOIN admin_users u ON s.user_id = u.id WHERE s.token = ?"
  ).bind(tokenHash).first();

  if (!session) return { ok: false, reason: 'invalid_token' };
  if (new Date(session.expires_at) < new Date()) {
    await env.DB.prepare('DELETE FROM admin_sessions WHERE token = ?').bind(tokenHash).run();
    return { ok: false, reason: 'expired' };
  }

  // 按概率清理过期session和限流记录
  if (Math.random() < CLEANUP_PROBABILITY) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at < datetime('now')").run().catch(() => {});
    await env.DB.prepare("DELETE FROM auth_attempts WHERE last_attempt < datetime('now', '-1 day')").run().catch(() => {});
    await env.DB.prepare("DELETE FROM site_settings WHERE key LIKE 'oauth_state:%' AND value < datetime('now')").run().catch(() => {});
  }

    // 兼容旧角色：editor → admin
  const role = session.role === 'editor' ? 'admin' : (session.role || 'demo');
  return { ok: true, userId: session.user_id, username: session.username, role, passwordLocked: session.password_locked === 1, _token: token };
}

// ===== 登录 =====

export async function login(env, username, password, ip) {
  const ipHash = await sha256Hash(ip);
  const locked = await isIpLocked(env, ipHash);
  if (locked) return { ok: false, reason: 'locked' };

  await ensureDefaultAdmin(env);

  const user = await env.DB.prepare('SELECT id, password_hash, role FROM admin_users WHERE username = ?')
    .bind(username).first();

  if (!user) {
    await recordFailedAttempt(env, ipHash);
    // 同时记录 username 维度限流
    const usernameHash = await sha256Hash('user:' + username);
    await recordFailedAttempt(env, usernameHash);
    return { ok: false, reason: 'wrong' };
  }

  // 检查 username 维度限流
  const usernameHash = await sha256Hash('user:' + username);
  const userLocked = await isIpLocked(env, usernameHash);
  if (userLocked) return { ok: false, reason: 'locked' };

  // GitHub OAuth 用户不能用密码登录
  if (user.password_hash === 'github_oauth:no_password') {
    return { ok: false, reason: 'github_only' };
  }

  const result = await verifyPassword(password, user.password_hash);

  if (!result.match) {
    await recordFailedAttempt(env, ipHash);
    await recordFailedAttempt(env, usernameHash);
    return { ok: false, reason: 'wrong' };
  }

  if (result.needsMigration) {
    const newHash = await hashPassword(password);
    await env.DB.prepare("UPDATE admin_users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(newHash, user.id).run().catch(() => {});
  }

  await clearFailedAttempts(env, ipHash);
  await clearFailedAttempts(env, usernameHash);

  // token明文返回客户端，DB只存哈希
  const token = generateToken();
  const tokenHash = await sha256Hash(token);
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();
  await env.DB.prepare('INSERT INTO admin_sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, user.id, expiresAt).run();

  // 限制单用户最大活跃会话数，删除最旧的
  await env.DB.prepare(
    `DELETE FROM admin_sessions WHERE user_id = ? AND token NOT IN (SELECT token FROM admin_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ${MAX_SESSIONS_PER_USER})`
  ).bind(user.id, user.id).run().catch(() => {});

  await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at < datetime('now')").run().catch(() => {});
  await env.DB.prepare("DELETE FROM auth_attempts WHERE last_attempt < datetime('now', '-1 day')").run().catch(() => {});

  const loginRole = user.role === 'editor' ? 'admin' : (user.role || 'demo');
  return { ok: true, token, username: user.username, role: loginRole, userId: user.id, expiresAt };
}

// ===== 修改密码 =====

export async function changePassword(env, userId, oldPassword, newPassword) {
  const user = await env.DB.prepare('SELECT password_hash FROM admin_users WHERE id = ?')
    .bind(userId).first();
  if (!user) return { ok: false, reason: 'not_found' };

  const result = await verifyPassword(oldPassword, user.password_hash);
  if (!result.match) return { ok: false, reason: 'wrong_old' };

  if (!newPassword || newPassword.length < 8) return { ok: false, reason: 'too_short' };
  if (newPassword.length > 128) return { ok: false, reason: 'too_long' };
  if (!/[a-zA-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
    return { ok: false, reason: 'too_weak' };
  }

  const newHash = await hashPassword(newPassword);
  await env.DB.prepare("UPDATE admin_users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
    .bind(newHash, userId).run();

  await env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(userId).run();

  return { ok: true };
}

// ===== IP限流 =====

async function isIpLocked(env, ip) {
  try {
    const r = await env.DB.prepare('SELECT fail_count, locked_until FROM auth_attempts WHERE ip_hash = ?')
      .bind(ip).first();
    if (!r) return false;
    return r.locked_until && new Date(r.locked_until) > new Date();
  } catch { return true; } // fail-closed: DB异常时拒绝登录
}

async function recordFailedAttempt(env, ip) {
  try {
    const r = await env.DB.prepare('SELECT fail_count, locked_until FROM auth_attempts WHERE ip_hash = ?')
      .bind(ip).first();
    if (!r) {
      await env.DB.prepare("INSERT INTO auth_attempts (ip_hash, fail_count, last_attempt) VALUES (?, 1, datetime('now'))")
        .bind(ip).run();
      return;
    }
    if (r.locked_until && new Date(r.locked_until) <= new Date()) {
      await env.DB.prepare("UPDATE auth_attempts SET fail_count = 1, locked_until = NULL, last_attempt = datetime('now') WHERE ip_hash = ?")
        .bind(ip).run();
      return;
    }
    const n = r.fail_count + 1;
    if (n >= AUTH_MAX_ATTEMPTS) {
      const lock = new Date(Date.now() + AUTH_LOCK_DURATION_MS).toISOString();
      await env.DB.prepare("UPDATE auth_attempts SET fail_count = ?, locked_until = ?, last_attempt = datetime('now') WHERE ip_hash = ?")
        .bind(n, lock, ip).run();
    } else {
      await env.DB.prepare("UPDATE auth_attempts SET fail_count = ?, last_attempt = datetime('now') WHERE ip_hash = ?")
        .bind(n, ip).run();
    }
  } catch {}
}

async function clearFailedAttempts(env, ip) {
  try { await env.DB.prepare('DELETE FROM auth_attempts WHERE ip_hash = ?').bind(ip).run(); } catch {}
}

// ===== 工具函数 =====
export function validateId(id) { return /^\d{1,18}$/.test(id) && Number(id) > 0; }

// 角色层级：super_admin > admin > demo（editor是admin的旧名，兼容）
const ROLE_LEVEL = { super_admin: 3, admin: 2, editor: 2, demo: 1 };

export function requireSuperAdmin(auth) {
  return auth.role === 'super_admin';
}

// 检查是否满足最低角色要求
export function requireMinRole(auth, minRole) {
  return (ROLE_LEVEL[auth.role] || 0) >= (ROLE_LEVEL[minRole] || 99);
}

// demo角色的书籍所有权检查：返回true表示允许操作
export async function checkBookOwnership(auth, env, bookId) {
  // admin及以上不受限
  if (requireMinRole(auth, 'admin')) return true;
  // demo只能操作自己创建的书
  const book = await env.DB.prepare('SELECT created_by FROM books WHERE id = ?').bind(bookId).first();
  if (!book) return false; // 书不存在
  return book.created_by === auth.userId;
}

export async function parseJsonBody(request) {
  try { return await request.json(); } catch { return null; }
}

// ===== GitHub OAuth 工具 =====

export async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function hmacVerify(data, signature, secret) {
  const expected = await hmacSign(data, secret);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

// 为 GitHub 用户创建 session（复用现有 token 机制）
export async function createSession(env, userId) {
  const token = generateToken();
  const tokenHash = await sha256Hash(token);
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();
  await env.DB.prepare('INSERT INTO admin_sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, userId, expiresAt).run();
  // 限制单用户最大活跃会话数
  await env.DB.prepare(
    `DELETE FROM admin_sessions WHERE user_id = ? AND token NOT IN (SELECT token FROM admin_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ${MAX_SESSIONS_PER_USER})`
  ).bind(userId, userId).run().catch(() => {});
  return { token, expiresAt };
}

// GitHub OAuth secret：优先环境变量（更安全），fallback到DB
export async function getGitHubClientSecret(env) {
  if (env.GITHUB_CLIENT_SECRET) return env.GITHUB_CLIENT_SECRET;
  const row = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'github_client_secret'").first();
  return row?.value || null;
}

// 确保批注表存在（供未认证API调用）
let _annoSchemaEnsured = false;
export async function ensureAnnotationSchema(env) {
  if (_annoSchemaEnsured) return;
  try {
    // Phase 1: annotations + likes
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS annotations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      chapter_id INTEGER NOT NULL,
      book_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      para_idx INTEGER NOT NULL,
      sent_idx INTEGER NOT NULL,
      sent_hash TEXT NOT NULL,
      sent_text TEXT NOT NULL,
      content TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'private',
      status TEXT NOT NULL DEFAULT 'normal',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE,
      FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES admin_users(id)
    )`).run();
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_anno_chapter ON annotations(chapter_id, para_idx, sent_idx)').run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS annotation_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      annotation_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(annotation_id, user_id),
      FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES admin_users(id)
    )`).run();

    // Phase 3: reports + votes + score_logs + mutes
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      annotation_id INTEGER NOT NULL,
      book_id INTEGER NOT NULL,
      reporter_id INTEGER,
      reporter_guest_hash TEXT,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      handler_id INTEGER,
      handler_action TEXT,
      threshold_reached_at TEXT,
      escalated_at TEXT,
      handled_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE,
      FOREIGN KEY (reporter_id) REFERENCES admin_users(id)
    )`).run();
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_reports_annotation ON reports(annotation_id, status)').run();
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_reports_book ON reports(book_id, status)').run();

    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS votes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      annotation_id INTEGER NOT NULL,
      admin_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      reason TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(annotation_id, admin_id),
      FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE,
      FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    )`).run();

    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS score_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      delta REAL NOT NULL,
      reason TEXT NOT NULL,
      related_annotation_id INTEGER,
      related_report_id INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES admin_users(id)
    )`).run();
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_score_user ON score_logs(user_id, created_at)').run();

    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS mutes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      reason TEXT NOT NULL,
      related_annotation_id INTEGER,
      duration_minutes INTEGER,
      starts_at TEXT NOT NULL DEFAULT (datetime('now')),
      ends_at TEXT,
      lifted_by INTEGER,
      lifted_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES admin_users(id)
    )`).run();

    // admin_users 新字段 (ALTER TABLE 忽略已存在的列错误)
    const alterCols = [
      'score REAL NOT NULL DEFAULT 0',
      'violation_count INTEGER NOT NULL DEFAULT 0',
      'last_violation_at TEXT',
      'consecutive_neglect_count INTEGER NOT NULL DEFAULT 0',
      'lock_count INTEGER NOT NULL DEFAULT 0',
      'locked_until TEXT',
      'banned_at TEXT',
      'appeal_count INTEGER NOT NULL DEFAULT 0',
      'muted_until TEXT'
    ];
    for (const col of alterCols) {
      try {
        await env.DB.prepare(`ALTER TABLE admin_users ADD COLUMN ${col}`).run();
      } catch (_) { /* column already exists */ }
    }

    // 补充缺失索引
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_user ON admin_sessions(user_id)').run(); } catch (_) {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_mutes_user ON mutes(user_id, ends_at)').run(); } catch (_) {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_likes_user ON annotation_likes(user_id)').run(); } catch (_) {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_votes_annotation ON votes(annotation_id, admin_id)').run(); } catch (_) {}

    _annoSchemaEnsured = true;
  } catch (e) {
    console.error('ensureAnnotationSchema failed:', e);
  }
}

// ===== P2修复：统一错误响应格式 =====
// 标准错误响应格式，确保API返回一致的错误结构
//
// 使用示例：
// return errorResponse(400, '參數錯誤', 'INVALID_PARAM', { field: 'book_id' });
// return errorResponse(404, '書籍不存在', 'NOT_FOUND');
// return errorResponse(500, '伺服器內部錯誤');

export function errorResponse(status, message, code = null, details = null) {
  const response = {
    error: message,
    success: false
  };
  
  // 可选的错误码（便于前端国际化处理）
  if (code) {
    response.code = code;
  }
  
  // 可选的详细信息（调试用，生产环境可省略）
  if (details) {
    response.details = details;
  }
  
  return Response.json(response, { status });
}

// 常用错误响应快捷函数
export const Errors = {
  badRequest: (message = '請求參數錯誤', details = null) =>
    errorResponse(400, message, 'BAD_REQUEST', details),
  
  unauthorized: (message = '未授權，請先登入') =>
    errorResponse(401, message, 'UNAUTHORIZED'),
  
  forbidden: (message = '權限不足') =>
    errorResponse(403, message, 'FORBIDDEN'),
  
  notFound: (message = '資源不存在') =>
    errorResponse(404, message, 'NOT_FOUND'),
  
  conflict: (message = '資源衝突') =>
    errorResponse(409, message, 'CONFLICT'),
  
  tooManyRequests: (message = '請求過於頻繁，請稍後再試') =>
    errorResponse(429, message, 'RATE_LIMITED'),
  
  internal: (message = '伺服器內部錯誤') =>
    errorResponse(500, message, 'INTERNAL_ERROR'),
  
  serviceUnavailable: (message = '服務暫時不可用') =>
    errorResponse(503, message, 'SERVICE_UNAVAILABLE')
};

// 成功响应格式化（可选使用）
export function successResponse(data, meta = null) {
  const response = {
    success: true,
    ...data
  };
  
  if (meta) {
    response.meta = meta;
  }
  
  return Response.json(response);
}
