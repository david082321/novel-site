// 管理員管理API（僅super_admin可用）
import { checkAdmin, requireSuperAdmin, validateId, hashPassword, parseJsonBody } from '../_utils.js';

// GET: 取得管理員列表
export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理用戶' }, { status: 403 });

  const { results } = await env.DB.prepare(
    `SELECT u.id, u.username, u.role, u.password_locked, u.github_id, u.github_login, u.avatar_url, u.created_at, u.updated_at,
      (SELECT COUNT(*) FROM books WHERE created_by = u.id) as book_count
    FROM admin_users u ORDER BY u.id`
  ).all();
  return Response.json({ admins: results });
}

// POST: 建立新管理員
export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理用戶' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: '無效的請求' }, { status: 400 });

  const { username, password, role, password_locked } = body;
  if (!username || !password) return Response.json({ error: '用戶名和密碼不能為空' }, { status: 400 });
  if (username.length < 2 || username.length > 32) return Response.json({ error: '用戶名長度2-32位' }, { status: 400 });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return Response.json({ error: '用戶名只能包含字母數字底線' }, { status: 400 });
  if (/^gh_/i.test(username)) return Response.json({ error: '用戶名不能以 gh_ 開頭（保留給 GitHub 登入用戶）' }, { status: 400 });
  if (password.length < 8) return Response.json({ error: '密碼至少8位' }, { status: 400 });
  if (password.length > 128) return Response.json({ error: '密碼最長128位' }, { status: 400 });
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) return Response.json({ error: '密碼需包含字母和數字' }, { status: 400 });

  const validRoles = ['super_admin', 'admin', 'demo'];
  const userRole = validRoles.includes(role) ? role : 'demo';
  const pwdLocked = password_locked === 1 ? 1 : 0;

  const existing = await env.DB.prepare('SELECT id FROM admin_users WHERE username = ?').bind(username).first();
  if (existing) return Response.json({ error: '用戶名已存在' }, { status: 409 });

  const passwordHash = await hashPassword(password);

  await env.DB.prepare("INSERT INTO admin_users (username, password_hash, role, password_locked) VALUES (?, ?, ?, ?)")
    .bind(username, passwordHash, userRole, pwdLocked).run();

  return Response.json({ success: true, message: `管理員 ${username} 建立成功` });
}

// DELETE: 刪除管理員
export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理用戶' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少用戶ID' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '無效的用戶ID' }, { status: 400 });

  // 不能刪除自己
  if (String(body.id) === String(auth.userId)) return Response.json({ error: '不能刪除自己' }, { status: 400 });

  const user = await env.DB.prepare('SELECT username, role FROM admin_users WHERE id = ?').bind(body.id).first();
  if (!user) return Response.json({ error: '用戶不存在' }, { status: 404 });

  // 保護最後一個super_admin
  if (user.role === 'super_admin') {
    const { count } = await env.DB.prepare("SELECT COUNT(*) as count FROM admin_users WHERE role = 'super_admin'").first();
    if (count <= 1) return Response.json({ error: '不能刪除最後一個超級管理員' }, { status: 400 });
  }

  // 將該用戶建立的書籍轉移給第一個超管，然後原子刪除
  const superAdmin = await env.DB.prepare(
    "SELECT id FROM admin_users WHERE role = 'super_admin' AND id != ? ORDER BY id ASC LIMIT 1"
  ).bind(body.id).first();
  const newOwner = superAdmin ? superAdmin.id : auth.userId;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(body.id),
    env.DB.prepare('UPDATE books SET created_by = ? WHERE created_by = ?').bind(newOwner, body.id),
    env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(body.id),
  ]);

  return Response.json({ success: true, message: `管理員 ${user.username} 已刪除` });
}

// 定義允許更新的欄位白名單及其驗證函式
const ALLOWED_UPDATE_FIELDS = {
  'role': {
    validate: (v) => ['super_admin', 'admin', 'demo'].includes(v),
    errorMsg: '無效的角色值'
  },
  'password_locked': {
    validate: (v) => v === 0 || v === 1,
    errorMsg: '無效的鎖定狀態'
  }
};

// PUT: 修改管理員角色
export async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理用戶' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: '缺少參數' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: '無效的用戶ID' }, { status: 400 });

  // 至少要有 role 或 password_locked 其中一個
  const hasRole = body.role !== undefined;
  const hasPwdLock = body.password_locked !== undefined;
  if (!hasRole && !hasPwdLock) return Response.json({ error: '缺少參數' }, { status: 400 });

  if (hasRole) {
    // 使用白名單驗證角色值
    if (!ALLOWED_UPDATE_FIELDS.role.validate(body.role)) {
      return Response.json({ error: ALLOWED_UPDATE_FIELDS.role.errorMsg }, { status: 400 });
    }

    // 不能降級自己
    if (String(body.id) === String(auth.userId) && body.role !== 'super_admin') {
      return Response.json({ error: '不能降級自己的權限' }, { status: 400 });
    }

    // 保護最後一個super_admin不被降級
    if (body.role !== 'super_admin') {
      const target = await env.DB.prepare('SELECT role FROM admin_users WHERE id = ?').bind(body.id).first();
      if (target && target.role === 'super_admin') {
        const { count } = await env.DB.prepare("SELECT COUNT(*) as count FROM admin_users WHERE role = 'super_admin'").first();
        if (count <= 1) return Response.json({ error: '不能降級最後一個超級管理員' }, { status: 400 });
      }
    }
  }

  // 驗證 password_locked 值
  if (hasPwdLock && !ALLOWED_UPDATE_FIELDS.password_locked.validate(body.password_locked)) {
    return Response.json({ error: ALLOWED_UPDATE_FIELDS.password_locked.errorMsg }, { status: 400 });
  }

  // 構建安全的更新語句 - 欄位名來自程式碼寫死，值透過參數化傳遞
  const sets = [];
  const binds = [];
  if (hasRole) { sets.push('role = ?'); binds.push(body.role); }
  if (hasPwdLock) { sets.push('password_locked = ?'); binds.push(body.password_locked === 1 ? 1 : 0); }
  sets.push("updated_at = datetime('now')");
  binds.push(body.id);

  await env.DB.prepare(`UPDATE admin_users SET ${sets.join(', ')} WHERE id = ?`)
    .bind(...binds).run();

  // 角色變更時清除目標用戶所有 session，強制重新登入
  if (hasRole) {
    await env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(body.id).run().catch(() => {});
  }

  return Response.json({ success: true });
}
