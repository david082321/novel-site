// DELETE /api/admin/account — demo用戶自助註銷
import { checkAdmin, requireMinRole } from '../_utils.js';

export async function onRequestDelete(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  // 只有 demo 用戶可以自助註銷
  if (requireMinRole(auth, 'admin')) {
    return Response.json({ error: '管理員及以上角色請聯絡超級管理員註銷' }, { status: 403 });
  }

  const userId = auth.userId;

  // 找到第一個 super_admin 作為內容接收者
  const superAdmin = await env.DB.prepare(
    "SELECT id FROM admin_users WHERE role = 'super_admin' ORDER BY id ASC LIMIT 1"
  ).first();

  if (!superAdmin) {
    return Response.json({ error: '系統異常：無超級管理員' }, { status: 500 });
  }

  // 原子操作：轉移內容所有權 + 清理用戶資料
  await env.DB.batch([
    // 轉移書籍所有權給第一個超管
    env.DB.prepare('UPDATE books SET created_by = ? WHERE created_by = ?').bind(superAdmin.id, userId),
    // 刪除所有 session
    env.DB.prepare('DELETE FROM admin_sessions WHERE user_id = ?').bind(userId),
    // 刪除用戶記錄
    env.DB.prepare('DELETE FROM admin_users WHERE id = ?').bind(userId),
  ]);

  return Response.json({
    success: true,
    message: '帳號已註銷，您建立的內容已轉交管理員保管'
  });
}
