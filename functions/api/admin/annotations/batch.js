import { checkAdmin } from '../../_utils.js';

// POST /api/admin/annotations/batch - 批次操作
export async function onRequestPost(context) {
  const { request, env } = context;
  
  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '請先登入' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'invalid JSON' }, { status: 400 });
  }

  const { ids, action } = body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return Response.json({ error: '請選擇要操作的批註' }, { status: 400 });
  }
  if (ids.length > 100) {
    return Response.json({ error: '單次最多操作100條' }, { status: 400 });
  }
  if (!['remove', 'restore'].includes(action)) {
    return Response.json({ error: '無效的操作' }, { status: 400 });
  }

  // 驗證所有 ID 格式
  for (const id of ids) {
    if (!/^\d{1,18}$/.test(String(id))) {
      return Response.json({ error: '無效的批註ID' }, { status: 400 });
    }
  }

  const newStatus = action === 'remove' ? 'removed' : 'normal';
  const placeholders = ids.map(() => '?').join(',');

  // 根據權限構建過濾條件
  let permFilter = '';
  const permBinds = [];
  
  if (auth.role === 'admin') {
    // admin 不能操作超管的批註
    permFilter = `AND a.id IN (
      SELECT a2.id FROM annotations a2
      LEFT JOIN admin_users u2 ON a2.user_id = u2.id
      WHERE u2.role != 'super_admin' OR u2.role IS NULL
    )`;
  } else if (auth.role === 'demo') {
    // demo 只能操作自己的批註或自己書上的 demo 批註
    permFilter = `AND a.id IN (
      SELECT a2.id FROM annotations a2
      LEFT JOIN admin_users u2 ON a2.user_id = u2.id
      LEFT JOIN books b2 ON a2.book_id = b2.id
      WHERE a2.user_id = ? OR (b2.created_by = ? AND u2.role = 'demo')
    )`;
    permBinds.push(auth.userId, auth.userId);
  }

  const result = await env.DB.prepare(`
    UPDATE annotations a
    SET status = ?, updated_at = datetime('now')
    WHERE id IN (${placeholders}) ${permFilter}
  `).bind(newStatus, ...ids, ...permBinds).run();

  return Response.json({ 
    success: true, 
    affected: result.meta.changes 
  });
}
