import { checkAdmin } from '../../_utils.js';

// PUT /api/admin/annotations/[id] - 修改批註狀態（移除/復原）
export async function onRequestPut(context) {
  const { request, env, params } = context;
  const annoId = params.id;

  if (!/^\d{1,18}$/.test(annoId)) {
    return Response.json({ error: 'invalid id' }, { status: 400 });
  }

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '請先登入' }, { status: 401 });
  }

  // 取得批註資訊
  const anno = await env.DB.prepare(`
    SELECT a.*, u.role as user_role, b.created_by as book_owner
    FROM annotations a
    LEFT JOIN admin_users u ON a.user_id = u.id
    LEFT JOIN books b ON a.book_id = b.id
    WHERE a.id = ?
  `).bind(annoId).first();

  if (!anno) {
    return Response.json({ error: '批註不存在' }, { status: 404 });
  }

  // 權限檢查
  if (auth.role === 'demo') {
    // demo 只能操作自己的批註或自己書上的 demo 批註
    const canOperate = anno.user_id === auth.userId || 
      (anno.book_owner === auth.userId && anno.user_role === 'demo');
    if (!canOperate) {
      return Response.json({ error: '無權操作此批註' }, { status: 403 });
    }
  } else if (auth.role === 'admin') {
    // admin 不能操作超管的批註
    if (anno.user_role === 'super_admin') {
      return Response.json({ error: '無權操作超級管理員的批註' }, { status: 403 });
    }
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'invalid JSON' }, { status: 400 });
  }

  const { status } = body;
  if (!['normal', 'removed', 'hidden'].includes(status)) {
    return Response.json({ error: '無效的狀態' }, { status: 400 });
  }

  await env.DB.prepare(`
    UPDATE annotations SET status = ?, updated_at = datetime('now') WHERE id = ?
  `).bind(status, annoId).run();

  return Response.json({ success: true, status });
}

// DELETE /api/admin/annotations/[id] - 永久刪除批註（僅超管）
export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const annoId = params.id;

  if (!/^\d{1,18}$/.test(annoId)) {
    return Response.json({ error: 'invalid id' }, { status: 400 });
  }

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '請先登入' }, { status: 401 });
  }

  // 僅超管可永久刪除
  if (auth.role !== 'super_admin') {
    return Response.json({ error: '僅超級管理員可永久刪除批註' }, { status: 403 });
  }

  // 檢查批註是否存在且已移除
  const anno = await env.DB.prepare('SELECT status FROM annotations WHERE id = ?').bind(annoId).first();
  if (!anno) {
    return Response.json({ error: '批註不存在' }, { status: 404 });
  }
  if (anno.status !== 'removed') {
    return Response.json({ error: '只能永久刪除已移除的批註' }, { status: 400 });
  }

  // 刪除相關按讚
  await env.DB.prepare('DELETE FROM annotation_likes WHERE annotation_id = ?').bind(annoId).run();
  // 刪除批註
  await env.DB.prepare('DELETE FROM annotations WHERE id = ?').bind(annoId).run();

  return Response.json({ success: true });
}
