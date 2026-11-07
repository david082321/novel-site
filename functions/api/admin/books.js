// POST /api/admin/books — 建立新書籍
import { checkAdmin, parseJsonBody, requireMinRole } from '../_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    const status = auth.reason === 'locked' ? 429 : 401;
    const msg = auth.reason === 'locked' ? 'Too many failed attempts, try again later' : 'Unauthorized';
    return Response.json({ error: msg }, { status });
  }

  // demo 用戶配額：最多 10 本書
  if (!requireMinRole(auth, 'admin')) {
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM books WHERE created_by = ?'
    ).bind(auth.userId).first();
    if (count >= 10) return Response.json({ error: '示範帳號最多建立 10 本書' }, { status: 403 });
  }

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const { title, description, author } = body;

  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return Response.json({ error: 'Title is required' }, { status: 400 });
  }
  if (title.length > 200) {
    return Response.json({ error: 'Title too long (max 200)' }, { status: 400 });
  }

  const result = await env.DB.prepare(`
    INSERT INTO books (title, description, author, created_by) VALUES (?, ?, ?, ?)
  `).bind(
    title.trim(),
    (typeof description === 'string' ? description : '').trim().slice(0, 2000),
    (typeof author === 'string' ? author : '').trim().slice(0, 100),
    auth.userId
  ).run();

  // demo配額二次檢查（防TOCTOU競態繞過）
  if (!requireMinRole(auth, 'admin')) {
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM books WHERE created_by = ?'
    ).bind(auth.userId).first();
    if (count > 10) {
      await env.DB.prepare('DELETE FROM books WHERE id = ?').bind(result.meta.last_row_id).run().catch(() => {});
      return Response.json({ error: '示範帳號最多建立 10 本書' }, { status: 403 });
    }
  }

  return Response.json({
    success: true,
    book: { id: result.meta.last_row_id, title: title.trim() }
  }, { status: 201 });
}
