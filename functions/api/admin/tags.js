// CRUD /api/admin/tags — 標籤管理
import { checkAdmin, parseJsonBody, validateId, requireMinRole } from '../_utils.js';

const COLOR_RE = /^#[0-9a-fA-F]{3,6}$/;

export async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const { results } = await env.DB.prepare(`
    SELECT t.*, (SELECT COUNT(*) FROM book_tags WHERE tag_id = t.id) as book_count
    FROM tags t ORDER BY t.name ASC
  `).all();
  return Response.json({ tags: results });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '示範管理員不能管理全域標籤' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  const { name, color } = body;
  if (!name || typeof name !== 'string' || !name.trim()) return Response.json({ error: 'Name required' }, { status: 400 });
  const safeName = name.trim().slice(0, 50);
  const safeColor = (color && COLOR_RE.test(color)) ? color : '#888';

  try {
    const r = await env.DB.prepare('INSERT INTO tags (name, color) VALUES (?, ?)').bind(safeName, safeColor).run();
    return Response.json({ success: true, tag: { id: r.meta.last_row_id, name: safeName, color: safeColor } }, { status: 201 });
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return Response.json({ error: 'Tag already exists' }, { status: 409 });
    return Response.json({ error: 'Failed to create tag' }, { status: 500 });
  }
}

export async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '示範管理員不能管理全域標籤' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: 'Tag id required' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: 'Invalid tag id' }, { status: 400 });

  const sets = [], vals = [];
  if (body.name) { sets.push('name = ?'); vals.push(body.name.trim().slice(0, 50)); }
  if (body.color) {
    if (!COLOR_RE.test(body.color)) return Response.json({ error: 'Invalid color format' }, { status: 400 });
    sets.push('color = ?'); vals.push(body.color);
  }
  if (sets.length === 0) return Response.json({ error: 'Nothing to update' }, { status: 400 });

  vals.push(body.id);
  await env.DB.prepare(`UPDATE tags SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  return Response.json({ success: true });
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireMinRole(auth, 'admin')) return Response.json({ error: '示範管理員不能管理全域標籤' }, { status: 403 });

  const body = await parseJsonBody(request);
  if (!body || !body.id) return Response.json({ error: 'Tag id required' }, { status: 400 });
  if (!validateId(String(body.id))) return Response.json({ error: 'Invalid tag id' }, { status: 400 });

  await env.DB.batch([
    env.DB.prepare('DELETE FROM book_tags WHERE tag_id = ?').bind(body.id),
    env.DB.prepare('DELETE FROM tags WHERE id = ?').bind(body.id),
  ]);
  return Response.json({ success: true });
}
