// PUT /api/admin/books/:id — 編輯書籍
// DELETE /api/admin/books/:id — 軟刪除書籍（30天後自動清理）
// POST /api/admin/books/:id — 狀態變更（上架/下架/復原/永久刪除）
import { checkAdmin, validateId, parseJsonBody, checkBookOwnership, requireMinRole } from '../../_utils.js';

async function authCheck(request, env) {
  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    const status = auth.reason === 'locked' ? 429 : 401;
    const msg = auth.reason === 'locked' ? 'Too many failed attempts, try again later' : 'Unauthorized';
    return { denied: Response.json({ error: msg }, { status }) };
  }
  return { auth };
}

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { denied, auth } = await authCheck(request, env);
  if (denied) return denied;
  if (!validateId(params.id)) return Response.json({ error: 'Invalid ID' }, { status: 400 });

  const book = await env.DB.prepare('SELECT * FROM books WHERE id = ?').bind(params.id).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  // demo只能編輯自己的書
  if (!await checkBookOwnership(auth, env, params.id)) {
    return Response.json({ error: '只能編輯自己建立的書籍' }, { status: 403 });
  }

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const title = (body.title || book.title || '').trim().slice(0, 200);
  const author = (body.author ?? book.author ?? '').trim().slice(0, 100);
  const description = (body.description ?? book.description ?? '').trim().slice(0, 2000);

  // 批註開關：只接受 0 或 1
  const annotationEnabled = body.annotation_enabled === 1 || body.annotation_enabled === true ? 1 : (body.annotation_enabled === 0 || body.annotation_enabled === false ? 0 : (book.annotation_enabled || 0));

  await env.DB.prepare(`
    UPDATE books SET title = ?, author = ?, description = ?, annotation_enabled = ?, updated_at = datetime('now') WHERE id = ?
  `).bind(title, author, description, annotationEnabled, params.id).run();

  return Response.json({ success: true });
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { denied, auth } = await authCheck(request, env);
  if (denied) return denied;
  if (!validateId(params.id)) return Response.json({ error: 'Invalid ID' }, { status: 400 });

  const book = await env.DB.prepare('SELECT * FROM books WHERE id = ?').bind(params.id).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  if (!await checkBookOwnership(auth, env, params.id)) {
    return Response.json({ error: '只能刪除自己建立的書籍' }, { status: 403 });
  }

  // 🔴-3: 已在回收站的書不能重複軟刪除（防 delete_at 無限續期）
  const currentStatus = book.status || 'normal';
  if (currentStatus === 'deleted') {
    return Response.json({ error: '書籍已在回收站中' }, { status: 400 });
  }

  // 軟刪除：標記為 deleted，30天後自動清理
  const deleteAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare(
    "UPDATE books SET status = 'deleted', delete_at = ?, updated_at = datetime('now') WHERE id = ?"
  ).bind(deleteAt, params.id).run();

  return Response.json({ success: true, message: '書籍已移入回收站，30天後自動刪除', delete_at: deleteAt });
}

// POST /api/admin/books/:id — 狀態變更
const VALID_ACTIONS = ['unlist', 'restore', 'purge'];

export async function onRequestPost(context) {
  const { request, env, params } = context;
  const { denied, auth } = await authCheck(request, env);
  if (denied) return denied;
  if (!validateId(params.id)) return Response.json({ error: 'Invalid ID' }, { status: 400 });

  const book = await env.DB.prepare('SELECT * FROM books WHERE id = ?').bind(params.id).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  if (!await checkBookOwnership(auth, env, params.id)) {
    return Response.json({ error: '只能操作自己建立的書籍' }, { status: 403 });
  }

  const body = await parseJsonBody(request);
  if (!body || !body.action) return Response.json({ error: 'Missing action' }, { status: 400 });

  const { action } = body;
  // 🟡-6: 入口白名單校驗
  if (!VALID_ACTIONS.includes(action)) {
    return Response.json({ error: 'Unknown action' }, { status: 400 });
  }

  const currentStatus = book.status || 'normal';

  if (action === 'unlist') {
    // 🔴-1: 只有 normal 狀態可以下架
    if (currentStatus !== 'normal') {
      return Response.json({ error: '只有正常狀態的書籍可以下架' }, { status: 400 });
    }
    await env.DB.prepare(
      "UPDATE books SET status = 'unlisted', delete_at = NULL, updated_at = datetime('now') WHERE id = ?"
    ).bind(params.id).run();
    return Response.json({ success: true, message: '書籍已下架' });
  }

  if (action === 'restore') {
    // 🔴-2: 只有 unlisted/deleted 可以復原
    if (currentStatus === 'normal') {
      return Response.json({ error: '書籍已是正常狀態' }, { status: 400 });
    }
    await env.DB.prepare(
      "UPDATE books SET status = 'normal', delete_at = NULL, updated_at = datetime('now') WHERE id = ?"
    ).bind(params.id).run();
    return Response.json({ success: true, message: '書籍已復原上架' });
  }

  if (action === 'purge') {
    // 🟡-1: 只有 deleted 狀態可以永久刪除
    if (currentStatus !== 'deleted') {
      return Response.json({ error: '只能永久刪除已在回收站中的書籍' }, { status: 400 });
    }
    if (!requireMinRole(auth, 'super_admin')) {
      return Response.json({ error: '僅超級管理員可永久刪除' }, { status: 403 });
    }
    // 先刪 DB（batch 原子），再刪 R2（🟡-2: 順序調整）
    const { results: chapters } = await env.DB.prepare('SELECT content_key FROM chapters WHERE book_id = ?')
      .bind(params.id).all();
    const r2Keys = chapters.map(c => c.content_key);
    if (book.cover_key) r2Keys.push(book.cover_key);

    await env.DB.batch([
      env.DB.prepare('DELETE FROM chapter_stats WHERE chapter_id IN (SELECT id FROM chapters WHERE book_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM book_stats WHERE book_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM book_tags WHERE book_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM votes WHERE annotation_id IN (SELECT id FROM annotations WHERE book_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM reports WHERE book_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM annotation_likes WHERE annotation_id IN (SELECT id FROM annotations WHERE book_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM annotations WHERE book_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM chapters WHERE book_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM books WHERE id = ?').bind(params.id),
    ]);
    // R2 刪除在 DB 之後，失敗不影響資料一致性
    await Promise.all(r2Keys.map(k => env.R2.delete(k).catch(() => {})));
    return Response.json({ success: true, message: '書籍已永久刪除' });
  }
}
