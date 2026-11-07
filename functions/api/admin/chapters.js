// POST /api/admin/chapters — 建立新章節
import { checkAdmin, validateId, parseJsonBody, checkBookOwnership, requireMinRole } from '../_utils.js';

const MAX_CONTENT_LENGTH = 500000; // 50萬字

export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    const status = auth.reason === 'locked' ? 429 : 401;
    const msg = auth.reason === 'locked' ? 'Too many failed attempts, try again later' : 'Unauthorized';
    return Response.json({ error: msg }, { status });
  }

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const { book_id, title, content, sort_order: clientSortOrder } = body;

  if (!book_id || !validateId(String(book_id))) {
    return Response.json({ error: 'Valid book_id is required' }, { status: 400 });
  }
  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return Response.json({ error: 'Title is required' }, { status: 400 });
  }
  if (title.length > 200) {
    return Response.json({ error: 'Title too long (max 200)' }, { status: 400 });
  }
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return Response.json({ error: 'Content is required' }, { status: 400 });
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return Response.json({ error: `Content too long (max ${MAX_CONTENT_LENGTH} chars)` }, { status: 400 });
  }

  const book = await env.DB.prepare('SELECT id FROM books WHERE id = ?')
    .bind(book_id).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  // demo只能往自己的書裡新增章節
  if (!await checkBookOwnership(auth, env, book_id)) {
    return Response.json({ error: '只能向自己建立的書籍新增章節' }, { status: 403 });
  }

  // demo 用戶配額：每本書最多 200 章
  if (!requireMinRole(auth, 'admin')) {
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM chapters WHERE book_id = ?'
    ).bind(book_id).first();
    if (count >= 200) return Response.json({ error: '示範帳號每本書最多 200 章' }, { status: 403 });
  }

  // sort_order：前端傳了就用前端的（批次匯入場景），否則自動遞增（單章新增場景）
  let sortOrder;
  if (clientSortOrder !== undefined && Number.isInteger(Number(clientSortOrder)) && Number(clientSortOrder) > 0 && Number(clientSortOrder) <= 2147483647) {
    sortOrder = Number(clientSortOrder);
  } else {
    const lastChapter = await env.DB.prepare(
      'SELECT MAX(sort_order) as max_order FROM chapters WHERE book_id = ?'
    ).bind(book_id).first();
    sortOrder = (lastChapter?.max_order || 0) + 1;
  }
  const wordCount = content.trim().length;

  // 先插入DB拿到chapterId，用占位content_key
  let chapterId;
  try {
    const result = await env.DB.prepare(`
      INSERT INTO chapters (book_id, title, sort_order, word_count, content_key)
      VALUES (?, ?, ?, ?, ?)
    `).bind(book_id, title.trim(), sortOrder, wordCount, 'pending').run();
    chapterId = result.meta.last_row_id;
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE')) {
      return Response.json({ success: true, duplicate: true, message: '章節已存在（重複請求）' });
    }
    return Response.json({ error: 'Failed to create chapter' }, { status: 500 });
  }

  // 用最終key寫R2（只寫一次）
  const contentKey = `novels/books/${book_id}/chapters/${chapterId}.txt`;
  try {
    await env.R2.put(contentKey, content.trim());
  } catch (err) {
    // R2失敗，回滾DB
    await env.DB.prepare('DELETE FROM chapters WHERE id = ?').bind(chapterId).run().catch(() => {});
    return Response.json({ error: 'Failed to store content' }, { status: 500 });
  }

  // 更新content_key為最終值
  try {
    await env.DB.prepare('UPDATE chapters SET content_key = ? WHERE id = ?')
      .bind(contentKey, chapterId).run();
  } catch (err) {
    // content_key更新失敗，回滾DB和R2
    await env.DB.prepare('DELETE FROM chapters WHERE id = ?').bind(chapterId).run().catch(() => {});
    await env.R2.delete(contentKey).catch(() => {});
    return Response.json({ error: 'Failed to finalize chapter' }, { status: 500 });
  }

  await env.DB.prepare("UPDATE books SET updated_at = datetime('now') WHERE id = ?")
    .bind(book_id).run();

  // demo章節配額二次檢查（防TOCTOU競態繞過）
  if (!requireMinRole(auth, 'admin')) {
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM chapters WHERE book_id = ?'
    ).bind(book_id).first();
    if (count > 200) {
      await env.DB.prepare('DELETE FROM chapters WHERE id = ?').bind(chapterId).run().catch(() => {});
      await env.R2.delete(contentKey).catch(() => {});
      return Response.json({ error: '示範帳號每本書最多 200 章' }, { status: 403 });
    }
  }

  return Response.json({
    success: true,
    chapter: { id: chapterId, title: title.trim(), sort_order: sortOrder, word_count: wordCount }
  }, { status: 201 });
}
