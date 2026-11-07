// PUT /api/admin/book-tags — 設定書籍標籤
import { checkAdmin, parseJsonBody, validateId, checkBookOwnership } from '../_utils.js';

export async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await parseJsonBody(request);
  if (!body || !body.book_id) return Response.json({ error: 'book_id required' }, { status: 400 });
  if (!validateId(String(body.book_id))) return Response.json({ error: 'Invalid book_id' }, { status: 400 });
  if (!Array.isArray(body.tag_ids)) return Response.json({ error: 'tag_ids array required' }, { status: 400 });
  if (body.tag_ids.length > 20) return Response.json({ error: '最多 20 個標籤' }, { status: 400 });

  // 驗證每個 tag_id
  for (const tagId of body.tag_ids) {
    if (!validateId(String(tagId))) return Response.json({ error: 'Invalid tag_id: ' + tagId }, { status: 400 });
  }

  const bookId = body.book_id;

  // demo只能給自己的書打標籤
  if (!await checkBookOwnership(auth, env, bookId)) {
    return Response.json({ error: '只能管理自己書籍的標籤' }, { status: 403 });
  }

  // 驗證tag_id確實存在於tags表中，過濾無效ID
  let validTagIds = body.tag_ids;
  if (validTagIds.length > 0) {
    const placeholders = validTagIds.map(() => '?').join(',');
    const { results: validTags } = await env.DB.prepare(
      `SELECT id FROM tags WHERE id IN (${placeholders})`
    ).bind(...validTagIds.map(Number)).all();
    const validSet = new Set(validTags.map(t => t.id));
    validTagIds = validTagIds.filter(id => validSet.has(Number(id)));
  }

  // 原子操作：先刪後插
  const stmts = [
    env.DB.prepare('DELETE FROM book_tags WHERE book_id = ?').bind(bookId),
    ...validTagIds.map(tagId =>
      env.DB.prepare('INSERT OR IGNORE INTO book_tags (book_id, tag_id) VALUES (?, ?)').bind(bookId, tagId)
    ),
  ];
  await env.DB.batch(stmts);

  return Response.json({ success: true });
}
