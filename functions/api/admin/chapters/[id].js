// PUT /api/admin/chapters/:id — 编辑章节
// DELETE /api/admin/chapters/:id — 删除章节
import { checkAdmin, validateId, parseJsonBody, checkBookOwnership } from '../../_utils.js';

const MAX_CONTENT_LENGTH = 500000;

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
  if (!validateId(params.id)) return Response.json({ error: 'Invalid chapter ID' }, { status: 400 });

  const chapter = await env.DB.prepare('SELECT * FROM chapters WHERE id = ?').bind(params.id).first();
  if (!chapter) return Response.json({ error: 'Chapter not found' }, { status: 404 });

  // demo只能编辑自己书的章节
  if (!await checkBookOwnership(auth, env, chapter.book_id)) {
    return Response.json({ error: '只能編輯自己書籍的章節' }, { status: 403 });
  }

  const body = await parseJsonBody(request);
  if (!body) return Response.json({ error: 'Invalid JSON' }, { status: 400 });

  const { title, content, version } = body;

  // 樂觀鎖：編輯內容時必須攜帶version欄位
  const currentVersion = chapter.version || 0;
  if (content && version === undefined) {
    return Response.json({ error: '請提供 version 欄位以防止並發衝突' }, { status: 400 });
  }
  if (version !== undefined && Number(version) !== currentVersion) {
    return Response.json({ error: '內容已被其他人修改，請重新整理後重試' }, { status: 409 });
  }

  if (title && typeof title === 'string' && title.trim().length > 0) {
    if (title.length > 200) return Response.json({ error: 'Title too long' }, { status: 400 });
    await env.DB.prepare("UPDATE chapters SET title = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(title.trim(), params.id).run();
  }

  if (content && typeof content === 'string' && content.trim().length > 0) {
    if (content.length > MAX_CONTENT_LENGTH) {
      return Response.json({ error: `Content too long (max ${MAX_CONTENT_LENGTH} chars)` }, { status: 400 });
    }
    const wordCount = content.trim().length;
    // 先寫R2 → 成功後更新D1 version
    const newVersion = (chapter.version || 0) + 1;
    try {
      await env.R2.put(chapter.content_key, content.trim());
    } catch (err) {
      return Response.json({ error: 'Failed to update content' }, { status: 500 });
    }
    try {
      await env.DB.prepare(
        "UPDATE chapters SET word_count = ?, version = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(wordCount, newVersion, params.id).run();
    } catch (err) {
      // DB失敗，R2已寫入新內容但version未更新，下次編輯會覆蓋，無需回滾R2
      return Response.json({ error: 'Failed to update metadata' }, { status: 500 });
    }
  }

  await env.DB.prepare("UPDATE books SET updated_at = datetime('now') WHERE id = ?")
    .bind(chapter.book_id).run();

  // 檢查是否有批註可能失效
  let warning = null;
  if (content) {
    const annoCount = await env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM annotations WHERE chapter_id = ? AND status != 'removed'"
    ).bind(params.id).first();
    if (annoCount && annoCount.cnt > 0) {
      warning = `該章節有 ${annoCount.cnt} 條批註，修改內容可能導致批註定位失效`;
    }
  }

  // 返回新version供前端下次編輯使用
  const newChapter = await env.DB.prepare('SELECT version FROM chapters WHERE id = ?').bind(params.id).first();
  return Response.json({ success: true, version: newChapter?.version || 0, ...(warning ? { warning } : {}) });
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { denied, auth } = await authCheck(request, env);
  if (denied) return denied;
  if (!validateId(params.id)) return Response.json({ error: 'Invalid chapter ID' }, { status: 400 });

  const chapter = await env.DB.prepare('SELECT * FROM chapters WHERE id = ?').bind(params.id).first();
  if (!chapter) return Response.json({ error: 'Chapter not found' }, { status: 404 });

  // demo只能刪除自己書的章節
  if (!await checkBookOwnership(auth, env, chapter.book_id)) {
    return Response.json({ error: '只能刪除自己書籍的章節' }, { status: 403 });
  }

  // 使用批次操作確保資料一致性
  // 注意：D1不支援傳統事務，但支援batch操作
  try {
    // 先刪除關聯資料，再刪除章節本身
    // 使用batch確保原子性
    const deleteStatements = [
      env.DB.prepare('DELETE FROM chapter_stats WHERE chapter_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM annotation_likes WHERE annotation_id IN (SELECT id FROM annotations WHERE chapter_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM reports WHERE annotation_id IN (SELECT id FROM annotations WHERE chapter_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM votes WHERE annotation_id IN (SELECT id FROM annotations WHERE chapter_id = ?)').bind(params.id),
      env.DB.prepare('DELETE FROM annotations WHERE chapter_id = ?').bind(params.id),
      env.DB.prepare('DELETE FROM chapters WHERE id = ?').bind(params.id),
      env.DB.prepare("UPDATE books SET updated_at = datetime('now') WHERE id = ?").bind(chapter.book_id)
    ];
    
    // 執行批次操作
    const batchResult = await env.DB.batch(deleteStatements);
    
    // 檢查章節是否成功刪除
    const chapterDeleteResult = batchResult[5];
    if (chapterDeleteResult.meta.changes === 0) {
      console.error('Chapter deletion failed: no rows affected');
      return Response.json({ error: '刪除章節失敗' }, { status: 500 });
    }
    
    // 刪除R2中的內容（在資料庫操作成功後執行）
    await env.R2.delete(chapter.content_key).catch((e) => {
      console.error('Failed to delete R2 content:', e);
      // R2刪除失敗不影響整體操作，但記錄日誌
    });
    
    return Response.json({ success: true });
  } catch (e) {
    console.error('Chapter deletion error:', e);
    return Response.json({ error: '刪除章節失敗: ' + e.message }, { status: 500 });
  }
}
