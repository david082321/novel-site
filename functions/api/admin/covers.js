// POST/DELETE /api/admin/covers — 上傳/刪除書籍封面（R2儲存）
import { checkAdmin, validateId, checkBookOwnership } from '../_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(request.url);
  const bookId = url.searchParams.get('book_id');
  if (!bookId || !validateId(bookId)) return Response.json({ error: 'Valid book_id required' }, { status: 400 });

  const book = await env.DB.prepare('SELECT id, cover_key FROM books WHERE id = ?').bind(bookId).first();
  if (!book) return Response.json({ error: 'Book not found' }, { status: 404 });

  // demo只能操作自己書的封面
  if (!await checkBookOwnership(auth, env, bookId)) {
    return Response.json({ error: '只能管理自己書籍的封面' }, { status: 403 });
  }

  const formData = await request.formData();
  const file = formData.get('file');
  if (!file || !file.size) return Response.json({ error: 'No file uploaded' }, { status: 400 });
  if (file.size > 5 * 1024 * 1024) return Response.json({ error: 'File too large (max 5MB)' }, { status: 400 });

  const ct = file.type || '';
  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  if (!ALLOWED_TYPES.includes(ct)) return Response.json({ error: '僅支援 JPEG、PNG、WebP 格式' }, { status: 400 });

  // 驗證文件頭魔數（防止偽造Content-Type）
  const headerBuf = await file.slice(0, 16).arrayBuffer();
  const header = new Uint8Array(headerBuf);
  const isJpeg = header[0] === 0xFF && header[1] === 0xD8;
  const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
  const isWebp = header[0] === 0x52 && header[1] === 0x49 && header[2] === 0x46 && header[3] === 0x46
    && header[8] === 0x57 && header[9] === 0x45 && header[10] === 0x42 && header[11] === 0x50;
  if (!isJpeg && !isPng && !isWebp) return Response.json({ error: '文件內容不是有效的圖片格式' }, { status: 400 });

  const ext = ct.includes('png') ? 'png' : ct.includes('webp') ? 'webp' : 'jpg';
  const key = `covers/${bookId}.${ext}`;
  const oldKey = book.cover_key;

  // 先寫新封面到R2，再更新DB，DB失敗則清理R2
  try {
    await env.R2.put(key, file.stream(), { httpMetadata: { contentType: ct } });
  } catch (err) {
    return Response.json({ error: 'Failed to upload cover' }, { status: 500 });
  }
  try {
    await env.DB.prepare('UPDATE books SET cover_key = ? WHERE id = ?').bind(key, bookId).run();
  } catch (err) {
    // DB更新失敗時清理已上傳的新封面
    await env.R2.delete(key).catch(() => {});
    return Response.json({ error: 'Failed to update cover' }, { status: 500 });
  }
  // DB成功後再刪舊封面（舊封面遺失無害）
  if (oldKey && oldKey !== key) {
    await env.R2.delete(oldKey).catch(() => {});
  }

  return Response.json({ success: true, cover_key: key });
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(request.url);
  const bookId = url.searchParams.get('book_id');
  if (!bookId || !validateId(bookId)) return Response.json({ error: 'Valid book_id required' }, { status: 400 });

  // demo只能操作自己書的封面
  if (!await checkBookOwnership(auth, env, bookId)) {
    return Response.json({ error: '只能管理自己書籍的封面' }, { status: 403 });
  }

  const book = await env.DB.prepare('SELECT cover_key FROM books WHERE id = ?').bind(bookId).first();
  const coverKey = book?.cover_key;
  // 先更新DB（可回滾），再刪R2（孤兒無害）
  await env.DB.prepare('UPDATE books SET cover_key = NULL WHERE id = ?').bind(bookId).run();
  if (coverKey) {
    await env.R2.delete(coverKey).catch(() => {});
  }

  return Response.json({ success: true });
}
