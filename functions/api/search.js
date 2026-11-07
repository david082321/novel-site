// GET /api/search?q=keyword&book_id=1&page=1&limit=20 — 搜索书籍或章节内容
// P2修复：添加分页支持，优化大量结果时的性能
// 简单内存速率限制（每个isolate实例独立，CF Workers会自动分配）
const searchRateMap = new Map();
const SEARCH_RATE_LIMIT = 30; // 每分钟每IP最多30次搜索
const SEARCH_RATE_WINDOW = 60000; // 1分钟窗口

// 默认分页参数
const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 50;

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);

  // IP速率限制
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const entry = searchRateMap.get(ip);
  if (entry && now - entry.start < SEARCH_RATE_WINDOW) {
    if (entry.count >= SEARCH_RATE_LIMIT) {
      return Response.json({ error: '搜尋過於頻繁，請稍後再試' }, { status: 429 });
    }
    entry.count++;
  } else {
    searchRateMap.set(ip, { start: now, count: 1 });
  }
  // 定期清理过期条目（防内存泄漏）
  if (searchRateMap.size > 1000) {
    for (const [k, v] of searchRateMap) {
      if (now - v.start > SEARCH_RATE_WINDOW) searchRateMap.delete(k);
    }
  }

  const q = (url.searchParams.get('q') || '').trim();
  const bookId = url.searchParams.get('book_id');
  
  // P2修复：解析分页参数
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || DEFAULT_PAGE);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(url.searchParams.get('limit')) || DEFAULT_LIMIT));
  const offset = (page - 1) * limit;

  if (!q || q.length < 2) {
    return Response.json({ error: '搜尋詞至少 2 個字元' }, { status: 400 });
  }

  // 限制查询长度
  const query = q.slice(0, 50);
  const like = `%${query}%`;

  // 如果指定了 book_id，搜索该书的章节标题
  if (bookId && /^\d+$/.test(bookId)) {
    // P2修复：章节搜索也支持分页
    const countResult = await env.DB.prepare(
      `SELECT COUNT(*) as total FROM chapters WHERE book_id = ? AND title LIKE ?`
    ).bind(bookId, like).first();
    const total = countResult?.total || 0;
    const totalPages = Math.ceil(total / limit);

    const { results } = await env.DB.prepare(
      `SELECT id, title, word_count, sort_order FROM chapters
       WHERE book_id = ? AND title LIKE ?
       ORDER BY sort_order ASC LIMIT ? OFFSET ?`
    ).bind(bookId, like, limit, offset).all();

    return Response.json({
      chapters: results,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasMore: page < totalPages
      }
    });
  }

  // P2修复：书籍搜索支持分页，先获取总数
  const countResult = await env.DB.prepare(
    `SELECT COUNT(*) as total FROM books b
     WHERE b.title LIKE ? OR b.author LIKE ?`
  ).bind(like, like).first();
  const total = countResult?.total || 0;
  const totalPages = Math.ceil(total / limit);

  // 搜索书籍（书名 + 作者）
  const { results } = await env.DB.prepare(
    `SELECT b.id, b.title, b.author, b.description, b.cover_key, b.created_at, b.updated_at,
      (SELECT COUNT(*) FROM chapters WHERE book_id = b.id) as chapter_count,
      (SELECT COALESCE(SUM(word_count), 0) FROM chapters WHERE book_id = b.id) as total_words
     FROM books b
     WHERE b.title LIKE ? OR b.author LIKE ?
     ORDER BY b.updated_at DESC LIMIT ? OFFSET ?`
  ).bind(like, like, limit, offset).all();

  return Response.json({
    books: results,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasMore: page < totalPages
    }
  });
}
