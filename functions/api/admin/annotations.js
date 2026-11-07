import { checkAdmin } from '../_utils.js';

// 定義允許的狀態和可見性值白名單
const VALID_STATUSES = ['normal', 'reported', 'removed'];
const VALID_VISIBILITIES = ['public', 'private'];
// 定義允許的排序方式白名單
const VALID_SORT_OPTIONS = {
  'latest': 'a.created_at DESC',
  'oldest': 'a.created_at ASC',
  'reports': 'a.created_at DESC' // reports 排序需要子查詢，暫時用 created_at
};

// 權限過濾
function buildPermissionFilter(auth) {
  const where = [];
  const binds = [];

  if (auth.role === 'super_admin') {
    // 無限制
  } else if (auth.role === 'admin') {
    // 排除超管的批註
    where.push("u.role != 'super_admin'");
  } else {
    // demo：自己的批註 + 自己書上的 demo 批註
    where.push('(a.user_id = ? OR (b.created_by = ? AND u.role = ?))');
    binds.push(auth.userId, auth.userId, 'demo');
  }

  return { where, binds };
}

/**
 * 轉義LIKE查詢中的萬用字元，防止LIKE注入
 * @param {string} str - 需要轉義的字串
 * @returns {string} - 轉義後的字串
 */
function escapeLikePattern(str) {
  return str.replace(/[%_\\]/g, '\\$&');
}

// GET /api/admin/annotations - 批註列表
export async function onRequestGet(context) {
  const { request, env } = context;
  
  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '請先登入' }, { status: 401 });
  }

  const url = new URL(request.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = Math.min(50, Math.max(10, parseInt(url.searchParams.get('limit')) || 20));
  const offset = (page - 1) * limit;

  const bookId = url.searchParams.get('bookId');
  const status = url.searchParams.get('status'); // all/normal/reported/removed
  const visibility = url.searchParams.get('visibility'); // all/public/private
  const search = url.searchParams.get('search');
  const sort = url.searchParams.get('sort') || 'latest'; // latest/oldest/reports

  // 構建查詢條件
  const { where, binds } = buildPermissionFilter(auth);

  if (bookId) {
    // 驗證bookId為有效數字
    const bookIdNum = parseInt(bookId, 10);
    if (isNaN(bookIdNum) || bookIdNum <= 0) {
      return Response.json({ error: '無效的書籍ID' }, { status: 400 });
    }
    where.push('a.book_id = ?');
    binds.push(bookIdNum);
  }
  if (status && status !== 'all') {
    if (!VALID_STATUSES.includes(status)) return Response.json({ error: '無效的狀態' }, { status: 400 });
    where.push('a.status = ?');
    binds.push(status);
  }
  if (visibility && visibility !== 'all') {
    if (!VALID_VISIBILITIES.includes(visibility)) return Response.json({ error: '無效的類型' }, { status: 400 });
    where.push('a.visibility = ?');
    binds.push(visibility);
  }
  if (search) {
    // 轉義LIKE萬用字元，防止LIKE注入攻擊
    const escapedSearch = escapeLikePattern(search);
    where.push('(a.content LIKE ? ESCAPE "\\\\" OR a.sent_text LIKE ? ESCAPE "\\\\")');
    binds.push(`%${escapedSearch}%`, `%${escapedSearch}%`);
  }

  const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';
  
  // 使用白名單驗證排序欄位，防止SQL隱碼攻擊
  const orderBy = VALID_SORT_OPTIONS[sort] || VALID_SORT_OPTIONS['latest'];

  // 查詢總數
  const countSql = `
    SELECT COUNT(*) as total
    FROM annotations a
    LEFT JOIN admin_users u ON a.user_id = u.id
    LEFT JOIN books b ON a.book_id = b.id
    ${whereClause}
  `;
  const countResult = await env.DB.prepare(countSql).bind(...binds).first();
  const total = countResult?.total || 0;

  // 查詢列表
  const listSql = `
    SELECT a.id, a.chapter_id, a.book_id, a.user_id, a.para_idx, a.sent_idx,
           a.sent_text, a.content, a.visibility, a.status, a.created_at,
           u.username, u.role as user_role,
           b.title as book_title,
           c.title as chapter_title,
           (SELECT COUNT(*) FROM annotation_likes WHERE annotation_id = a.id) as like_count
    FROM annotations a
    LEFT JOIN admin_users u ON a.user_id = u.id
    LEFT JOIN books b ON a.book_id = b.id
    LEFT JOIN chapters c ON a.chapter_id = c.id
    ${whereClause}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;
  const listResult = await env.DB.prepare(listSql).bind(...binds, limit, offset).all();

  return Response.json({
    annotations: listResult.results,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
}

// GET /api/admin/annotations/stats - 統計資料
export async function onRequestHead(context) {
  // 用 HEAD 請求取得統計（避免與 GET 衝突）
  return new Response(null, { status: 405 });
}
