import { checkAdmin } from '../../_utils.js';

// GET /api/admin/annotations/stats - 批註統計
export async function onRequestGet(context) {
  const { request, env } = context;
  
  const auth = await checkAdmin(request, env);
  if (!auth.ok) {
    return Response.json({ error: '請先登入' }, { status: 401 });
  }

  // 根據權限構建過濾條件
  let permFilter = '';
  const binds = [];
  
  if (auth.role === 'admin') {
    permFilter = "AND u.role != 'super_admin'";
  } else if (auth.role === 'demo') {
    permFilter = 'AND (a.user_id = ? OR (b.created_by = ? AND u.role = ?))';
    binds.push(auth.userId, auth.userId, 'demo');
  }

  const today = new Date().toISOString().slice(0, 10);

  const stats = await env.DB.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN date(a.created_at) = ? THEN 1 ELSE 0 END) as today,
      SUM(CASE WHEN a.status = 'reported' THEN 1 ELSE 0 END) as reported,
      SUM(CASE WHEN a.status = 'removed' THEN 1 ELSE 0 END) as removed,
      SUM(CASE WHEN a.visibility = 'public' THEN 1 ELSE 0 END) as public_count,
      SUM(CASE WHEN a.visibility = 'private' THEN 1 ELSE 0 END) as private_count
    FROM annotations a
    LEFT JOIN admin_users u ON a.user_id = u.id
    LEFT JOIN books b ON a.book_id = b.id
    WHERE 1=1 ${permFilter}
  `).bind(today, ...binds).first();

  return Response.json({
    total: stats?.total || 0,
    today: stats?.today || 0,
    reported: stats?.reported || 0,
    removed: stats?.removed || 0,
    public: stats?.public_count || 0,
    private: stats?.private_count || 0
  });
}
