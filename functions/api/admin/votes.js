import { checkAdmin } from '../_utils.js';

// POST /api/admin/votes - 提交投票
export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: '請先登入' }, { status: 401 });

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'invalid JSON' }, { status: 400 }); }

  const { annotationId, action, reason } = body;

  if (!annotationId || !/^\d{1,18}$/.test(String(annotationId))) {
    return Response.json({ error: '無效的批註ID' }, { status: 400 });
  }
  if (!['remove', 'keep'].includes(action)) {
    return Response.json({ error: '無效的投票選項' }, { status: 400 });
  }
  if (reason && reason.length > 500) {
    return Response.json({ error: '投票理由不能超過500字' }, { status: 400 });
  }

  // 檢查批註是否處於 escalated 狀態（社區投票階段）
  const anno = await env.DB.prepare(
    'SELECT a.id, a.user_id, a.book_id FROM annotations a WHERE a.id = ? AND a.status = ?'
  ).bind(annotationId, 'reported').first();
  if (!anno) {
    return Response.json({ error: '該批註不在投票階段' }, { status: 400 });
  }

  // 檢查是否有 escalated 的檢舉
  const escalatedReport = await env.DB.prepare(
    "SELECT id, book_id FROM reports WHERE annotation_id = ? AND status = 'escalated' LIMIT 1"
  ).bind(annotationId).first();

  // 也允許對 pending+threshold_reached 的檢舉投票
  const pendingReport = await env.DB.prepare(
    "SELECT id, book_id FROM reports WHERE annotation_id = ? AND status = 'pending' AND threshold_reached_at IS NOT NULL LIMIT 1"
  ).bind(annotationId).first();

  if (!escalatedReport && !pendingReport) {
    return Response.json({ error: '該批註不在投票階段' }, { status: 400 });
  }

  // 不能對自己的批註投票
  if (anno.user_id === auth.userId) {
    return Response.json({ error: '不能對自己的批註投票' }, { status: 400 });
  }

  // 檢查是否已投票
  const existing = await env.DB.prepare(
    'SELECT 1 FROM votes WHERE annotation_id = ? AND admin_id = ?'
  ).bind(annotationId, auth.userId).first();
  if (existing) {
    return Response.json({ error: '您已對此批註投過票' }, { status: 400 });
  }

  // 插入投票
  await env.DB.prepare(`
    INSERT INTO votes (annotation_id, admin_id, action, reason) VALUES (?, ?, ?, ?)
  `).bind(annotationId, auth.userId, action, reason || null).run();

  // 檢查投票結果
  const voteStats = await env.DB.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN action = 'remove' THEN 1 ELSE 0 END) as remove_count,
      SUM(CASE WHEN action = 'keep' THEN 1 ELSE 0 END) as keep_count
    FROM votes WHERE annotation_id = ?
  `).bind(annotationId).first();

  const voteThreshold = 10; // 預設閾值
  const removePercent = 75;

  if (voteStats && voteStats.total >= voteThreshold) {
    const removeRatio = (voteStats.remove_count / voteStats.total) * 100;
    if (removeRatio >= removePercent) {
      // 樂觀鎖：只有 status 仍為 reported 時才執行，防並發重複
      const upd = await env.DB.prepare(`
        UPDATE annotations SET status = 'removed', updated_at = datetime('now') WHERE id = ? AND status = 'reported'
      `).bind(annotationId).run();

      if (upd.meta.changes > 0) {
        // 解決所有相關檢舉
        await env.DB.prepare(`
          UPDATE reports SET status = 'resolved', handler_action = 'remove', handled_at = datetime('now')
          WHERE annotation_id = ? AND status IN ('pending', 'escalated')
        `).bind(annotationId).run();
        // 投票者加分（只執行一次）
        const voters = await env.DB.prepare(
          'SELECT admin_id FROM votes WHERE annotation_id = ?'
        ).bind(annotationId).all();
        for (const v of (voters.results || [])) {
          await env.DB.prepare(
            "UPDATE admin_users SET score = ROUND(MIN(100, ROUND(score, 1) + 0.1), 1) WHERE id = ?"
          ).bind(v.admin_id).run();
          await env.DB.prepare(`
            INSERT INTO score_logs (user_id, delta, reason, related_annotation_id) VALUES (?, 0.1, 'vote_contribution', ?)
          `).bind(v.admin_id, annotationId).run();
        }
        // 對批註作者施加處罰
        const MUTE_DURATIONS_MIN = [0, 0, 1440, 4320, 10080, 43200];
        await env.DB.prepare(`
          UPDATE admin_users SET violation_count = violation_count + 1, last_violation_at = datetime('now') WHERE id = ?
        `).bind(anno.user_id).run();
        const annoAuthor = await env.DB.prepare('SELECT violation_count FROM admin_users WHERE id = ?').bind(anno.user_id).first();
        if (annoAuthor) {
          const vc = annoAuthor.violation_count;
          if (vc >= 6) {
            await env.DB.prepare("UPDATE admin_users SET banned_at = datetime('now') WHERE id = ?").bind(anno.user_id).run();
            await env.DB.prepare("INSERT INTO mutes (user_id, type, reason, related_annotation_id) VALUES (?, 'ban', '累計違規達到封禁閾值', ?)").bind(anno.user_id, annotationId).run();
          } else if (vc >= 2) {
            const dur = MUTE_DURATIONS_MIN[vc] || 43200;
            const endsAt = new Date(Date.now() + dur * 60000).toISOString();
            await env.DB.prepare('UPDATE admin_users SET muted_until = ? WHERE id = ?').bind(endsAt, anno.user_id).run();
            await env.DB.prepare("INSERT INTO mutes (user_id, type, reason, related_annotation_id, duration_minutes, ends_at) VALUES (?, 'mute', '社區投票移除批註', ?, ?, ?)").bind(anno.user_id, annotationId, dur, endsAt).run();
          } else {
            await env.DB.prepare("INSERT INTO mutes (user_id, type, reason, related_annotation_id) VALUES (?, 'warning', '社區投票移除批註（警告）', ?)").bind(anno.user_id, annotationId).run();
          }
        }
      }
    } else {
      // 保留批註（同樣用樂觀鎖）
      const upd = await env.DB.prepare(`
        UPDATE annotations SET status = 'normal', updated_at = datetime('now') WHERE id = ? AND status = 'reported'
      `).bind(annotationId).run();
      if (upd.meta.changes > 0) {
        await env.DB.prepare(`
          UPDATE reports SET status = 'resolved', handler_action = 'keep', handled_at = datetime('now')
          WHERE annotation_id = ? AND status IN ('pending', 'escalated')
        `).bind(annotationId).run();
      }
    }
  }

  return Response.json({ 
    success: true, 
    votes: { total: voteStats?.total || 0, remove: voteStats?.remove_count || 0, keep: voteStats?.keep_count || 0 }
  });
}
