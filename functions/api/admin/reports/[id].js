import { checkAdmin } from '../../_utils.js';

const MUTE_DURATIONS_MIN = [0, 0, 1440, 4320, 10080, 43200]; // index=違規次數

function getMuteDuration(violationCount) {
  if (violationCount <= 1) return 0; // 警告
  if (violationCount >= 6) return -1; // 封禁
  return MUTE_DURATIONS_MIN[violationCount];
}

// 記錄積分變動
async function addScore(env, userId, delta, reason, annoId, reportId) {
  await env.DB.prepare(
    'UPDATE admin_users SET score = ROUND(MIN(100, MAX(-100, ROUND(score, 1) + ?)), 1) WHERE id = ?'
  ).bind(delta, userId).run();
  await env.DB.prepare(`
    INSERT INTO score_logs (user_id, delta, reason, related_annotation_id, related_report_id)
    VALUES (?, ?, ?, ?, ?)
  `).bind(userId, delta, reason, annoId, reportId).run();
}

// 對違規用戶施加處罰
async function applyPunishment(env, userId, annotationId) {
  await env.DB.prepare(`
    UPDATE admin_users SET violation_count = violation_count + 1, last_violation_at = datetime('now') WHERE id = ?
  `).bind(userId).run();

  const user = await env.DB.prepare('SELECT violation_count FROM admin_users WHERE id = ?').bind(userId).first();
  const duration = getMuteDuration(user.violation_count);

  if (duration === -1) {
    await env.DB.prepare('UPDATE admin_users SET banned_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
    await env.DB.prepare(`
      INSERT INTO mutes (user_id, type, reason, related_annotation_id) VALUES (?, 'ban', '累計違規達到封禁閾值', ?)
    `).bind(userId, annotationId).run();
  } else if (duration > 0) {
    const endsAt = new Date(Date.now() + duration * 60000).toISOString();
    await env.DB.prepare('UPDATE admin_users SET muted_until = ? WHERE id = ?').bind(endsAt, userId).run();
    await env.DB.prepare(`
      INSERT INTO mutes (user_id, type, reason, related_annotation_id, duration_minutes, ends_at)
      VALUES (?, 'mute', '發表違規批註', ?, ?, ?)
    `).bind(userId, annotationId, duration, endsAt).run();
  } else {
    await env.DB.prepare(`
      INSERT INTO mutes (user_id, type, reason, related_annotation_id) VALUES (?, 'warning', '發表違規批註（首次警告）', ?)
    `).bind(userId, annotationId).run();
  }
}

// PATCH /api/admin/reports/[id] - 處理檢舉
export async function onRequestPatch(context) {
  const { request, env, params } = context;
  const reportId = params.id;

  if (!/^\d{1,18}$/.test(reportId)) {
    return Response.json({ error: '無效的ID' }, { status: 400 });
  }

  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: '請先登入' }, { status: 401 });

  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'invalid JSON' }, { status: 400 }); }

  const { action } = body; // 'remove' | 'keep'
  if (!['remove', 'keep'].includes(action)) {
    return Response.json({ error: '無效的操作' }, { status: 400 });
  }

  // 取得檢舉資訊
  const report = await env.DB.prepare(`
    SELECT r.*, a.user_id as anno_user_id, a.book_id, b.created_by as book_owner
    FROM reports r
    LEFT JOIN annotations a ON r.annotation_id = a.id
    LEFT JOIN books b ON a.book_id = b.id
    WHERE r.id = ?
  `).bind(reportId).first();

  if (!report) return Response.json({ error: '檢舉不存在' }, { status: 404 });
  if (report.status === 'resolved') return Response.json({ error: '該檢舉已處理' }, { status: 400 });

  // 權限檢查：書籍負責人、admin、super_admin 可處理
  const isBookOwner = report.book_owner === auth.userId;
  const canHandle = auth.role === 'super_admin' || auth.role === 'admin' || isBookOwner;
  if (!canHandle) {
    return Response.json({ error: '無權處理此檢舉' }, { status: 403 });
  }

  // 角色保護：非超管不能處理超管批註的檢舉
  if (auth.role !== 'super_admin') {
    const annoUser = await env.DB.prepare('SELECT role FROM admin_users WHERE id = ?').bind(report.anno_user_id).first();
    if (annoUser?.role === 'super_admin') {
      return Response.json({ error: '無權處理此檢舉' }, { status: 403 });
    }
  }

  // 執行操作
  if (action === 'remove') {
    // 移除批註
    await env.DB.prepare(`
      UPDATE annotations SET status = 'removed', updated_at = datetime('now') WHERE id = ?
    `).bind(report.annotation_id).run();
    // 對批註作者施加處罰
    await applyPunishment(env, report.anno_user_id, report.annotation_id);
  } else {
    // 保留：復原批註狀態為 normal
    await env.DB.prepare(`
      UPDATE annotations SET status = 'normal', updated_at = datetime('now') WHERE id = ? AND status = 'reported'
    `).bind(report.annotation_id).run();
  }

  // 更新檢舉狀態
  await env.DB.prepare(`
    UPDATE reports SET status = 'resolved', handler_id = ?, handler_action = ?, handled_at = datetime('now')
    WHERE id = ?
  `).bind(auth.userId, action, reportId).run();

  // 同時解決該批註的所有 pending 檢舉
  await env.DB.prepare(`
    UPDATE reports SET status = 'resolved', handler_id = ?, handler_action = ?, handled_at = datetime('now')
    WHERE annotation_id = ? AND status IN ('pending', 'escalated')
  `).bind(auth.userId, action, report.annotation_id).run();

  // 負責人處理加分
  if (isBookOwner) {
    await addScore(env, auth.userId, 0.2, 'handle_report', report.annotation_id, parseInt(reportId));
  }

  return Response.json({ success: true, action });
}
