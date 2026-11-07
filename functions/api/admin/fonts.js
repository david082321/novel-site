// 管理API：上传/删除自定义字体
import { checkAdmin, requireSuperAdmin } from '../_utils.js';

async function getFontList(env) {
  const row = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'custom_fonts'").first();
  return row ? JSON.parse(row.value) : [];
}

async function saveFontList(env, fonts) {
  await env.DB.prepare(
    "INSERT OR REPLACE INTO site_settings (key, value) VALUES ('custom_fonts', ?)"
  ).bind(JSON.stringify(fonts)).run();
}

// POST: 上传字体
export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理字體' }, { status: 403 });

  try {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file || !file.name) return Response.json({ error: '請選擇文件' }, { status: 400 });

    const name = file.name.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
    if (!/\.woff2$/i.test(name)) return Response.json({ error: '只支援 .woff2 格式' }, { status: 400 });
    if (file.size > 10 * 1024 * 1024) return Response.json({ error: '文件不能超過10MB' }, { status: 400 });

    // 上传到R2
    const arrayBuffer = await file.arrayBuffer();
    await env.R2.put(`fonts/${name}`, arrayBuffer, {
      httpMetadata: { contentType: 'font/woff2' }
    });

    // 更新字体列表
    const fonts = await getFontList(env);
    if (!fonts.includes(name)) fonts.push(name);
    await saveFontList(env, fonts);

    return Response.json({ success: true, name });
  } catch (e) {
    console.error('Font upload error:', e);
    return Response.json({ error: '上傳失敗' }, { status: 500 });
  }
}

// DELETE: 删除字体
export async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await checkAdmin(request, env);
  if (!auth.ok) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!requireSuperAdmin(auth)) return Response.json({ error: '僅超級管理員可管理字體' }, { status: 403 });

  try {
    const body = await request.json();
    const { filename } = body;
    if (!filename || !/^[\w\-\.]+\.woff2$/i.test(filename)) {
      return Response.json({ error: '無效的檔案名' }, { status: 400 });
    }

    // 先更新DB列表（可回滚），再删R2文件（孤儿无害）
    const fonts = await getFontList(env);
    const idx = fonts.indexOf(filename);
    if (idx >= 0) fonts.splice(idx, 1);
    await saveFontList(env, fonts);

    await env.R2.delete(`fonts/${filename}`).catch(() => {});

    return Response.json({ success: true });
  } catch (e) {
    console.error('Font delete error:', e);
    return Response.json({ error: '刪除失敗' }, { status: 500 });
  }
}
