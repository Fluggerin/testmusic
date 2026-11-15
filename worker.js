// Cloudflare Worker: каталог из закрытого ТГ-канала + стриминг для Mini App.
//
// wrangler.toml:
//   name = "music-api"
//   main = "worker.js"
//   compatibility_date = "2026-01-01"
//   [[kv_namespaces]]
//   binding = "DB"
//   id = "<id из: wrangler kv namespace create DB>"
//
// Секреты (wrangler secret put ...):
//   BOT_TOKEN       токен бота
//   CHANNEL_ID      id закрытого канала, вида -1001234567890
//   WEBHOOK_SECRET  любая длинная случайная строка (латиница/цифры)
//   ALLOWED_IDS     (необязательно) Telegram id через запятую, кому можно слушать

const enc = new TextEncoder();
const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'range',
  'access-control-expose-headers': 'content-range, accept-ranges, content-length',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'content-type': 'application/json' },
  });

// ---------- проверка, что запрос идёт из настоящего Mini App ----------
async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

async function checkAuth(initData, env) {
  if (!initData) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  p.delete('hash');
  const dcs = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = await hmac(enc.encode('WebAppData'), env.BOT_TOKEN);
  if (hex(await hmac(secret, dcs)) !== hash) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
  const user = JSON.parse(p.get('user') || 'null');
  if (env.ALLOWED_IDS && !env.ALLOWED_IDS.split(',').map((s) => s.trim()).includes(String(user?.id))) return null;
  return user || {};
}

// ---------- Telegram Bot API ----------
const tgApi = (env, method, body) =>
  fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then((r) => r.json());

// Бот видит только посты, опубликованные ПОСЛЕ того, как его сделали админом канала.
async function onUpdate(u, env) {
  const m = u.channel_post || u.edited_channel_post;
  if (!m || String(m.chat.id) !== String(env.CHANNEL_ID) || !m.audio) return;

  const a = m.audio;
  const cap = m.caption || '';
  // В подписи к треку пиши:  Альбом: Название   и   Год: 2026
  const album = (cap.match(/(?:альбом|album)\s*[:：]\s*(.+)/i) || [])[1]?.trim() || 'Синглы';
  const year = (cap.match(/(?:год|year)\s*[:：]\s*(\d{4})/i) || [])[1] || '';
  const thumb = a.thumbnail || a.thumb;

  const track = {
    id: a.file_unique_id,
    msgId: m.message_id,
    title: a.title || a.file_name?.replace(/\.[^.]+$/, '') || 'Без названия',
    artist: a.performer || 'Неизвестный исполнитель',
    album,
    year,
    duration: a.duration || 0,
    mime: a.mime_type || 'audio/mpeg',
    fileId: a.file_id,
    thumbId: thumb?.file_id || null,
  };

  const list = JSON.parse((await env.DB.get('catalog')) || '[]');
  const i = list.findIndex((x) => x.msgId === track.msgId);
  if (i >= 0) list[i] = track;
  else list.push(track);
  await env.DB.put('catalog', JSON.stringify(list));
}

// Отдаём файл из Telegram, не раскрывая токен. Range нужен, чтобы работала перемотка.
async function proxyFile(env, fileId, req, contentType) {
  const info = await tgApi(env, 'getFile', { file_id: fileId });
  if (!info.ok) return new Response('file not available', { status: 404, headers: cors });

  const headers = {};
  const range = req.headers.get('range');
  if (range) headers.range = range;

  const up = await fetch(`https://api.telegram.org/file/bot${env.BOT_TOKEN}/${info.result.file_path}`, { headers });
  const out = new Headers(cors);
  for (const k of ['content-length', 'content-range', 'accept-ranges']) {
    if (up.headers.get(k)) out.set(k, up.headers.get(k));
  }
  out.set('content-type', contentType);
  out.set('cache-control', 'private, max-age=3600');
  return new Response(up.body, { status: up.status, headers: out });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });

    // Вебхук от Telegram
    if (req.method === 'POST' && path === `/webhook/${env.WEBHOOK_SECRET}`) {
      await onUpdate(await req.json(), env);
      return new Response('ok');
    }

    // Всё остальное только для авторизованных из Mini App
    const user = await checkAuth(url.searchParams.get('auth'), env);
    if (!user) return json({ error: 'unauthorized' }, 401);

    if (path === '/api/tracks') {
      const list = JSON.parse((await env.DB.get('catalog')) || '[]');
      return json(
        list.map(({ fileId, thumbId, mime, msgId, ...t }) => ({ ...t, hasCover: !!thumbId }))
      );
    }

    const m = path.match(/^\/api\/(audio|cover)\/([^/]+)$/);
    if (m) {
      const list = JSON.parse((await env.DB.get('catalog')) || '[]');
      const t = list.find((x) => x.id === m[2]);
      if (!t) return json({ error: 'not found' }, 404);
      if (m[1] === 'audio') return proxyFile(env, t.fileId, req, t.mime);
      if (!t.thumbId) return json({ error: 'no cover' }, 404);
      return proxyFile(env, t.thumbId, req, 'image/jpeg');
    }

    return json({ error: 'not found' }, 404);
  },
};
